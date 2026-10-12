package service

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// WorkerID is the trusted in-broker worker identity recorded on execution
// attempts it claims. It is not a principal: every operation still passes
// the same admission, policy re-evaluation, epoch check and atomic claim as
// manual execution. There is no fast path around the state machine (C13).
const WorkerID = "broker:auto-worker"

// RunAutoWorker executes authorized operations until ctx ends. It consumes
// only the authorized set: requested/pending ops still need operator
// approval, and each claim races revocation exactly like manual execution.
// Claim losers and empty polls are silent; terminal failures are recorded
// through the normal attempt/audit path inside Execute*.
func (s *Service) RunAutoWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.runWorkerOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ExpireStaleRequests sweeps expired open operations into the expired
// terminal state (G04). It runs on every worker pass — and the daemon
// invokes it at startup — so expiry never depends on automatic execution
// being enabled: even a workerless broker stops presenting dead work.
func (s *Service) ExpireStaleRequests() int {
	now := time.Now()
	n, err := s.db.ExpireOpenOperations(now)
	if err != nil {
		return 0
	}
	// Relay sweep (QR-05): expired grants go terminal and their
	// staged bytes are dropped at once — an expired payload can
	// never start a new dispatch, including after delayed
	// resolution or restart.
	if ids, err := s.db.ExpireRelays(now); err == nil {
		for _, id := range ids {
			s.eph.Delete(relayPayloadKey(id))
			s.audit(id, "relay_expired", "broker", "", "deadline")
		}
		n += len(ids)
	}
	if n := s.eph.Sweep(now); n > 0 {
		s.audit("", "relay_spool_swept", "broker", "", fmt.Sprintf("entries=%d", n))
	}
	return n
} // ExecuteReadyRelays delivers fulfilled quick relays without requiring the
// general policy auto-execution switch (F05). It consumes ONLY relay-backed
// authorized transfers (secret_ref "relay:...") through the normal
// ExecuteTransfer claim/dispatch/finalization path. Standing-policy
// operations are never executed here.
func (s *Service) ExecuteReadyRelays(ctx context.Context) int {
	_, transfers, err := s.db.ListAuthorizedOps()
	if err != nil {
		return 0
	}
	n := 0
	for _, tr := range transfers {
		if ctx.Err() != nil {
			return n
		}
		if _, ok := relayIDOf(tr.SecretRef); !ok {
			continue
		}
		if _, err := s.ExecuteTransfer(ctx, tr.ID, WorkerID); err == nil {
			n++
		}
	}
	return n
}

// RunRelayWorker runs the broker-managed relay job queue (F05): expiry
// maintenance plus relay-only delivery, independent of the general
// auto-execution switch. It stops on ctx cancellation.
func (s *Service) RunRelayWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.ExpireStaleRequests()
		s.ExecuteReadyRelays(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunLifecycleLoop is the small bounded maintenance task (F12): expire
// requests, purge expired payloads, update statuses — independent of the
// execution worker. One ticker, supervised shutdown via ctx.
func (s *Service) RunLifecycleLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.ExpireStaleRequests()
		}
	}
}

// workerJob is one authorized operation awaiting execution. The queue
// carries IDs only — each worker re-reads and claims through the atomic
// gates, so queueing never pre-authorizes anything.
type workerJob struct {
	opType string // "use" | "transfer"
	id     string
	// deadline orders the queue: short-lived relays must not sit
	// behind a large backlog of unrelated work (QR-08).
	deadline time.Time
}

// workerQueueBound caps queued (not yet running) jobs. Admission is
// bounded end to end: N workers + a finite queue, never a goroutine
// per listed operation (QR-08).
const workerQueueBound = 256

func (s *Service) runWorkerOnce(ctx context.Context) {
	_ = s.ExpireStaleRequests()
	uses, transfers, err := s.db.ListAuthorizedOps()
	if err != nil {
		return
	}
	// Bounded concurrent executor (concurrency design + QR-08): a FIXED
	// pool of maxConcurrentOps workers drains a bounded earliest-
	// deadline-first queue. Each operation still travels the same
	// independent authorize→claim→dispatch→finalize path as manual
	// execution. The operation ID is the unit of exactly-once claiming;
	// the credential is a shared resource and is NEVER locked for an
	// operation's duration.
	n := s.maxConcurrentOps()
	jobs := make(chan workerJob, workerQueueBound)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue // drain without starting new side effects
				}
				switch j.opType {
				case "use":
					_, _ = s.ExecuteUse(ctx, j.id, WorkerID)
				default:
					_, _ = s.ExecuteTransfer(ctx, j.id, WorkerID)
				}
			}
		}()
	}
	var pending []workerJob
	for _, ur := range uses {
		pending = append(pending, workerJob{opType: "use", id: ur.ID, deadline: ur.ExpiresAt})
	}
	for _, tr := range transfers {
		pending = append(pending, workerJob{opType: "transfer", id: tr.ID, deadline: tr.ExpiresAt})
	}
	sort.Slice(pending, func(a, b int) bool {
		if pending[a].deadline.Equal(pending[b].deadline) {
			return pending[a].id < pending[b].id
		}
		return pending[a].deadline.Before(pending[b].deadline)
	})
	// Bounded admission: feed in pages so an unbounded listing cannot
	// wedge the queue. Workers drain concurrently with feeding.
	for _, j := range pending {
		select {
		case jobs <- j:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	// The pass ends only when every admitted execution settles:
	// shutdown never strands in-flight side effects (P1-5).
	wg.Wait()
}
