package service

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func claimFixture(t *testing.T, svc *Service) (id, attempt string) {
	t.Helper()
	id = submitUnapproved(t, svc)
	tr, _ := svc.DB().GetTransfer(id)
	if err := svc.ApproveTransfer(id, "operator", tr.Revision); err != nil {
		t.Fatal(err)
	}
	tr, _ = svc.DB().GetTransfer(id)
	att, claimed, err := svc.DB().ClaimTransfer(id, tr.OpHash, tr.DestDigest, tr.Revision, "op", time.Now())
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	return id, att
}

func bumpEpoch(t *testing.T, svc *Service) {
	t.Helper()
	pols, err := svc.DB().ListPolicies()
	if err != nil || len(pols) == 0 {
		t.Fatalf("policies: %v", pols)
	}
	if err := svc.DB().SetPolicyEnabled(pols[0].ID, false); err != nil {
		t.Fatal(err)
	}
}

// SC-03: revocation committed before the dispatch point prevents the side
// effect. BeginDispatch checks the LIVE epoch inside the transition — a
// policy change after claim but before dispatch denies external I/O.
func TestRevocationBeforeDispatchDenies(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id, attempt := claimFixture(t, svc)
	tr, _ := svc.DB().GetTransfer(id)
	bumpEpoch(t, svc)
	if err := svc.DB().BeginDispatch("transfer", id, attempt, tr.OpHash, tr.DestDigest, "op", time.Now()); err == nil {
		t.Fatal("dispatch admitted after revocation (SC-03)")
	}
}

// SC-03: the dispatch commit IS the authorization point. Once admitted,
// a later revocation identifies an in-flight op but cannot retro-deny the
// already-authorized transition; and a second dispatch never re-admits.
func TestDispatchAdmitsOnceBeforeRevocation(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id, attempt := claimFixture(t, svc)
	tr, _ := svc.DB().GetTransfer(id)
	if err := svc.DB().BeginDispatch("transfer", id, attempt, tr.OpHash, tr.DestDigest, "op", time.Now()); err != nil {
		t.Fatalf("dispatch denied: %v", err)
	}
	bumpEpoch(t, svc)
	if err := svc.DB().BeginDispatch("transfer", id, attempt, tr.OpHash, tr.DestDigest, "op", time.Now()); err == nil {
		t.Fatal("double dispatch admitted (SC-03)")
	}
	if err := svc.DB().FinalizeOp("transfer", id, attempt, "failed", "", nil); err != nil {
		t.Fatalf("finalize after dispatch: %v", err)
	}
}

// SC-03: concurrent dispatch racers converge on one winner — every
// externally observable side effect has exactly one dispatch record.
func TestConcurrentDispatchSingleWinner(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id, attempt := claimFixture(t, svc)
	tr, _ := svc.DB().GetTransfer(id)
	var wins int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.DB().BeginDispatch("transfer", id, attempt, tr.OpHash, tr.DestDigest, "op", time.Now()); err == nil {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("dispatch admitted %d winners, want exactly 1 (SC-03)", wins)
	}
}
