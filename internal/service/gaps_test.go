package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// P2-7: RecordDispatch is a guarded insert, not a blind one. It must
// reject pre-dispatch operations, attempts that do not own the op, and
// conflicting records — while accepting a byte-identical retry.
func TestRecordDispatchGuarded(t *testing.T) {
	svc := testService(t)
	id := setupTransferFixture(t, svc)
	db := svc.DB()
	dest, err := db.GetDestination("d1")
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	mkrec := func(attempt, digest string) *metadata.DispatchRecord {
		return &metadata.DispatchRecord{OpID: id, AttemptID: attempt, DestID: "d1",
			DestEndpoint: dest.Endpoint, DestExpectedUID: &uid,
			DestConfigDigest: "cfg", PayloadDigest: digest}
	}
	// Before the dispatch barrier: authorized but not dispatching.
	if err := db.RecordDispatch(mkrec("nope", "aaa")); err == nil {
		t.Fatal("RecordDispatch accepted a pre-dispatch operation")
	}
	// Cross the barrier through the real claim path.
	tr, _ := db.GetTransfer(id)
	attempt, claimed, err := db.ClaimTransfer(tr.ID, tr.OpHash, tr.DestDigest, tr.Revision, "op", time.Now())
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := db.BeginDispatch("transfer", id, attempt, tr.OpHash, tr.DestDigest, "op", time.Now()); err != nil {
		t.Fatalf("begin dispatch: %v", err)
	}
	// An attempt that does not own the op cannot record.
	if err := db.RecordDispatch(mkrec("bogus-attempt", "aaa")); err == nil {
		t.Fatal("RecordDispatch accepted a non-owning attempt")
	}
	// The owning attempt records exactly once.
	if err := db.RecordDispatch(mkrec(attempt, "aaa")); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	// A byte-identical retry is idempotent (safe recording retry).
	if err := db.RecordDispatch(mkrec(attempt, "aaa")); err != nil {
		t.Fatalf("identical retry rejected: %v", err)
	}
	// A conflicting record — same op, different payload identity — is
	// an explicit error, never a silent overwrite or ignore.
	if err := db.RecordDispatch(mkrec(attempt, "bbb")); err == nil {
		t.Fatal("conflicting dispatch record silently accepted")
	}
	got, err := db.GetDispatch(id)
	if err != nil || got == nil || got.PayloadDigest != "aaa" || got.AttemptID != attempt {
		t.Fatalf("stored record is not the original: %+v %v", got, err)
	}
}

// P2-9 end to end: a broad preauthorization grant added alongside a
// narrower review rule must not flip new submissions to preauthorized.
// The operation stays pending for a human despite the broad grant.
func TestOverlappingSubmitRequiresHuman(t *testing.T) {
	svc := testService(t)
	approved := setupTransferFixture(t, svc)
	tr, _ := svc.DB().GetTransfer(approved)
	if tr.Status != types.StatusAuthorized || tr.ApprovedBy != "operator" {
		t.Fatalf("fixture not human-approved (sanity): %+v", tr)
	}
	broad := &types.Policy{Name: "broad-preauth", Priority: 100, Enabled: true, Rules: []types.PolicyRule{{
		Principal: "uid:1000", SecretRefs: []string{"cert1"}, Ops: []string{"transfer"},
		DestIDs: []string{"*"}, Resources: []string{"*"}, NoApproval: true,
	}}}
	if err := svc.DB().CreatePolicy(broad); err != nil {
		t.Fatal(err)
	}
	second, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	tr2, _ := svc.DB().GetTransfer(second)
	if tr2.Status == types.StatusAuthorized {
		t.Fatal("broad grant bypassed the narrower mandatory-review rule at submit")
	}
}

func shaHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// storeRecipient is a G02-capable fixture: accept loop serving v1 deliver
// frames (persist-then-ack with digest recompute) and lookup frames from
// a durable map. dropAck persists but never acks.
type storeRecipient struct {
	sock    string
	lis     net.Listener
	mu      sync.Mutex
	store   map[string][]byte
	dropAck bool
}

func startStoreRecipient(t *testing.T, dropAck bool) *storeRecipient {
	t.Helper()
	dir := recipientDir(t)
	sock := filepath.Join(dir, "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	r := &storeRecipient{sock: sock, lis: l, store: map[string][]byte{}, dropAck: dropAck}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go r.handle(c)
		}
	}()
	return r
}

func (r *storeRecipient) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var lb [4]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n == 0 || n > 2<<20 {
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	var probe struct {
		V    uint32 `json:"v"`
		Kind string `json:"kind"`
	}
	if json.Unmarshal(buf, &probe) != nil || probe.V != 1 {
		return
	}
	if probe.Kind == "lookup" {
		var q struct {
			OpID   string `json:"op_id"`
			Digest string `json:"digest"`
		}
		_ = json.Unmarshal(buf, &q)
		status, dgst, nb := "unknown", q.Digest, 0
		r.mu.Lock()
		if q.Digest != "" {
			if p, ok := r.store[q.OpID+"/"+q.Digest]; ok {
				status, dgst, nb = "durably_accepted", q.Digest, len(p)
			}
		} else {
			for k, p := range r.store {
				if strings.HasPrefix(k, q.OpID+"/") {
					status, dgst, nb = "durably_accepted", strings.TrimPrefix(k, q.OpID+"/"), len(p)
				}
			}
		}
		r.mu.Unlock()
		raw, _ := json.Marshal(map[string]interface{}{"op_id": q.OpID, "digest": dgst, "status": status, "bytes": nb})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
		return
	}
	var env struct {
		OpID    string `json:"op_id"`
		Digest  string `json:"digest"`
		Payload string `json:"payload"`
	}
	if json.Unmarshal(buf, &env) != nil {
		return
	}
	if shaHex(env.Payload) != env.Digest {
		raw, _ := json.Marshal(map[string]interface{}{"accepted": false, "op_id": env.OpID, "digest": env.Digest})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
		return
	}
	r.mu.Lock()
	r.store[env.OpID+"/"+env.Digest] = []byte(env.Payload)
	r.mu.Unlock()
	if r.dropAck {
		return
	}
	raw, _ := json.Marshal(map[string]interface{}{"accepted": true, "op_id": env.OpID, "digest": env.Digest, "bytes": len(env.Payload)})
	binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
	_, _ = c.Write(lb[:])
	_, _ = c.Write(raw)
}

// G01: a low-entropy secret gains no offline guessing oracle. Neither the
// secret nor its deterministic digest may appear on any agent-visible
// surface — while the private dispatch record keeps the digest so
// reconciliation still binds the exact payload.
func TestNoDigestOracleForLowEntropySecret(t *testing.T) {
	svc := testService(t)
	const pin = "1234"
	dgst := shaHex(pin)
	sr := &types.SecretReference{ID: "pin1", Name: "pin", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("pin1", []byte(pin)); err != nil {
		t.Fatal(err)
	}
	r := startStoreRecipient(t, false)
	uid := uint32(os.Geteuid())
	if err := svc.AddDestination(&types.Destination{ID: "d1", Name: "r",
		Type: "recipient-socket", Endpoint: r.sock, ExpectedUID: &uid}); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "pin1", "transfer", "d1")
	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "pin1", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	res, err := svc.ExecuteTransfer(context.Background(), id, "op")
	if err != nil {
		t.Fatal(err)
	}
	surfaces := map[string]string{}
	raw, _ := json.Marshal(res)
	surfaces["execute-result"] = string(raw)
	detail, err := svc.StatusDetail("uid:1000", "transfer", id)
	if err != nil {
		t.Fatal(err)
	}
	surfaces["status-result"] = detail.Result
	rcpt, _ := svc.DB().GetReceipt(id)
	surfaces["stored-receipt"] = rcpt.Result
	rs, err := svc.RecipientStatus(context.Background(), "uid:1000", id, false)
	if err != nil {
		t.Fatal(err)
	}
	rraw, _ := json.Marshal(rs)
	surfaces["recipient-status"] = string(rraw)
	logs, _ := svc.DB().ListAuditLogs(100)
	var la strings.Builder
	for _, l := range logs {
		la.WriteString(l.Action + "\x00" + l.Outcome + "\x00" + l.Metadata + "\x00")
	}
	surfaces["audit"] = la.String()
	for name, body := range surfaces {
		if strings.Contains(body, pin) {
			t.Fatalf("secret leaked on %s: %s", name, body)
		}
		if strings.Contains(body, dgst) {
			t.Fatalf("secret digest oracle on %s: %s", name, body)
		}
	}
	// The private record still binds the exact payload for recovery.
	rec, err := svc.DB().GetDispatch(id)
	if err != nil || rec == nil || rec.PayloadDigest != dgst {
		t.Fatalf("private dispatch record lost the payload binding: %+v %v", rec, err)
	}
	if _, ok := rs["digest"]; ok {
		t.Fatalf("digest key present in agent-visible recipient status: %v", rs)
	}
}

// P0: no side effect starts after the authorization deadline. An op
// claimed just before expiry that crosses its deadline before dispatch
// is refused at the barrier — and the refusal records expired.
func TestDispatchRejectsLapsedDeadline(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	mk := func(ttl time.Duration) (id, attempt string) {
		id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
			SecretRef: "s1", Operation: "github.get_repo",
			Params:    map[string]string{"repo": "o/r"},
			ExpiresAt: time.Now().Add(ttl),
		})
		if err != nil {
			t.Fatal(err)
		}
		st, _ := svc.DB().GetUse(id)
		if err := svc.DB().ApproveUse(id, "op", st.OpHash, st.AuthEpoch, st.Revision); err != nil {
			t.Fatal(err)
		}
		st, _ = svc.DB().GetUse(id)
		a, ok, err := svc.DB().ClaimUse(id, st.OpHash, st.DestDigest, st.Revision, "w", time.Now())
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return id, a
	}
	// Positive control: dispatch inside the window succeeds.
	id, attempt := mk(5 * time.Minute)
	st, _ := svc.DB().GetUse(id)
	if err := svc.DB().BeginDispatch("use", id, attempt, st.OpHash, st.DestDigest, "w", time.Now()); err != nil {
		t.Fatalf("in-window dispatch denied: %v", err)
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusFailed, "", nil); err != nil {
		t.Fatal(err)
	}
	// Lapsed deadline: claim valid, dispatch after expiry refused.
	id2, attempt2 := mk(60 * time.Millisecond)
	st2, _ := svc.DB().GetUse(id2)
	time.Sleep(120 * time.Millisecond)
	if err := svc.DB().BeginDispatch("use", id2, attempt2, st2.OpHash, st2.DestDigest, "w", time.Now()); err == nil {
		t.Fatal("dispatch admitted after authorization expiry")
	}
	// The service mapping records expired, not failed, for a barrier
	// refusal past the deadline — and failed for a live deadline.
	if _, err := svc.finalizeDispatchDenied("use", id2, attempt2, "uid:1000", "", st2.ExpiresAt, fmt.Errorf("dispatch denied")); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("dispatch-denied error hides expiry: %v", err)
	}
	ur, _ := svc.DB().GetUse(id2)
	if ur.Status != types.StatusExpired {
		t.Fatalf("status=%s, want expired", ur.Status)
	}
	id3, attempt3 := mk(5 * time.Minute)
	st3, _ := svc.DB().GetUse(id3)
	if _, err := svc.finalizeDispatchDenied("use", id3, attempt3, "uid:1000", "", st3.ExpiresAt, fmt.Errorf("dispatch denied")); err == nil || strings.Contains(err.Error(), "expired") {
		t.Fatalf("live-deadline refusal misreported as expiry: %v", err)
	}
	ur3, _ := svc.DB().GetUse(id3)
	if ur3.Status != types.StatusFailed {
		t.Fatalf("status=%s, want failed", ur3.Status)
	}
}

// G02: reconciliation consults the ORIGINAL delivery. Repointing the
// destination after dispatch cannot substitute a new recipient, and a
// dead original yields unavailable — never a guess.
func TestReconciliationBoundToOriginal(t *testing.T) {
	svc := testService(t)
	sr := &types.SecretReference{ID: "s2", Name: "s", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("s2", []byte("PAYLOAD-A")); err != nil {
		t.Fatal(err)
	}
	a := startStoreRecipient(t, true) // persists, ack lost -> uncertain
	b := startStoreRecipient(t, false)
	uid := uint32(os.Geteuid())
	if err := svc.AddDestination(&types.Destination{ID: "d1", Name: "r",
		Type: "recipient-socket", Endpoint: a.sock, ExpectedUID: &uid}); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "s2", "transfer", "d1")
	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "s2", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteTransfer(context.Background(), id, "op"); err == nil {
		t.Fatal("expected uncertain delivery")
	}
	tr, _ := svc.DB().GetTransfer(id)
	if tr.Status != types.StatusUncertain {
		t.Fatalf("status=%s, want uncertain", tr.Status)
	}
	// Repoint the destination at B AFTER dispatch. Reconciliation must
	// still ask A and settle durably_accepted.
	if err := svc.DB().UpdateDestinationEndpoint("d1", b.sock, "op"); err != nil {
		t.Fatal(err)
	}
	rs, err := svc.RecipientStatus(context.Background(), "uid:1000", id, false)
	if err != nil {
		t.Fatalf("reconciliation failed after repoint: %v", err)
	}
	if rs["status"] != transfer.RecipientDurablyAccepted {
		t.Fatalf("reconciliation settled by the wrong recipient: %v", rs)
	}
	// Kill the original: unavailable, never B's answer.
	_ = a.lis.Close()
	if _, err := svc.RecipientStatus(context.Background(), "uid:1000", id, false); err == nil ||
		!strings.Contains(err.Error(), "reconciliation unavailable") {
		t.Fatalf("dead original must be unavailable, got %v", err)
	}
	// Never-dispatched ops have nothing to reconcile.
	id2, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "s2", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecipientStatus(context.Background(), "uid:1000", id2, false); err == nil ||
		!strings.Contains(err.Error(), "reconciliation unavailable") {
		t.Fatalf("undispatched op must be unavailable, got %v", err)
	}
}

// G03: preauthorized work is never stranded. An authorized op appears in
// the ready view (not the pending queue) with an execution next-action,
// with the worker on or off.
func TestReadyViewPreventsStranding(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	p := &types.Policy{Name: "pre", Priority: 10, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"s1"},
			Ops: []string{"transfer"}, DestIDs: []string{"d1"},
			Resources: []string{"*"}, NoApproval: true,
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	sock := filepath.Join(t.TempDir(), "r.sock")
	if err := svc.AddDestination(&types.Destination{ID: "d1", Name: "d",
		Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}); err != nil {
		t.Fatal(err)
	}
	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "s1", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	// Ready, not pending; visible without running the worker.
	uses, transfers, err := svc.DB().ListAuthorizedOps()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tr := range transfers {
		if tr.ID == id {
			found = true
		}
	}
	if !found || len(uses) != 0 {
		t.Fatal("authorized op missing from the ready view")
	}
	pu, pt, err := svc.DB().ListPendingOps()
	if err != nil {
		t.Fatal(err)
	}
	if len(pu)+len(pt) != 0 {
		t.Fatal("authorized op leaks into the approval queue")
	}
	d, err := svc.StatusDetail("uid:1000", "transfer", id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != types.StatusAuthorized || !strings.Contains(d.NextAction, "admin execute") {
		t.Fatalf("agent cannot see the execution path: %+v", d)
	}
}

// G04: expiry is a visible lifecycle transition. Expired requests leave
// the actionable queues, read as expired, and cannot be approved,
// claimed, or executed without a fresh cycle.
func TestExpiryLifecycle(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Read-path mapping holds even before any sweep runs.
	stored, _ := svc.DB().GetUse(id)
	if got := effectiveStatus(stored.Status, time.Now().Add(-time.Second), time.Now()); got != types.StatusExpired {
		t.Fatalf("effective status=%s, want expired", got)
	}
	n, err := svc.DB().ExpireOpenOperations(time.Now().Add(10 * time.Minute))
	if err != nil || n < 1 {
		t.Fatalf("sweep expired %d, err=%v", n, err)
	}
	d, err := svc.StatusDetail("uid:1000", "use", id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != types.StatusExpired || !strings.Contains(d.NextAction, "fresh request") {
		t.Fatalf("expired request misreported: %+v", d)
	}
	pu, _, err := svc.DB().ListPendingOps()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range pu {
		if u.ID == id {
			t.Fatal("expired request still in the actionable queue")
		}
	}
	stored, _ = svc.DB().GetUse(id)
	if err := svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision); err == nil {
		t.Fatal("expired request approved without a fresh cycle")
	}
	if _, claimed, _ := svc.DB().ClaimUse(id, stored.OpHash, stored.DestDigest, stored.Revision, "w", time.Now().Add(time.Minute)); claimed {
		t.Fatal("expired request claimed without a fresh cycle")
	}
}

// G06: the agent discovers what it may actually invoke. Ready operations
// show arguments; scoped ones stay honest about needing an exact
// target/resource; disallowed operations stay hidden.
func TestCatalogDiscovery(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	sr := &types.SecretReference{ID: "gh", Name: "gh", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	p := &types.Policy{Name: "scoped", Priority: 10, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"gh"},
			Ops: []string{"github.get_repo"}, DestIDs: []string{"*"},
			Resources: []string{"github.repository:o/r"},
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
	entries, err := svc.Catalog("uid:1000")
	if err != nil || len(entries) != 1 {
		t.Fatalf("catalog=%v err=%v", entries, err)
	}
	byName := map[string]CatalogOp{}
	for _, op := range entries[0].Operations {
		byName[op.Name] = op
	}
	got, ok := byName["github.get_repo"]
	if !ok {
		t.Fatalf("permitted op hidden: %+v", entries[0].Operations)
	}
	if got.Access != "scoped" {
		t.Fatalf("repo-scoped op advertised as %q", got.Access)
	}
	if len(got.Params) == 0 || got.Params[0].Name != "repo" {
		t.Fatalf("required arguments undiscoverable: %+v", got)
	}
	if _, ok := byName["github.list_issues"]; ok {
		t.Fatal("unpermitted op listed in catalog")
	}
	if _, ok := byName["transfer"]; ok {
		t.Fatal("unpermitted transfer listed in catalog")
	}
	// A wildcard rule promotes the op to ready.
	p2 := &types.Policy{Name: "open", Priority: 5, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"gh"},
			Ops: []string{"github.list_issues"}, DestIDs: []string{"*"},
			Resources: []string{"*"},
		}},
	}
	if err := svc.DB().CreatePolicy(p2); err != nil {
		t.Fatal(err)
	}
	entries, _ = svc.Catalog("uid:1000")
	for _, op := range entries[0].Operations {
		byName[op.Name] = op
	}
	if byName["github.list_issues"].Access != "ready" {
		t.Fatalf("wildcard op not ready: %+v", byName["github.list_issues"])
	}
	if _, err := svc.Catalog("uid:9999"); err != nil {
		t.Fatal(err)
	}
}

// P1 false-ready fix: advertised access must agree with admission.
// Empty resources, exact identifiers, kind wildcards, and unrestricted
// wildcards each classify distinctly — and match what submit/admission
// would actually allow.
func TestCatalogAdmissionMatrix(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	sr := &types.SecretReference{ID: "m", Name: "m", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	mk := func(name string, res []string, dests []string, ops []string) {
		p := &types.Policy{Name: name, Priority: 10, Enabled: true, Revision: 1,
			Rules: []types.PolicyRule{{
				Principal: "uid:1000", SecretRefs: []string{"m"},
				Ops: ops, DestIDs: dests, Resources: res,
			}},
		}
		if err := svc.DB().CreatePolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	mk("empty-res", nil, []string{"*"}, []string{"github.get_repo"})
	entries, err := svc.Catalog("uid:1000")
	if err != nil || len(entries) != 1 {
		t.Fatalf("catalog=%v err=%v", entries, err)
	}
	access := ""
	for _, op := range entries[0].Operations {
		if op.Name == "github.get_repo" {
			access = op.Access
		}
	}
	if access != "scoped" {
		t.Fatalf("resourceless rule advertised resource-bearing op as %q, want scoped", access)
	}
	// And admission agrees: the op is denied without a scoped resource.
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "m", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	}); err == nil {
		t.Fatal("resourceless rule admitted a resource-bearing op")
	}
	// Kind wildcard promotes to ready and admits.
	mk("kind-open", []string{"github.repository:*"}, []string{"*"}, []string{"github.list_issues"})
	entries, _ = svc.Catalog("uid:1000")
	for _, op := range entries[0].Operations {
		if op.Name == "github.list_issues" && op.Access != "ready" {
			t.Fatalf("kind-wildcard op advertised as %q, want ready", op.Access)
		}
	}
	// Transfer with wildcard dests needs a destination, not ready.
	mk("tx-open", []string{"*"}, []string{"*"}, []string{"transfer"})
	entries, _ = svc.Catalog("uid:1000")
	for _, op := range entries[0].Operations {
		if op.Name == "transfer" && op.Access != "needs_destination" {
			t.Fatalf("transfer advertised as %q, want needs_destination", op.Access)
		}
	}
}

// G07: concurrent observations order by observation time, not completion
// order, and evidence kinds survive the round trip.
func TestObservationOrderingAndKind(t *testing.T) {
	svc := testService(t)
	base := time.Now()
	first := &metadata.Observation{
		OperationID: "op-ord", VerifierID: "v", VerifierVersion: "1",
		State: metadata.ObsContradicted, ObservedAt: base.Add(2 * time.Second),
		EvidenceDigest: "d1", EvidenceKind: metadata.EvidenceExternal,
		Source: "s", Details: "later observation recorded first",
	}
	second := &metadata.Observation{
		OperationID: "op-ord", VerifierID: "v", VerifierVersion: "1",
		State: metadata.ObsSatisfied, ObservedAt: base,
		EvidenceDigest: "d2", EvidenceKind: metadata.EvidenceAssertion,
		Source: "s", Details: "earlier observation recorded second",
	}
	if err := svc.DB().RecordObservation(first); err != nil {
		t.Fatal(err)
	}
	if err := svc.DB().RecordObservation(second); err != nil {
		t.Fatal(err)
	}
	latest, err := svc.DB().LatestObservation("op-ord")
	if err != nil || latest.State != metadata.ObsContradicted {
		t.Fatalf("history ordered by completion, not observation: %+v %v", latest, err)
	}
	if latest.EvidenceKind != metadata.EvidenceExternal || latest.RecordedAt.IsZero() {
		t.Fatalf("provenance lost: %+v", latest)
	}
	hist, err := svc.DB().ListObservations("op-ord")
	if err != nil || len(hist) != 2 || hist[0].State != metadata.ObsSatisfied {
		t.Fatalf("history wrong: %+v %v", hist, err)
	}
}

// G09: the finalizer enforces attempt ownership and receipt pairing. A
// wrong attempt, a replayed finalization, a completed-without-receipt,
// and a receipt-paired-with-failure are all rejected.
func TestFinalizerOwnership(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	mk := func() (id, attempt string) {
		id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
			SecretRef: "s1", Operation: "github.get_repo",
			Params: map[string]string{"repo": "o/r"},
		})
		if err != nil {
			t.Fatal(err)
		}
		st, _ := svc.DB().GetUse(id)
		if err := svc.DB().ApproveUse(id, "op", st.OpHash, st.AuthEpoch, st.Revision); err != nil {
			t.Fatal(err)
		}
		st, _ = svc.DB().GetUse(id)
		a, ok, err := svc.DB().ClaimUse(id, st.OpHash, st.DestDigest, st.Revision, "w", time.Now().Add(time.Minute))
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return id, a
	}
	id, attempt := mk()
	if err := svc.DB().FinalizeOp("use", id, "att-bogus", types.StatusCompleted, "github.get_repo", map[string]interface{}{"a": 1}); err == nil {
		t.Fatal("foreign attempt finalized the operation")
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusCompleted, "", nil); err == nil {
		t.Fatal("completed-without-receipt accepted")
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusFailed, "github.get_repo", map[string]interface{}{"a": 1}); err == nil {
		t.Fatal("receipt-paired-with-failure accepted")
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusCompleted, "github.get_repo", map[string]interface{}{"a": 1}); err != nil {
		t.Fatalf("valid finalization rejected: %v", err)
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusFailed, "", nil); err == nil {
		t.Fatal("replayed finalization overwrote a terminal state")
	}
	// Cross-operation attempt: B's attempt cannot finalize A.
	ida, atta := mk()
	idb, _ := mk()
	_ = atta
	if err := svc.DB().FinalizeOp("use", ida, "att-cross", types.StatusFailed, "", nil); err == nil {
		t.Fatal("unknown attempt finalized")
	}
	attB, _, _ := svc.DB().OpenAttempt(idb)
	if err := svc.DB().FinalizeOp("use", ida, attB, types.StatusFailed, "", nil); err == nil {
		t.Fatal("sibling attempt finalized another operation")
	}
}
