package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// relayService builds a service on a known DB path so tests can scan
// the raw SQLite file for leaked plaintext (QR-09/QR-10).
func relayService(t *testing.T) (*Service, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc, dbPath
}

const relaySecret = "otp-TEST-972134-secret-value"

// relayDest registers a store recipient (countable deliveries,
// optional lost-ack mode) and returns its destination.
func relayDest(t *testing.T, svc *Service, id string, dropAck bool) (*types.Destination, *storeRecipient) {
	t.Helper()
	r := startStoreRecipient(t, dropAck)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{ID: id, Name: "relay-recipient", Type: "recipient-socket", Endpoint: r.sock, ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	return dest, r
}

func countDeliveries(r *storeRecipient) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.store)
}

func relayPayload(t *testing.T, r *storeRecipient, opID string) []byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.store {
		if strings.HasPrefix(k, opID+"/") {
			return v
		}
	}
	return nil
}

// QR-10 primary: user material in, recipient bytes out, agent sees only
// status. The full cycle runs through the real worker, claim, dispatch
// barrier, delivery and finalization — no fixture shortcuts.
func TestRelayFullCycleDelivered(t *testing.T) {
	svc, dbPath := relayService(t)
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "one_time_code", "login step", 5*time.Minute, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	svc.runWorkerOnce(context.Background())
	tr, _ := svc.DB().GetTransfer(opID)
	if tr.Status != types.StatusCompleted {
		t.Fatalf("op status = %s, want completed", tr.Status)
	}
	if got := relayPayload(t, r, opID); string(got) != relaySecret {
		t.Fatal("recipient did not receive the exact bytes")
	}
	st, err := svc.RelayStatus("uid:1000", reqID)
	if err != nil {
		t.Fatal(err)
	}
	if st["status"] != types.RelayDelivered || st["recipient_status"] != "durably_accepted" {
		t.Fatalf("status = %+v, want delivered/durably_accepted", st)
	}
	// F07: the broker asserts only broker-observable facts. No
	// secret_exposed-style field may appear; the receipt-level
	// invariant is plaintext_in_public_receipt.
	if _, ok := st["secret_exposed"]; ok {
		t.Fatal("status claims properties outside the broker boundary")
	}
	if st["plaintext_in_public_receipt"] != false {
		t.Fatal("broker receipt contains plaintext")
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), relaySecret) {
		t.Fatal("plaintext in agent-visible status")
	}
	// No plaintext anywhere outside the trusted boundary: raw DB file,
	// audit trail and receipt must not contain the value.
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dbBytes), relaySecret) {
		t.Fatal("plaintext persisted in SQLite file (data, WAL, or freelist)")
	}
	logs, _ := svc.DB().ListAuditLogs(200)
	for _, l := range logs {
		if strings.Contains(l.Action+l.Actor+l.Target+l.Outcome+l.Metadata, relaySecret) {
			t.Fatalf("plaintext in audit log: %+v", l)
		}
	}
	rec, _ := svc.DB().GetReceipt(opID)
	if rec != nil && strings.Contains(rec.Result, relaySecret) {
		t.Fatal("plaintext in durable receipt")
	}
}

// The agent cannot read the value back: status carries no payload, and
// no agent method returns plaintext (method surface asserted separately
// in the IPC allowlist tests).
func TestRelayAgentCannotReadValue(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	for _, st := range []struct {
		agent, id string
	}{
		{"uid:1000", reqID},
	} {
		m, err := svc.RelayStatus(st.agent, st.id)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), relaySecret) {
			t.Fatal("value reachable through agent status")
		}
		for _, k := range []string{"payload", "secret", "value", "bytes"} {
			if _, ok := m[k]; ok {
				t.Fatalf("status exposes %q field", k)
			}
		}
	}
}

// Two fulfillments race: exactly one wins the CAS; the loser's staged
// bytes are dropped, never attached to the relay.
func TestRelayDoubleFulfillOneWinner(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte("second-value")); err == nil {
		t.Fatal("second fulfillment of one request succeeded")
	}
	if svc.eph.Live(relayPayloadKey(reqID)) == false {
		t.Fatal("original payload lost after conflict")
	}
}

// Single-use race (QR-05): two authorized operations, one value. The
// worker runs both; exactly one delivery happens and the loser fails
// closed (never waits, never receives).
func TestRelaySingleUseRaceOneDelivery(t *testing.T) {
	svc := testService(t)
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "one_time_code", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	op1, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	op2, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: RelayRefPrefix + reqID, DestinationID: "rd1",
	})
	if err != nil {
		t.Fatalf("budget-bound follow-up refused before execution: %v", err)
	}
	svc.runWorkerOnce(context.Background())
	done := 0
	for _, id := range []string{op1, op2} {
		tr, _ := svc.DB().GetTransfer(id)
		if tr.Status == types.StatusCompleted {
			done++
		}
	}
	if done != 1 {
		t.Fatalf("completed = %d, want exactly 1", done)
	}
	if n := countDeliveries(r); n != 1 {
		t.Fatalf("recipient deliveries = %d, want exactly 1", n)
	}
}

// Reusable reference (QR-05/QR-08): two independently authorized apps
// proceed concurrently through the bounded pool.
func TestRelayReusableConcurrentApps(t *testing.T) {
	svc := testService(t)
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "api_key", "configure integration", 0, types.RelayReusable, 0)
	if err != nil {
		t.Fatal(err)
	}
	fulfillOp, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	ops := []string{fulfillOp}
	for i := 0; i < 2; i++ {
		id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
			SecretRef: RelayRefPrefix + reqID, DestinationID: "rd1",
		})
		if err != nil {
			t.Fatalf("reusable follow-up %d refused: %v", i, err)
		}
		ops = append(ops, id)
	}
	svc.runWorkerOnce(context.Background())
	for _, id := range ops {
		tr, _ := svc.DB().GetTransfer(id)
		if tr.Status != types.StatusCompleted {
			dumpAudits(t, svc)
			t.Fatalf("reusable op %s = %s, want completed", id, tr.Status)
		}
	}
	// All three bound operations (fulfillment + two follow-ups)
	// deliver independently through the shared grant.
	if n := countDeliveries(r); n != 3 {
		t.Fatalf("deliveries = %d, want 3", n)
	}
}

// Wrong agent: a valid locator confers nothing. Status, submit and
// reservation all deny the foreign principal.
func TestRelayForeignAgentDenied(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayStatus("uid:9999", reqID); err == nil {
		t.Fatal("foreign agent read another agent's relay")
	}
	if err := svc.RelayCancel("uid:9999", reqID, false); err == nil {
		t.Fatal("foreign agent cancelled another agent's relay")
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitTransfer("uid:9999", &types.TransferRequest{
		SecretRef: RelayRefPrefix + reqID, DestinationID: "rd1",
	}); err == nil {
		t.Fatal("foreign agent bound an op to the grant")
	}
	if err := svc.DB().ReserveRelay(reqID, "op-x", "uid:9999", "rd1", time.Now()); err == nil {
		t.Fatal("foreign agent reserved the value")
	}
}

// Substituted recipient (SP-TUI-08): the grant covers exactly the
// approved destination. A different dest, or a repointed one, fails.
func TestRelaySubstitutedRecipientDenied(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	_, r2 := relayDest(t, svc, "rd2", false)
	_ = r2
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: RelayRefPrefix + reqID, DestinationID: "rd2",
	}); err == nil {
		t.Fatal("handoff rebound to another recipient")
	}
	// Repoint rd1 after approval: reservation must fail closed.
	uid := uint32(os.Geteuid())
	other := "/tmp/seqpass-relay-test-other.sock"
	if err := svc.DB().UpdateDestinationRecipient("rd1", other, &uid, nil, "operator"); err != nil {
		t.Fatal(err)
	}
	tr, _ := svc.DB().GetTransfer(mustRelayOp(t, svc, reqID))
	if err := svc.DB().ReserveRelay(reqID, tr.ID, "uid:1000", "rd1", time.Now()); err == nil {
		t.Fatal("reservation survived recipient repointing")
	}
}

// dumpAudits prints the recent audit trail for failure diagnosis (the
// outcome column carries the denial reason; never secret material).
func dumpAudits(t *testing.T, svc *Service) {
	t.Helper()
	logs, _ := svc.DB().ListAuditLogs(40)
	for _, l := range logs {
		t.Logf("audit %s op=%s outcome=%s", l.Action, l.OperationID, l.Outcome)
	}
}

func mustRelayOp(t *testing.T, svc *Service, reqID string) string {
	t.Helper()
	r, err := svc.DB().GetRelay(reqID)
	if err != nil || r == nil || r.OpID == "" {
		t.Fatalf("no bound op: %+v %v", r, err)
	}
	return r.OpID
}

// Expiry (QR-05): a lapsed relay authorizes nothing — reservation,
// sweep and execution all refuse, and staged bytes are dropped.
func TestRelayExpiryEnforced(t *testing.T) {
	svc := testService(t)
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "one_time_code", "login", 30*time.Second, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := svc.DB().ReserveRelay(reqID, opID, "uid:1000", "rd1", future); err == nil {
		t.Fatal("reservation past relay deadline succeeded")
	}
	ids, err := svc.DB().ExpireRelays(future)
	if err != nil || len(ids) != 1 || ids[0] != reqID {
		t.Fatalf("sweep = %v %v, want [%s]", ids, err, reqID)
	}
	svc.eph.Delete(relayPayloadKey(reqID))
	svc.runWorkerOnce(context.Background())
	tr, _ := svc.DB().GetTransfer(opID)
	if tr.Status == types.StatusCompleted {
		t.Fatal("expired relay delivered")
	}
	if n := countDeliveries(r); n != 0 {
		t.Fatal("expired relay reached the recipient")
	}
	if svc.eph.Live(relayPayloadKey(reqID)) {
		t.Fatal("expired payload still staged")
	}
}

// Lost acknowledgment (QR-05/QR-10): the recipient persists but the ack
// never arrives. The op is uncertain, the relay follows, the single-use
// value is dropped (no second delivery exists), and reconciliation
// points at the ORIGINAL recipient via the dispatch record.
func TestRelayLostAckUncertain(t *testing.T) {
	svc := testService(t)
	_, r := relayDest(t, svc, "rd1", true)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "handoff", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	svc.runWorkerOnce(context.Background())
	tr, _ := svc.DB().GetTransfer(opID)
	if tr.Status != types.StatusUncertain {
		t.Fatalf("op = %s, want uncertain", tr.Status)
	}
	if got := relayPayload(t, r, opID); string(got) != relaySecret {
		t.Fatal("recipient did not durably receive before the lost ack")
	}
	rl, _ := svc.DB().GetRelay(reqID)
	if rl.State != types.RelayUncertain {
		t.Fatalf("relay = %s, want uncertain", rl.State)
	}
	if svc.eph.Live(relayPayloadKey(reqID)) {
		t.Fatal("single-use payload retained after uncertain delivery")
	}
	rec, err := svc.DB().GetDispatch(opID)
	if err != nil || rec == nil || rec.DestID != "rd1" {
		t.Fatal("reconciliation lost the original recipient")
	}
	st, _ := svc.RelayStatus("uid:1000", reqID)
	if st["status"] != types.RelayUncertain {
		t.Fatalf("agent status = %v, want uncertain", st["status"])
	}
}

// Restart (QR-01/05): staged bytes die with the process. After reopen,
// the relay reads unavailable (never ready/authorized), the op fails
// truthfully, and nothing reaches the recipient.
func TestRelayRestartUnavailable(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/relay-restart.db"
	mk := func() *Service {
		s, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	svc := mk()
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "handoff", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2 := mk()
	defer svc2.Close()
	rl, _ := svc2.DB().GetRelay(reqID)
	if rl.State != types.RelayUnavailable {
		t.Fatalf("relay after restart = %s, want unavailable", rl.State)
	}
	svc2.runWorkerOnce(context.Background())
	tr, _ := svc2.DB().GetTransfer(opID)
	if tr.Status == types.StatusCompleted {
		t.Fatal("unavailable payload delivered after restart")
	}
	if n := countDeliveries(r); n != 0 {
		t.Fatal("recipient reached after restart")
	}
	_ = r
}

// Accepted is not applied (QR-10): the receipt proves durable
// recipient acceptance; the agent status must not claim downstream
// application happened.
func TestRelayAcceptedNotApplied(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "api_key", "configure", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, relayRev(svc, reqID), []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	svc.runWorkerOnce(context.Background())
	st, _ := svc.RelayStatus("uid:1000", reqID)
	raw, _ := json.Marshal(st)
	s := strings.ToLower(string(raw))
	if strings.Contains(s, "applied") {
		t.Fatal("status claims application beyond acceptance")
	}
	if st["recipient_status"] != "durably_accepted" {
		t.Fatalf("recipient_status = %v", st["recipient_status"])
	}
}

// Request validation: unknown kinds, unknown recipients, and bad
// consumption fail before any row exists.
func TestRelayRequestValidation(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	if _, err := svc.RelayRequest("uid:1000", "rd1", "passport_number", "x", 0, "", 0); err == nil {
		t.Fatal("free-form data kind accepted")
	}
	if _, err := svc.RelayRequest("uid:1000", "no-such-dest", "password", "x", 0, "", 0); err == nil {
		t.Fatal("unregistered recipient accepted")
	}
	if _, err := svc.RelayRequest("", "rd1", "password", "x", 0, "", 0); err == nil {
		t.Fatal("missing agent accepted")
	}
	if _, err := svc.RelayRequest("uid:1000", "rd1", "password", "x", 0, types.RelayBoundedUses, 0); err == nil {
		t.Fatal("bounded_uses with zero budget accepted")
	}
}

// Metadata-level reservation matrix (QR-05): budget accounting,
// holder binding, and release-before-dispatch semantics.
func TestRelayReservationMatrix(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	mk := func(consumption string, max uint32) string {
		id, err := svc.RelayRequest("uid:1000", "rd1", "token", "use", time.Hour, consumption, max)
		if err != nil {
			t.Fatal(err)
		}
		// Advance to authorized without staging: flip via fulfill path
		// with a real payload so reservation has bytes behind it.
		if _, err := svc.RelayFulfill("operator", id, relayRev(svc, id), []byte("v-"+id)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// Bounded 2: two reserves ok, third denied.
	b := mk(types.RelayBoundedUses, 2)
	now := time.Now()
	if err := svc.DB().ReserveRelay(b, "op-a", "uid:1000", "rd1", now); err != nil {
		t.Fatalf("reserve 1: %v", err)
	}
	if err := svc.DB().ReserveRelay(b, "op-b", "uid:1000", "rd1", now); err != nil {
		t.Fatalf("reserve 2: %v", err)
	}
	if err := svc.DB().ReserveRelay(b, "op-c", "uid:1000", "rd1", now); err == nil {
		t.Fatal("reserve past budget succeeded")
	}
	// Release returns one unit pre-dispatch.
	if err := svc.DB().ReleaseRelayReservation(b, "op-a", now); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := svc.DB().ReserveRelay(b, "op-c", "uid:1000", "rd1", now); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	// Single-use: second reserve denied; foreign op cannot release.
	u := mk(types.RelaySingleDispatch, 1)
	if err := svc.DB().ReserveRelay(u, "op-1", "uid:1000", "rd1", now); err != nil {
		t.Fatalf("single reserve: %v", err)
	}
	if err := svc.DB().ReserveRelay(u, "op-2", "uid:1000", "rd1", now); err == nil {
		t.Fatal("single-use second reservation succeeded")
	}
	if err := svc.DB().ReleaseRelayReservation(u, "op-2", now); err == nil {
		t.Fatal("foreign op released the hold")
	}
	if err := svc.DB().ReleaseRelayReservation(u, "op-1", now); err != nil {
		t.Fatalf("holder release: %v", err)
	}
}
