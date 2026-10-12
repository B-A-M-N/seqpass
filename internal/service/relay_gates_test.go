package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// F01: a changed recipient must not replace the one originally requested.
// Request, repoint/re-pin the destination, then fulfill: zero payload bytes
// may be dispatched and the stale request must be refused.
func TestRelayFulfillRefusesChangedRecipient(t *testing.T) {
	svc := testService(t)
	_, r := relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Legitimate-looking change after the agent's request: new endpoint.
	if err := svc.DB().UpdateDestinationEndpoint("rd1", "/tmp/evil.sock", "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret)); err == nil {
		t.Fatal("fulfillment rebound to a changed recipient")
	}
	if n := countDeliveries(r); n != 0 {
		t.Fatalf("dispatched %d payloads to changed recipient", n)
	}
	got, err := svc.DB().GetRelay(reqID)
	if err != nil || got == nil {
		t.Fatal("relay row lost")
	}
	if got.State != types.RelayAwaitingUser {
		t.Fatalf("stale request state = %s, want awaiting_user (fresh request required)", got.State)
	}
}

// F02: after a successful single-use handoff, no holder or backing
// plaintext may remain — Live()==false alone proves nothing.
func TestRelaySingleUseClearsMemory(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteTransfer(context.Background(), opID, "test"); err != nil {
		t.Fatal(err)
	}
	key := relayPayloadKey(reqID)
	if n := svc.eph.Holders(key); n != 0 {
		t.Fatalf("holders = %d, want 0 after single-use delivery", n)
	}
	if svc.eph.HasBacking(key) {
		t.Fatal("backing plaintext retained after single-use delivery")
	}
	if svc.eph.Live(key) {
		t.Fatal("payload still live after single-use delivery")
	}
}

// F02: reusable deliveries must not accumulate completed-operation holders,
// and expiry detected by a failed read must still clear backing storage.
func TestRelayReusableLeavesNoHolders(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "api_key", "shared", 0, types.RelayReusable, 0)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteTransfer(context.Background(), opID, "test"); err != nil {
		t.Fatal(err)
	}
	key := relayPayloadKey(reqID)
	if n := svc.eph.Holders(key); n != 0 {
		t.Fatalf("holders = %d, want 0 after reusable delivery", n)
	}
	// Expiry first observed by a failed read, then swept: bytes cleared.
	if err := svc.eph.Store("exp-test", []byte("v"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if _, err := svc.eph.GetFor("exp-test", "nobody"); err == nil {
		t.Fatal("unreserved read succeeded")
	}
	// A failed GetFor on an unexpired key does not expire it; force expiry
	// through time and confirm the sweep reaps previously marked entries.
	if n := svc.eph.Sweep(future); n < 1 {
		t.Fatalf("swept = %d, want >= 1", n)
	}
	if svc.eph.HasBacking("exp-test") {
		t.Fatal("expired backing bytes retained after sweep")
	}
}

// F08: ten concurrent operations on one reusable grant produce ten distinct
// delivery records with a consistent budget — no lost correlation, no
// double refund on out-of-order completion.
func TestRelayTenConcurrentDeliveries(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "api_key", "fleet", 0, types.RelayReusable, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	ops := []string{first}
	for i := 0; i < 9; i++ {
		id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
			SecretRef: RelayRefPrefix + reqID, DestinationID: "rd1",
		})
		if err != nil {
			t.Fatalf("follow-up %d refused: %v", i, err)
		}
		ops = append(ops, id)
	}
	svc.runWorkerOnce(context.Background())
	for _, id := range ops {
		tr, _ := svc.DB().GetTransfer(id)
		if tr.Status != types.StatusCompleted {
			t.Fatalf("op %s = %s, want completed", id, tr.Status)
		}
	}
	if n, _ := svc.DB().DeliveryCount(reqID); n != 10 {
		t.Fatalf("delivery rows = %d, want 10 distinct records", n)
	}
	got, _ := svc.DB().GetRelay(reqID)
	if got.UsedDeliveries != 10 {
		t.Fatalf("used_deliveries = %d, want 10", got.UsedDeliveries)
	}
}

// F11: a broker restart must keep valid awaiting_user requests fulfillable
// (no staged plaintext exists yet) while marking staged-but-undelivered
// material unavailable.
func TestRelayRestartPreservesAwaitingUser(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	pending, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", staged, []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	n, err := svc.DB().MarkRelaysUnavailable(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("marked = %d, want 1 (only the staged relay)", n)
	}
	got, _ := svc.DB().GetRelay(pending)
	if got.State != types.RelayAwaitingUser {
		t.Fatalf("pending request state = %s, want awaiting_user across restart", got.State)
	}
	got2, _ := svc.DB().GetRelay(staged)
	if got2.State != types.RelayUnavailable {
		t.Fatalf("staged relay state = %s, want unavailable (memory lost)", got2.State)
	}
}

// F05: a fulfilled quick relay dispatches through the broker-managed relay
// queue without --auto-execute and without manual admin execute. Only
// relay-backed transfers move; standing-policy ops never do.
func TestRelayQueueDeliversWithoutAutoExecute(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "one_time_code", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret)); err != nil {
		t.Fatal(err)
	}
	if n := svc.ExecuteReadyRelays(context.Background()); n != 1 {
		t.Fatalf("relay queue delivered %d, want 1", n)
	}
	st, err := svc.RelayStatus("uid:1000", reqID)
	if err != nil {
		t.Fatal(err)
	}
	if st["status"] != types.RelayDelivered {
		t.Fatalf("status = %v, want delivered", st["status"])
	}
}

// F07: every displayed state carries matching next-action guidance, and no
// public response claims properties outside the broker's boundary.
func TestRelayStatusTruthfulness(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	reqID, err := svc.RelayRequest("uid:1000", "rd1", "password", "login", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := svc.RelayStatus("uid:1000", reqID)
	if err != nil {
		t.Fatal(err)
	}
	if st["status"] != types.RelayAwaitingUser {
		t.Fatalf("status = %v", st["status"])
	}
	if next, _ := st["next"].(string); !strings.Contains(next, "trusted intake") {
		t.Fatalf("awaiting_user next = %q, mismatched guidance", next)
	}
	if _, ok := st["secret_exposed"]; ok {
		t.Fatal("public status claims secret_exposed — outside broker boundary")
	}
	if v, _ := st["plaintext_in_public_receipt"].(bool); v {
		t.Fatal("broker receipt contains plaintext")
	}
	opID, err := svc.RelayFulfill("operator", reqID, []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteTransfer(context.Background(), opID, "test"); err != nil {
		t.Fatal(err)
	}
	st, _ = svc.RelayStatus("uid:1000", reqID)
	if st["status"] != types.RelayDelivered {
		t.Fatalf("status = %v, want delivered", st["status"])
	}
	if next, _ := st["next"].(string); !strings.Contains(next, "Recipient accepted") {
		t.Fatalf("delivered next = %q, mismatched guidance", next)
	}
}

// F09: once an intake owner claims a request, a different intake identity
// cannot cancel it — even knowing the request ID.
func TestRelayCrossUserCancelDenied(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	_, _, err := svc.RelayUserInit("uid:alice", "rd1", "password", "mine", 0, []byte(relaySecret))
	if err != nil {
		t.Fatal(err)
	}
	// Find Alice's request via her agent principal.
	list, err := svc.DB().ListAgentRelays("uid:alice", 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("alice relays = %d, err = %v", len(list), err)
	}
	reqID := list[0].ID
	if err := svc.RelayCancel("uid:bob", reqID, true); err == nil {
		t.Fatal("cross-user intake cancel succeeded")
	}
	if err := svc.RelayCancel("uid:alice", reqID, true); err != nil {
		t.Fatalf("owner cancel refused: %v", err)
	}
}

// F10/F17: untrusted agent text is bounded at admission; request volume is
// bounded per principal.
func TestRelayAdmissionBounds(t *testing.T) {
	svc := testService(t)
	_, _ = relayDest(t, svc, "rd1", false)
	evil := "need it\x1b[2J\x1b[1;1HOTHER-RECEPIENT ok?"
	if _, err := svc.RelayRequest("uid:1000", "rd1", "password", evil, 0, "", 0); err == nil {
		t.Fatal("ANSI escape payload in purpose accepted")
	}
	if _, err := svc.RelayRequest("uid:1000", "rd1", "password", strings.Repeat("x", 501), 0, "", 0); err == nil {
		t.Fatal("oversized purpose accepted")
	}
	for i := 0; i < 20; i++ {
		if _, err := svc.RelayRequest("uid:1000", "rd1", "password", "flood", 0, "", 0); err != nil {
			t.Fatalf("pending %d refused: %v", i, err)
		}
	}
	if _, err := svc.RelayRequest("uid:1000", "rd1", "password", "flood", 0, "", 0); err == nil {
		t.Fatal("21st pending request accepted (no per-principal bound)")
	}
}
