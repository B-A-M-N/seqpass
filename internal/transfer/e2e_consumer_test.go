package transfer

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

// testDest pins a recipient socket to the current effective UID.
func testDest(t *testing.T, sock string) *types.Destination {
	t.Helper()
	uid := uint32(os.Geteuid())
	return &types.Destination{ID: "dest1", Name: "dest1", Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}
}

func mkRuntimeDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Skipf("no temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// startAppConsumer boots a recipient endpoint backed by an ApplicationConsumer
// over a FileCommitter, so a successful delivery is independently verifiable.
func startAppConsumer(t *testing.T, root string, committer CredentialCommitter) (*RecipientServer, *ApplicationConsumer, string) {
	t.Helper()
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewApplicationConsumer(journal, committer)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(root, "recipient.sock")
	srv, err := NewRecipientServer(RecipientServerConfig{
		SocketPath: sock,
		Consumer:   consumer,
	})
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, consumer, sock
}

// A real broker->consumer delivery must leave the secret durably committed at
// the destination and be reported as applied (verified effect), never merely
// "accepted".
func TestDeliverToApplicationConsumerApplies(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-e2e-")
	destDir := filepath.Join(root, "deststore")
	committer, err := NewFileCommitter(destDir)
	if err != nil {
		t.Fatal(err)
	}
	_, consumer, sock := startAppConsumer(t, root, committer)

	secret := "synthetic-api-key-0123456789"
	d := NewDeliverer()
	receipt, err := d.Deliver(context.Background(), "opapply", secret, testDest(t, sock))
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if receipt["delivered"] != true {
		t.Fatalf("bad receipt: %v", receipt)
	}
	// Independently verify the consumer stored exactly the secret.
	got, err := os.ReadFile(filepath.Join(destDir, "opapply.secret"))
	if err != nil {
		t.Fatalf("destination readback: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("destination holds %q, want %q", got, secret)
	}
	state, err := consumer.Lookup(context.Background(), "opapply")
	if err != nil {
		t.Fatal(err)
	}
	if state != StateApplied {
		t.Fatalf("state = %q, want applied", state)
	}
}

// A repeated delivery of the same operation must not repeat the credentialed
// side effect (idempotent replay).
func TestApplicationConsumerIdempotentReplay(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-idem-")
	var calls int64
	counting := &CallbackCommitter{Fn: func(ctx context.Context, d Delivery) (Committed, error) {
		atomic.AddInt64(&calls, 1)
		return Committed{Applied: true, Digest: PayloadDigest(d.Payload)}, nil
	}}
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewApplicationConsumer(journal, counting)
	if err != nil {
		t.Fatal(err)
	}
	d := Delivery{OperationID: "opidem", DataKind: "api_key", Payload: []byte("secret")}
	first, err := consumer.Accept(context.Background(), d)
	if err != nil || first.Duplicate || first.State != StateApplied {
		t.Fatalf("first accept: %+v %v", first, err)
	}
	second, err := consumer.Accept(context.Background(), d)
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if !second.Duplicate || second.State != StateApplied {
		t.Fatalf("replay not idempotent: %+v", second)
	}
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Fatalf("committer called %d times, want 1", n)
	}
}

// A repeated operation id carrying different bytes is a conflict, not a retry.
func TestApplicationConsumerConflict(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-conflict-")
	committer := &CallbackCommitter{Fn: func(ctx context.Context, d Delivery) (Committed, error) {
		return Committed{Applied: true, Digest: PayloadDigest(d.Payload)}, nil
	}}
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewApplicationConsumer(journal, committer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Accept(context.Background(), Delivery{OperationID: "opc", Payload: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Accept(context.Background(), Delivery{OperationID: "opc", Payload: []byte("second")}); err != ErrOperationConflict {
		t.Fatalf("conflict err = %v, want %v", err, ErrOperationConflict)
	}
}

// A consumer that cannot commit must not claim acceptance.
func TestApplicationConsumerCommitFailureNotAccepted(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-fail-")
	failing := &CallbackCommitter{Fn: func(ctx context.Context, d Delivery) (Committed, error) {
		return Committed{}, context.DeadlineExceeded
	}}
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewApplicationConsumer(journal, failing)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := consumer.Accept(context.Background(), Delivery{OperationID: "opfail", Payload: []byte("secret")})
	if err == nil {
		t.Fatal("failed commit reported success")
	}
	if acc.State == StateApplied || acc.State == StateDurablyAccepted {
		t.Fatalf("failed commit claimed state %q", acc.State)
	}
	// The journal shows the operation is not applied, so reconciliation can
	// see it needs attention rather than believing it succeeded.
	state, _ := consumer.Lookup(context.Background(), "opfail")
	if state == StateApplied {
		t.Fatal("failed commit journalled as applied")
	}
}

// Restarting the recipient must not lose the authoritative operation state,
// and reconciliation after a restart must not duplicate the side effect.
func TestRecipientRestartReconciliation(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-restart-")
	destDir := filepath.Join(root, "deststore")
	committer, err := NewFileCommitter(destDir)
	if err != nil {
		t.Fatal(err)
	}
	srv1, _, sock := startAppConsumer(t, root, committer)

	secret := "synthetic-otp-424242"
	d := NewDeliverer()
	if _, err := d.Deliver(context.Background(), "oprestart", secret, testDest(t, sock)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	// Simulate a broker crash+restart: stop the server and boot a fresh one
	// over the same durable journal directory and socket path.
	_ = srv1.Close()
	_ = os.Remove(sock)

	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewApplicationConsumer(journal, committer)
	if err != nil {
		t.Fatal(err)
	}
	srv2, err := NewRecipientServer(RecipientServerConfig{SocketPath: sock, Consumer: consumer})
	if err != nil {
		t.Fatalf("restart recipient: %v", err)
	}
	go srv2.Serve()
	t.Cleanup(func() { _ = srv2.Close() })

	// Authoritative reconciliation: the operation survived the restart.
	res, err := d.LookupExact(context.Background(), testDest(t, sock), "oprestart", DigestPayload(secret))
	if err != nil {
		t.Fatalf("lookup after restart: %v", err)
	}
	if res.Status != RecipientApplied {
		t.Fatalf("post-restart status = %q, want applied", res.Status)
	}
	// Replaying the delivery must not double-apply: the destination still
	// holds exactly one copy of the secret.
	if _, err := d.Deliver(context.Background(), "oprestart", secret, testDest(t, sock)); err != nil {
		t.Fatalf("replay deliver: %v", err)
	}
	entries, err := os.ReadDir(destDir)
	if err != nil {
		t.Fatal(err)
	}
	secrets := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".secret" {
			secrets++
		}
	}
	if secrets != 1 {
		t.Fatalf("destination holds %d secrets after replay, want 1", secrets)
	}
}

// The fixture (metadata-only) recipient is not a production credential
// destination: the consumer interface must reject a delivery it cannot
// validate, and must never report applied.
func TestReferenceRecipientRejectsBadDelivery(t *testing.T) {
	root := mkRuntimeDir(t, "seqpass-fixrej-")
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReferenceRecipient(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(context.Background(), Delivery{OperationID: "../escape", Payload: []byte("x")}); err == nil {
		t.Fatal("unsafe operation id accepted")
	}
	if _, err := r.Accept(context.Background(), Delivery{OperationID: "okid", Payload: nil}); err == nil {
		t.Fatal("empty payload accepted")
	}
}
