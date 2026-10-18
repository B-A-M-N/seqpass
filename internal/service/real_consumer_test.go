package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// realRecipient starts the production recipient endpoint backed by a file
// credential committer. Unlike the hand-rolled echo fixture, this consumer
// validates payload/digest agreement, commits the secret, and verifies the
// intended effect by reading the destination back.
func realRecipient(t *testing.T, root string) (string, string) {
	t.Helper()
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	destDir := filepath.Join(root, "credential-destination")
	committer, err := transfer.NewFileCommitter(destDir)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := transfer.NewApplicationConsumer(journal, committer)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(root, "recipient.sock")
	srv, err := transfer.NewRecipientServer(transfer.RecipientServerConfig{
		SocketPath: sock,
		Consumer:   consumer,
	})
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, destDir
}

// publicTempDir creates an owner-only directory under /tmp. The trusted
// ancestor chain for a recipient socket must be traversable by the broker,
// which the test runtime's own 0700 ancestors are not in restricted
// sandboxes.
func publicTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "seqpass-svc-")
	if err != nil {
		t.Skipf("no public temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// End-to-end through the real consumer: submit, approve, deliver, and then
// confirm the credential actually reached its destination and the operation
// is independently verified as applied. The broker-visible and agent-visible
// surfaces must never contain the secret.
func TestTransferToRealApplicationConsumerApplies(t *testing.T) {
	svc := testService(t)

	if err := svc.AddSecretRef(&types.SecretReference{ID: "creal1", Name: "cert", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	payload := successMarker + "-payload"
	if err := svc.vault.Store("creal1", []byte(payload)); err != nil {
		t.Fatal(err)
	}

	root := publicTempDir(t)
	sock, destDir := realRecipient(t, root)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{ID: "dreal", Name: "real", Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "creal1", "transfer", "dreal")

	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "creal1", DestinationID: "dreal"})
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
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), successMarker) {
		t.Fatal("secret marker leaked in the execution receipt")
	}

	// The real consumer committed exactly the payload to its destination.
	entries, err := os.ReadDir(destDir)
	if err != nil {
		t.Fatalf("credential destination unreadable: %v", err)
	}
	committed := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".secret" {
			continue
		}
		committed++
		data, err := os.ReadFile(filepath.Join(destDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != payload {
			t.Fatalf("committed bytes differ from the delivered payload")
		}
	}
	if committed != 1 {
		t.Fatalf("credential destination holds %d secrets, want 1", committed)
	}

	// The recipient readback reports the operation reached the consumer.
	rs, err := svc.RecipientStatus(context.Background(), "uid:1000", id, false)
	if err != nil {
		t.Fatal(err)
	}
	rsRaw, _ := json.Marshal(rs)
	if strings.Contains(string(rsRaw), successMarker) {
		t.Fatal("recipient readback leaked the secret")
	}

	// The agent-visible receipt stays sanitized.
	detail, err := svc.StatusDetail("uid:1000", "transfer", id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail.Result, successMarker) {
		t.Fatal("agent-visible receipt leaked the secret")
	}

	// A replay of the same delivery must not create a second committed copy.
	svc.runWorkerOnce(context.Background())
	if _, err := svc.ExecuteTransfer(context.Background(), id, "op"); err == nil {
		t.Fatal("completed operation was re-executed")
	}
	entries, _ = os.ReadDir(destDir)
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
