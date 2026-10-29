package apptarget

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

func testTarget() types.AppCredentialTarget {
	return types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: OpenCodeAuthJSONV1, SourceRef: "aegis/record-1", SourceRevision: 2}
}

func TestOpenCodeApplyPreservesConfigAndReconcilesReadOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	baseline := []byte(`{"other":{"type":"api","key":"unrelated"},"work":{"type":"api","key":"old","note":"preserve"}}`)
	if err := os.WriteFile(path, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	adapter := OpenCodeAuth{Path: path}
	target := testTarget()
	credential := []byte("synthetic-secret-credential")
	committed, err := adapter.Apply(context.Background(), target, "op-1", credential)
	if err != nil || !committed.Applied || committed.Digest != transfer.PayloadDigest(credential) {
		t.Fatalf("apply: %#v %v", committed, err)
	}
	got, err := adapter.readCredential(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(credential) {
		t.Fatal("readback missed credential")
	}
	zero(got)
	var doc map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["other"].(map[string]any)["key"] != "unrelated" || doc["work"].(map[string]any)["note"] != "preserve" {
		t.Fatal("adapter changed unrelated OpenCode configuration")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("auth file permissions=%o", info.Mode().Perm())
	}
	reconciled, err := adapter.Reconcile(context.Background(), target, "op-1", credential)
	if err != nil || !reconciled.Applied {
		t.Fatalf("reconcile: %#v %v", reconciled, err)
	}
	if err := os.WriteFile(path, []byte(`{"work":{"type":"api","key":"newer-value"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	reconciled, err = adapter.Reconcile(context.Background(), target, "op-1", credential)
	if err != nil || reconciled.Applied {
		t.Fatalf("reconcile falsely accepted changed target: %#v %v", reconciled, err)
	}
}

func TestOpenCodeRejectsWrongTargetAndSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "auth.json")
	adapter := OpenCodeAuth{Path: path}
	target := testTarget()
	wrong := target
	wrong.Slot = "fast"
	if _, err := adapter.Apply(context.Background(), wrong, "op-2", []byte("secret")); err == nil {
		t.Fatal("accepted unsupported app slot")
	}
	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Apply(context.Background(), target, "op-3", []byte("secret")); err == nil {
		t.Fatal("followed symlink credential target")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{}` {
		t.Fatal("symlink target was modified")
	}
}

func TestTransferCommitterRejectsDestinationSubstitution(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "auth.json")
	target := testTarget()
	committer := &TransferCommitter{Target: target, Adapter: OpenCodeAuth{Path: path}}
	other := target
	other.Account = "attacker"
	_, err := committer.Commit(context.Background(), transfer.Delivery{OperationID: "op-4", DataKind: "api_key", Payload: []byte("secret"), Target: &other})
	if err == nil {
		t.Fatal("accepted destination account substitution")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("target was written before identity rejection: %v", err)
	}
}

type crashAfterApply struct{ inner *TransferCommitter }

func (c crashAfterApply) Commit(ctx context.Context, d transfer.Delivery) (transfer.Committed, error) {
	_, _ = c.inner.Commit(ctx, d)
	return transfer.Committed{}, os.ErrDeadlineExceeded // simulate lost completion after the app write
}
func (c crashAfterApply) Reconcile(ctx context.Context, d transfer.Delivery) (transfer.Committed, error) {
	return c.inner.Reconcile(ctx, d)
}

type crashBeforeApply struct{}

func (crashBeforeApply) Commit(context.Context, transfer.Delivery) (transfer.Committed, error) {
	return transfer.Committed{}, os.ErrDeadlineExceeded
}
func (crashBeforeApply) Reconcile(ctx context.Context, d transfer.Delivery) (transfer.Committed, error) {
	return (OpenCodeAuth{Path: ""}).Reconcile(ctx, *d.Target, d.OperationID, d.Payload)
}

func TestApplicationConsumerReconcilesCrashAfterWriteWithoutReapplying(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	target := testTarget()
	adapter := OpenCodeAuth{Path: filepath.Join(root, "auth.json")}
	inner := &TransferCommitter{Target: target, Adapter: adapter}
	delivery := transfer.Delivery{OperationID: "handoff-crash-after-write", DataKind: "api_key", Payload: []byte("synthetic-crash-secret"), Target: &target}
	first, err := transfer.NewApplicationConsumer(journal, crashAfterApply{inner: inner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(context.Background(), delivery); err == nil {
		t.Fatal("expected simulated lost completion")
	}
	entry, ok, err := journal.Load(delivery.OperationID)
	if err != nil || !ok || entry.State != transfer.StateReceived {
		t.Fatalf("crash was not recorded as received: %#v %v", entry, err)
	}
	restarted, err := transfer.NewApplicationConsumer(journal, inner)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := restarted.Accept(context.Background(), delivery)
	if err != nil || settled.State != transfer.StateApplied || !settled.Duplicate {
		t.Fatalf("restart reconciliation: %+v %v", settled, err)
	}
	got, err := adapter.readCredential(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(delivery.Payload) {
		t.Fatal("reconciled value differs from committed credential")
	}
	zero(got)
}

func TestApplicationConsumerCrashBeforeWriteStaysUncertain(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	target := testTarget()
	adapter := OpenCodeAuth{Path: filepath.Join(root, "auth.json")}
	inner := &TransferCommitter{Target: target, Adapter: adapter}
	delivery := transfer.Delivery{OperationID: "handoff-crash-before-write", DataKind: "api_key", Payload: []byte("synthetic-crash-secret"), Target: &target}
	first, err := transfer.NewApplicationConsumer(journal, crashBeforeApply{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(context.Background(), delivery); err == nil {
		t.Fatal("expected simulated pre-write crash")
	}
	restarted, err := transfer.NewApplicationConsumer(journal, inner)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := restarted.Accept(context.Background(), delivery)
	if err == nil || settled.State != transfer.StateReceived {
		t.Fatalf("pre-write crash incorrectly settled: %+v %v", settled, err)
	}
	if _, err := os.Stat(adapter.Path); !os.IsNotExist(err) {
		t.Fatalf("reconciliation blindly created the credential file: %v", err)
	}
}
