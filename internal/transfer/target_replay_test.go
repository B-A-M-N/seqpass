package transfer

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestApplicationConsumerReplayBindsTargetIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewOperationJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	var calls int64
	committer := &CallbackCommitter{Fn: func(_ context.Context, d Delivery) (Committed, error) {
		atomic.AddInt64(&calls, 1)
		return Committed{Applied: true, Digest: PayloadDigest(d.Payload)}, nil
	}}
	consumer, err := NewApplicationConsumer(journal, committer)
	if err != nil {
		t.Fatal(err)
	}
	target := &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "ref-1", SourceRevision: 1}
	d := Delivery{OperationID: "target-replay", DataKind: "api_key", Payload: []byte("synthetic"), Target: target}
	if _, err := consumer.Accept(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	other := *target
	other.Account = "attacker"
	d.Target = &other
	if _, err := consumer.Accept(context.Background(), d); err != ErrOperationConflict {
		t.Fatalf("target substitution error=%v", err)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("committer called %d times", got)
	}
}

func TestApplicationConsumerSerializesConcurrentClaimsAcrossInstances(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "journal")
	j1, err := NewOperationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	j2, err := NewOperationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	var calls int64
	committer := &CallbackCommitter{Fn: func(_ context.Context, d Delivery) (Committed, error) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(20 * time.Millisecond)
		return Committed{Applied: true, Digest: PayloadDigest(d.Payload)}, nil
	}}
	c1, _ := NewApplicationConsumer(j1, committer)
	c2, _ := NewApplicationConsumer(j2, committer)
	target := &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "ref-1", SourceRevision: 1}
	d := Delivery{OperationID: "concurrent-handoff", DataKind: "api_key", Payload: []byte("synthetic"), Target: target}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, consumer := range []*ApplicationConsumer{c1, c2} {
		go func(c *ApplicationConsumer) { <-start; _, err := c.Accept(context.Background(), d); results <- err }(consumer)
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("concurrent duplicate commits=%d, want 1", got)
	}
}
