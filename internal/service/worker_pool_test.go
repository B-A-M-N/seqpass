package service

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// blockInflight/blockMax measure REAL execution overlap inside the
// driver's external-I/O window — not goroutine creation. The pool is
// proven concurrent only when two operations are inside Execute at the
// same instant.
var (
	blockInflight int32
	blockMax      int32
	blockOnce     sync.Once
)

type blockingDriver struct{}

func (blockingDriver) Name() string { return "test.block" }
func (blockingDriver) Completion() secureops.CompletionMode {
	return secureops.ResponseValidated
}
func (blockingDriver) RequiresDestination() bool { return false }
func (blockingDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic overlap probe", Completion: secureops.ResponseValidated}
}
func (blockingDriver) AllowedParams() []string { return []string{} }
func (blockingDriver) Resource(map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "block"}
}
func (blockingDriver) Validate(secureops.UseInput) error { return nil }
func (blockingDriver) Execute(context.Context, secureops.Credential, secureops.UseInput) (secureops.SafeResult, error) {
	cur := atomic.AddInt32(&blockInflight, 1)
	for {
		m := atomic.LoadInt32(&blockMax)
		if cur <= m || atomic.CompareAndSwapInt32(&blockMax, m, cur) {
			break
		}
	}
	time.Sleep(200 * time.Millisecond)
	atomic.AddInt32(&blockInflight, -1)
	return secureops.SafeResult{Summary: "blocked ok", Data: map[string]interface{}{"ok": true}}, nil
}

func ensureBlockingDriver(t *testing.T) {
	t.Helper()
	blockOnce.Do(func() {
		secureops.Register(blockingDriver{})
	})
}

// The bounded pool executes independent operations concurrently: with 8
// authorized ops and 4 workers, at least two must overlap inside Execute
// (sequential execution could never do that), no more than 4 ever do
// (the configured bound), and every operation still completes through
// its own independent claim with its own result.
func TestWorkerPoolOverlapsIndependentOps(t *testing.T) {
	ensureBlockingDriver(t)
	atomic.StoreInt32(&blockInflight, 0)
	atomic.StoreInt32(&blockMax, 0)
	dir := t.TempDir()
	svc, err := New(Config{DBPath: filepath.Join(dir, "test.db"), VaultType: "memory-test", MaxConcurrentOps: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	sr := &types.SecretReference{ID: "blk", Name: "blk", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("blk", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "blk", "test.block", "*")
	const n = 8
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
			SecretRef: "blk", Operation: "test.block", Params: map[string]string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.ApproveUse(id, "operator", -1); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	start := time.Now()
	svc.runWorkerOnce(context.Background())
	elapsed := time.Since(start)
	for _, id := range ids {
		ur, _ := svc.DB().GetUse(id)
		if ur.Status != types.StatusCompleted {
			t.Fatalf("op %s status = %s, want completed", id, ur.Status)
		}
	}
	max := atomic.LoadInt32(&blockMax)
	t.Logf("8 ops in %v with 4 workers (sequential floor 1.6s); peak overlap %d", elapsed, max)
	if max < 2 {
		t.Fatalf("no actual execution overlap: peak in-flight = %d", max)
	}
	if max > 4 {
		t.Fatalf("pool bound exceeded: peak in-flight = %d, want <= 4", max)
	}
	if atomic.LoadInt32(&blockInflight) != 0 {
		t.Fatal("in-flight counter leaked")
	}
}
