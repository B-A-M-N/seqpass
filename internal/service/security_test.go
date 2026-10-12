package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

type credentialEchoDriver struct{}

func (credentialEchoDriver) Name() string                         { return "test.credential_echo" }
func (credentialEchoDriver) Completion() secureops.CompletionMode { return secureops.ResponseValidated }
func (credentialEchoDriver) RequiresDestination() bool            { return false }
func (credentialEchoDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic credential echo", Completion: secureops.ResponseValidated}
}
func (credentialEchoDriver) AllowedParams() []string { return []string{} }
func (credentialEchoDriver) Resource(map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "credential-echo"}
}
func (credentialEchoDriver) Validate(secureops.UseInput) error { return nil }
func (credentialEchoDriver) Execute(_ context.Context, cred secureops.Credential, _ secureops.UseInput) (secureops.SafeResult, error) {
	return secureops.SafeResult{Summary: "echo result", Data: map[string]interface{}{"description": cred.Value}}, nil
}

type credentialErrorDriver struct{}

func (credentialErrorDriver) Name() string { return "test.credential_error" }
func (credentialErrorDriver) Completion() secureops.CompletionMode {
	return secureops.ResponseValidated
}
func (credentialErrorDriver) RequiresDestination() bool { return false }
func (credentialErrorDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic credential error", Completion: secureops.ResponseValidated}
}
func (credentialErrorDriver) AllowedParams() []string { return []string{} }
func (credentialErrorDriver) Resource(map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "credential-error"}
}
func (credentialErrorDriver) Validate(secureops.UseInput) error { return nil }
func (credentialErrorDriver) Execute(_ context.Context, cred secureops.Credential, _ secureops.UseInput) (secureops.SafeResult, error) {
	return secureops.SafeResult{}, fmt.Errorf("upstream returned token %s", cred.Value)
}

var (
	credentialEchoOnce  sync.Once
	credentialErrorOnce sync.Once
)

func ensureCredentialEchoDriver() {
	credentialEchoOnce.Do(func() { secureops.Register(credentialEchoDriver{}) })
}

func ensureCredentialErrorDriver() {
	credentialErrorOnce.Do(func() { secureops.Register(credentialErrorDriver{}) })
}

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	svc, err := New(Config{DBPath: filepath.Join(dir, "test.db"), VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func seedRef(t *testing.T, svc *Service, id, binding string) {
	t.Helper()
	sr := &types.SecretReference{ID: id, Name: id, Owner: "test", Binding: binding}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
}

func allowPolicy(t *testing.T, svc *Service, principal, secretRef, op, dest string) {
	t.Helper()
	p := &types.Policy{
		Name:     "allow",
		Priority: 10,
		Enabled:  true,
		Revision: 1,
		Rules: []types.PolicyRule{{
			Principal:  principal,
			SecretRefs: []string{secretRef},
			Ops:        []string{op},
			DestIDs:    []string{dest},
			Resources:  []string{"*"},
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialEchoRejectedBeforeReceiptAndIPCResult(t *testing.T) {
	ensureCredentialEchoDriver()
	svc := testService(t)
	const credential = "ghp_primary-secret-123"
	seedRef(t, svc, "echo-secret", "")
	if err := svc.vault.Store("echo-secret", []byte(credential)); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "echo-secret", "test.credential_echo", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "echo-secret", Operation: "test.credential_echo", Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExecuteUse(context.Background(), id, "worker")
	if err == nil || strings.Contains(err.Error(), credential) {
		t.Fatalf("credential echo result was not safely rejected: result=%v err=%v", result, err)
	}
	if result != nil {
		t.Fatalf("model-visible result returned after disclosure rejection: %v", result)
	}
	stored, err := svc.DB().GetUse(id)
	if err != nil || stored.Status != types.StatusFailed {
		t.Fatalf("operation status = %v, err=%v; want failed", stored, err)
	}
	receipt, err := svc.DB().GetReceipt(id)
	if err != nil {
		t.Fatal(err)
	}
	if receipt != nil {
		t.Fatalf("disclosing result persisted in receipt: %+v", receipt)
	}
}

func TestCredentialBearingDriverErrorIsNeverReturnedOrAudited(t *testing.T) {
	ensureCredentialErrorDriver()
	svc := testService(t)
	const credential = "synthetic-error-token-987"
	seedRef(t, svc, "error-secret", "")
	if err := svc.vault.Store("error-secret", []byte(credential)); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "error-secret", "test.credential_error", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "error-secret", Operation: "test.credential_error", Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExecuteUse(context.Background(), id, "worker")
	if err == nil || strings.Contains(err.Error(), credential) || result != nil {
		t.Fatalf("credential-bearing driver error escaped: result=%v err=%v", result, err)
	}
	logs, err := svc.DB().ListAuditLogs(20)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(logs)
	if strings.Contains(string(raw), credential) {
		t.Fatal("credential-bearing driver error escaped into audit log")
	}
}

// Default-deny: no policy => denial.
func TestDefaultDeny(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "github/staging", "inference/staging")
	_, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "github/staging", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denial, got %v", err)
	}
}

// Unknown destination denied.
func TestUnknownDestinationDenied(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "transfer", "*")
	_, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "s1", DestinationID: "nope",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown destination") {
		t.Fatalf("expected unknown-destination denial, got %v", err)
	}
}

// Pending op cannot execute: claim requires authorized.
func TestPendingCannotExecute(t *testing.T) {
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
	// Status is requested (no auto-approve). Direct execution must fail at claim.
	if _, err := svc.ExecuteUse(context.Background(), id, "uid:1000"); err == nil {
		t.Fatal("pending op executed; expected claim denial")
	}
}

// Double claim: exactly one winner.
func TestAtomicClaimSingleWinner(t *testing.T) {
	svc := testService(t)
	dir := t.TempDir()
	_ = dir
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "transfer", "d1")
	d := &types.Destination{ID: "d1", Name: "d", Type: "file", Endpoint: "/tmp/x"}
	if err := svc.AddDestination(d); err != nil {
		t.Fatal(err)
	}
	tr := &types.TransferRequest{SecretRef: "s1", DestinationID: "d1"}
	id, err := svc.SubmitTransfer("uid:1000", tr)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := svc.DB().GetTransfer(id)
	if err := svc.DB().ApproveTransfer(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision); err != nil {
		t.Fatal(err)
	}
	stored, _ = svc.DB().GetTransfer(id)
	_, ok1, err := svc.DB().ClaimTransfer(id, stored.OpHash, stored.DestDigest, stored.Revision, "w1", time.Now().Add(time.Minute))
	if err != nil || !ok1 {
		t.Fatalf("first claim should win: %v %v", ok1, err)
	}
	_, ok2, err := svc.DB().ClaimTransfer(id, stored.OpHash, stored.DestDigest, stored.Revision, "w2", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("second claim won; exactly one execution required")
	}
}

// Expired op cannot execute.
func TestExpiredDenied(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params:    map[string]string{"repo": "o/r"},
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		// Evaluate denies expired at submit — also acceptable (fail closed).
		return
	}
	if _, err := svc.ExecuteUse(context.Background(), id, "uid:1000"); err == nil {
		t.Fatal("expired op executed")
	}
}

// Catalog is scoped: unknown principal sees nothing; other principals' refs hidden.
func TestCatalogScoped(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "discover", "*")
	got, err := svc.Catalog("uid:1000")
	if err != nil || len(got) != 1 {
		t.Fatalf("expected 1 ref, got %v %v", len(got), err)
	}
	got, _ = svc.Catalog("uid:9999")
	if len(got) != 0 {
		t.Fatal("other principal sees refs")
	}
	got, _ = svc.Catalog("")
	if len(got) != 0 {
		t.Fatal("empty principal sees refs")
	}
}

// Status is owner-only.
func TestStatusOwnerOnly(t *testing.T) {
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
	if _, err := svc.Status("uid:9999", "use", id); err == nil {
		t.Fatal("other principal read status")
	}
}

// Unsupported vault type fails closed.
func TestVaultFailClosed(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{DBPath: filepath.Join(dir, "x.db"), VaultType: "file"})
	if err == nil {
		t.Fatal("plaintext file vault should be rejected")
	}
	_, err = New(Config{DBPath: filepath.Join(dir, "y.db"), VaultType: "openbao"})
	if err == nil {
		t.Fatal("unimplemented openbao should be rejected")
	}
}

// Approval survives broker restart (durable in SQLite).
func TestApprovalDurableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "r.db")
	svc, _ := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := svc.DB().GetUse(id)
	_ = svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision)
	_ = svc.Close()

	svc2, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	ur, _ := svc2.DB().GetUse(id)
	if ur.Status != types.StatusAuthorized {
		t.Fatalf("approval lost across restart: %s", ur.Status)
	}
}

// SC-05: explicit preauthorization. A NoApproval rule authorizes at submit
// (consumed by the worker through the normal claim path); without it, human
// approval is required. Destination AllowedOps restricts when non-empty.
func TestPreauthorizedMode(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	p := &types.Policy{
		Name: "preauth", Priority: 10, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"s1"},
			Ops: []string{"github.get_repo"}, DestIDs: []string{"*"},
			Resources: []string{"*"}, NoApproval: true,
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ur, _ := svc.DB().GetUse(id)
	if ur.Status != types.StatusAuthorized {
		t.Fatalf("preauthorized op status=%s, want authorized", ur.Status)
	}
}

func TestDestinationAllowedOpsEnforced(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "transfer", "d1")
	d := &types.Destination{ID: "d1", Name: "d", Type: "recipient-socket",
		Endpoint: "/tmp/x.sock", AllowedOps: []string{"other"}}
	uid := uint32(1000)
	d.ExpectedUID = &uid
	if err := svc.AddDestination(d); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "s1", DestinationID: "d1",
	}); err == nil {
		t.Fatal("transfer allowed despite destination AllowedOps exclusion (SC-05)")
	}
}

// SC-02: approval is a compare-and-swap on the reviewed artifact. A wrong
// revision, tampered envelope, or stale epoch cannot be approved.
func TestApprovalCAS(t *testing.T) {
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
	stored, _ := svc.DB().GetUse(id)
	if err := svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision+99); err == nil {
		t.Fatal("approval with wrong revision succeeded (SC-02)")
	}
	if err := svc.DB().ApproveUse(id, "op", "tampered", stored.AuthEpoch, stored.Revision); err == nil {
		t.Fatal("approval with wrong digest succeeded (SC-02)")
	}
	if err := svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch+99, stored.Revision); err == nil {
		t.Fatal("approval with stale epoch succeeded (SC-02)")
	}
	if err := svc.ApproveUse(id, "op", -1); err != nil {
		t.Fatalf("valid approval failed: %v", err)
	}
}

// SC-03: the dispatch barrier is atomic with revocation. A claim admitted
// before revocation cannot cross dispatch after it.
func TestDispatchBarrierAtomic(t *testing.T) {
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
	stored, _ := svc.DB().GetUse(id)
	if err := svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision); err != nil {
		t.Fatal(err)
	}
	stored, _ = svc.DB().GetUse(id)
	attempt, claimed, err := svc.DB().ClaimUse(id, stored.OpHash, stored.DestDigest, stored.Revision, "w", time.Now().Add(time.Minute))
	if err != nil || !claimed {
		t.Fatalf("claim failed: %v %v", claimed, err)
	}
	// Revoke after claim, before dispatch: barrier must refuse.
	if err := svc.DB().SetPolicyEnabled("allow", false); err != nil {
		// allowPolicy names it "allow"? fetch actual ID instead.
		pols, _ := svc.DB().ListPolicies()
		if len(pols) == 0 {
			t.Fatal("no policies")
		}
		if err := svc.DB().SetPolicyEnabled(pols[0].ID, false); err != nil {
			t.Fatal(err)
		}
	}
	stored, _ = svc.DB().GetUse(id)
	if err := svc.DB().BeginDispatch("use", id, attempt, stored.OpHash, stored.DestDigest, "w", time.Now()); err == nil {
		t.Fatal("dispatch crossed a committed revocation (SC-03)")
	}
}

// SC-07: startup reconciliation is stage-aware. Pre-dispatch orphans never
// caused a side effect (failed); dispatching orphans may have (uncertain).
func TestReconcileStageAware(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
	mk := func() string {
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
		if _, ok, err := svc.DB().ClaimUse(id, st.OpHash, st.DestDigest, st.Revision, "w", time.Now().Add(time.Minute)); err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return id
	}
	preID := mk()
	dispID := mk()
	// Cross the dispatch barrier on the second op, then simulate a crash
	// before any external I/O or finalization.
	st, _ := svc.DB().GetUse(dispID)
	// Retrieve the winning attempt for this op via a fresh claim attempt
	// listing: claim already won, so re-derive by dispatching with the
	// recorded attempt. The claim above did not return it here; fetch the
	// open attempt from the DB through a second approved op is overkill:
	// instead drive BeginDispatch through ExecuteUse's real path is async.
	// Direct approach: query execution_attempts for the open attempt.
	attempt, _, err := svc.DB().OpenAttempt(dispID)
	if err != nil || attempt == "" {
		t.Fatalf("open attempt: %v %q", err, attempt)
	}
	if err := svc.DB().BeginDispatch("use", dispID, attempt, st.OpHash, st.DestDigest, "w", time.Now()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	failed, uncertain, err := svc.DB().ReconcileExecuting()
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 || uncertain != 1 {
		t.Fatalf("stage-aware reconcile wrong: failed=%d uncertain=%d", failed, uncertain)
	}
	if ur, _ := svc.DB().GetUse(preID); ur.Status != types.StatusFailed {
		t.Fatalf("pre-dispatch orphan status=%s, want failed", ur.Status)
	}
	if ur, _ := svc.DB().GetUse(dispID); ur.Status != types.StatusUncertain {
		t.Fatalf("dispatching orphan status=%s, want uncertain", ur.Status)
	}
}

// C10: exact resource binding. A grant for one repo must not open another
// repo even with the same credential and driver.
func TestResourceBindingExact(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	p := &types.Policy{
		Name: "repo-scoped", Priority: 10, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"s1"},
			Ops: []string{"github.get_repo"}, DestIDs: []string{"*"},
			Resources: []string{"github.repository:o/r"},
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	}); err != nil {
		t.Fatalf("in-scope repo denied: %v", err)
	}
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/other"},
	}); err == nil {
		t.Fatal("out-of-scope repo allowed under one-repo grant (C10)")
	}
}

// C10: a rule with no resources must not silently grant resource-bearing ops.
func TestResourceBindingNoSilentGrant(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "s1", "")
	p := &types.Policy{
		Name: "no-resource", Priority: 10, Enabled: true, Revision: 1,
		Rules: []types.PolicyRule{{
			Principal: "uid:1000", SecretRefs: []string{"s1"},
			Ops: []string{"github.get_repo"}, DestIDs: []string{"*"},
		}},
	}
	if err := svc.DB().CreatePolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "s1", Operation: "github.get_repo",
		Params: map[string]string{"repo": "o/r"},
	}); err == nil {
		t.Fatal("resource-bearing op allowed by resourceless rule (C10)")
	}
}

// C14: no silent vault default. Empty vault type is rejected, never an
// ephemeral store; memory-test is explicit only.
func TestEmptyVaultRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(Config{DBPath: filepath.Join(dir, "x.db"), VaultType: ""}); err == nil {
		t.Fatal("empty vault type silently accepted")
	}
}

// SC-01: the approval envelope is injective. The audit's counterexample
// ({"a":"b;c=d"} vs {"a":"b","c":"d"}) must hash differently, and the
// transfer component selector must alter the digest.
func TestOpHashInjective(t *testing.T) {
	a := metadata.UseOpHash("u", "s", "github.get_repo", "", map[string]string{"a": "b;c=d"}, types.ResourceDescriptor{Kind: "github.repository", Identifier: "o/r"})
	b := metadata.UseOpHash("u", "s", "github.get_repo", "", map[string]string{"a": "b", "c": "d"}, types.ResourceDescriptor{Kind: "github.repository", Identifier: "o/r"})
	if a == b {
		t.Fatal("distinct param maps share an approval hash (SC-01)")
	}
	c := metadata.UseOpHash("u", "s", "github.get_repo", "", map[string]string{"a": "b"}, types.ResourceDescriptor{Kind: "github.repository", Identifier: "o/r"})
	d := metadata.UseOpHash("u", "s", "github.get_repo", "", map[string]string{"a": "b"}, types.ResourceDescriptor{Kind: "github.repository", Identifier: "o/other"})
	if c == d {
		t.Fatal("distinct resources share an approval hash (SC-01)")
	}
	t1 := metadata.TransferOpHash("u", "s", "d", "")
	t2 := metadata.TransferOpHash("u", "s", "d", "component:extra")
	if t1 == t2 {
		t.Fatal("component selector change leaves approval hash unchanged (SC-01)")
	}
}

var _ = metadata.CanonicalOpHash
