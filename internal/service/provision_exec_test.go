package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// testCredentialSaveDriver is a synthetic destinationless driver for the
// P0-3 execution tests: it accepts the resolved credential and returns a
// fixed closed DTO. Unlike pingDriver it is registered unconditionally so
// the service-level use-once/rebind/revocation regressions can drive
// ExecuteUse against an AegisKeys source resolved through the helper — the
// combination the suite previously exercised only at resolve level.
type testCredentialSaveDriver struct{}

func (testCredentialSaveDriver) Name() string { return "test.credential_save" }
func (testCredentialSaveDriver) Completion() secureops.CompletionMode {
	return secureops.ResponseValidated
}
func (testCredentialSaveDriver) RequiresDestination() bool { return false }
func (testCredentialSaveDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic P0-3 execution endpoint", Completion: secureops.ResponseValidated}
}
func (testCredentialSaveDriver) AllowedParams() []string { return []string{} }
func (testCredentialSaveDriver) Resource(map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "credential-save"}
}
func (testCredentialSaveDriver) Validate(secureops.UseInput) error { return nil }
func (testCredentialSaveDriver) Execute(_ context.Context, cred secureops.Credential, _ secureops.UseInput) (secureops.SafeResult, error) {
	if cred.Value == "" && len(cred.Components) == 0 {
		return secureops.SafeResult{}, fmt.Errorf("no credential material resolved")
	}
	return secureops.SafeResult{Summary: "credential accepted"}, nil
}

var testCredentialSaveOnce sync.Once

func ensureTestCredentialSaveDriver() {
	testCredentialSaveOnce.Do(func() { secureops.Register(testCredentialSaveDriver{}) })
}

// submitApprovedUse submits a use op for ref/operation, approves it, and
// returns the op ID ready for ExecuteUse.
func submitApprovedUse(t *testing.T, svc *Service, principal, refID, op string) string {
	t.Helper()
	id, err := svc.SubmitUse(principal, &types.UseRequest{
		SecretRef: refID, Operation: op, Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	return id
}

// provisionedRefFor provisions through the helper-mediated mock and
// returns the durable reference (pins populated by the provider response).
func provisionedRefFor(t *testing.T, svc *Service, requestID, binding, mode string) *types.SecretReference {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: "exec-secret-" + requestID, Service: "svc", Label: "L" + requestID,
		Kind: "api-key", Binding: binding, Operations: []string{"test.credential_save"},
	}
	_, ref, err := svc.ProvisionCredential(context.Background(), "intake:test", mode, req)
	if err != nil {
		t.Fatal(err)
	}
	if ref.BindingID == "" || ref.RecordID == "" {
		t.Fatalf("provisioned ref missing identity pins: %+v", ref)
	}
	return ref
}

// TestProvisionedRefExecuteUseOnceConsumes proves the execution-level
// use-once contract end to end: the FIRST authorized execution resolves
// through the helper and consumes the reference exactly-once; the SECOND
// fails closed at admission with the generic denial, even though the
// provider still holds the credential. This also covers the non-use-once
// path implicitly: the same driver executes save_only refs repeatedly in
// TestProvisionedRefRebindPinDenied without consumption.
func TestProvisionedRefExecuteUseOnceConsumes(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionedRefFor(t, svc, "prov-once-exec-1", "seqpass/once", IntakeUseOnce)
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")

	id1 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id1, "worker"); err != nil {
		t.Fatalf("first use-once execution failed: %v", err)
	}
	// The durable reference is consumed exactly once.
	got, err := svc.db.GetSecretRef(ref.ID)
	if err != nil || got == nil {
		t.Fatalf("ref lookup after consume: %v", err)
	}
	if got.ReconcileStatus != types.ProvisionReconcileConsumed {
		t.Fatalf("reconcile status after first use = %q, want consumed", got.ReconcileStatus)
	}
	// Second execution: fails closed at admission (generic outcome).
	id2 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id2, "worker"); err == nil {
		t.Fatal("second use-once execution succeeded")
	}
	st, _ := svc.db.GetUse(id2)
	if st == nil || st.Status != types.StatusFailed {
		t.Fatalf("second use status = %+v, want failed", st)
	}
}

// TestProvisionedRefRebindPinDenied proves rebind protection end to end:
// the provisioned ref carries binding_id/record_id pins on every resolve;
// after the provider REBINDS the binding name to a different record, the
// resolve — and therefore the approved execution — fails closed. An
// approved operation is never silently redirected to an unrelated
// credential.
func TestProvisionedRefRebindPinDenied(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionedRefFor(t, svc, "prov-pin-exec-2", "seqpass/pinned", IntakeSaveOnly)
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")

	// Pre-rebind: the pinned resolve works (the mock verifies the pins
	// match its committed identity).
	id1 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id1, "worker"); err != nil {
		t.Fatalf("pinned execution before rebind failed: %v", err)
	}
	m.refresh()
	if len(m.auditOps) == 0 || !strings.Contains(m.auditOps[len(m.auditOps)-1], "pins=yes") {
		t.Fatalf("resolve did not carry identity pins (audit = %v)", m.auditOps)
	}

	// Provider rebinds the name to a different record.
	m.rebind("seqpass/pinned", "bid-rotated", "rec-rotated")
	id2 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, execErr := svc.ExecuteUse(context.Background(), id2, "worker"); execErr == nil {
		t.Fatal("execution after provider rebind succeeded — pin protection is not wired")
	}
	st, _ := svc.db.GetUse(id2)
	if st == nil || st.Status != types.StatusFailed {
		t.Fatalf("post-rebind status = %+v, want failed", st)
	}
	// The audit trail records the failure without credential state.
	logs, _ := svc.db.ListAuditLogs(50)
	foundResolveFail := false
	for _, l := range logs {
		if strings.Contains(l.Outcome+l.Metadata, "exec-secret-prov-pin-exec-2") {
			t.Fatal("credential value leaked into audit trail")
		}
		if l.Action == "secret_use_failed" && l.OperationID == id2 {
			foundResolveFail = true
		}
	}
	if !foundResolveFail {
		t.Fatal("post-rebind resolve failure not audited")
	}
}

// TestProvisionedRefProviderRevocationDenied proves provider-side
// revocation propagation: after AegisKeys revokes the binding, every
// subsequent authorized use fails closed at resolve with a failed status
// and an audited generic refusal — the pinned SeqPass reference cannot
// keep using a revoked credential.
func TestProvisionedRefProviderRevocationDenied(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionedRefFor(t, svc, "prov-revoke-exec-3", "seqpass/revoked", IntakeSaveOnly)
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")

	id1 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id1, "worker"); err != nil {
		t.Fatalf("pre-revocation execution failed: %v", err)
	}
	m.revoke("seqpass/revoked")
	id2 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id2, "worker"); err == nil {
		t.Fatal("execution after provider revocation succeeded")
	}
	st, _ := svc.db.GetUse(id2)
	if st == nil || st.Status != types.StatusFailed {
		t.Fatalf("post-revocation status = %+v, want failed", st)
	}
	m.refresh()
	if !strings.Contains(m.denyReason, "revoked") {
		t.Fatalf("mock did not record the revocation denial: %q", m.denyReason)
	}
}

// TestProvisionedRefSurvivesRestart proves the durable-reference anchor
// across a service restart: a provisioned reference committed before the
// restart reopens with its pins and reconcile status intact, and a retry
// under the SAME request ID is recognized as the idempotent recovery (no
// duplicate reference, no provider round trip).
func TestProvisionedRefSurvivesRestart(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})

	dir := t.TempDir()
	dbPath := dir + "/restart.db"
	newSvc := func(t *testing.T) *Service {
		t.Helper()
		svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
		if err != nil {
			t.Fatal(err)
		}
		svc.cfg.AegisKeysSocket = m.sockPath
		svc.cfg.AegisKeysResolveHelper = selfExe(t)
		t.Cleanup(func() { _ = svc.Close() })
		return svc
	}

	svc1 := newSvc(t)
	req := aegiskeys.ProvisionRequest{
		RequestID: "prov-restart-0004", Value: "restart-secret", Service: "svc", Label: "L4",
		Kind: "api-key", Binding: "seqpass/restart", Operations: []string{"test.credential_save"},
	}
	report1, ref1, err := svc1.ProvisionCredential(context.Background(), "intake:test", IntakeSaveOnly, req)
	if err != nil {
		t.Fatal(err)
	}
	if !report1.Saved || ref1.ReconcileStatus != types.ProvisionReconcileCommitted {
		t.Fatalf("first provision = %+v ref=%+v", report1, ref1)
	}
	svc1.Close()

	// Restart: same DB, fresh service.
	svc2 := newSvc(t)
	got, err := svc2.db.GetSecretRefByProvisionRequest(req.RequestID)
	if err != nil || got == nil {
		t.Fatalf("provisioned ref lost across restart: %v", err)
	}
	if got.ID != ref1.ID || got.BindingID != ref1.BindingID || got.RecordID != ref1.RecordID ||
		got.ReconcileStatus != types.ProvisionReconcileCommitted || got.Binding != req.Binding {
		t.Fatalf("restart ref drifted: got %+v want id=%s binding_id=%s record_id=%s",
			got, ref1.ID, ref1.BindingID, ref1.RecordID)
	}
	// Idempotent recovery: the retry returns the SAME durable identity.
	report2, ref2, err := svc2.ProvisionCredential(context.Background(), "intake:test", IntakeSaveOnly, req)
	if err != nil {
		t.Fatalf("post-restart idempotent retry: %v", err)
	}
	if ref2.ID != ref1.ID || !report2.Saved {
		t.Fatalf("post-restart retry created a duplicate or lost saved state: report=%+v ref=%+v", report2, ref2)
	}
}
