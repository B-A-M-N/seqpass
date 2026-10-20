package service

// P0-C regressions: the two use-once semantics are genuinely distinct.
//
//   - transient_once: the credential exists ONLY in the broker's
//     in-memory ephemeral spool (the protected handoff boundary); ONE
//     approved operation consumes it at the dispatch barrier; NO
//     durable AegisKeys credential is created; unrecoverable after
//     expiry or restart.
//   - use_once (persisted single-use): AegisKeys deliberately retains
//     the encrypted credential; SeqPass limits its use to one authorized
//     execution. Covered unchanged by the provision_exec tests
//     (TestProvisionedRefExecuteUseOnceConsumes and the provision flow
//     tests) — the persisted behavior's coverage is intentionally
//     preserved.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
)

// transientRef provisions a transient_once credential and returns the
// durable metadata-only reference.
func transientRef(t *testing.T, svc *Service, requestID, binding string) (*ProvisionReport, *types.SecretReference) {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: "transient-secret-" + requestID, Service: "svc", Label: "L" + requestID,
		Kind: "api-key", Binding: binding, Operations: []string{"test.credential_save"},
	}
	report, ref, err := svc.ProvisionCredential(context.Background(), "intake:test", IntakeTransientOnce, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	return report, ref
}

// TestTransientOnceNeverPersistsCredential: no provider round trip, no
// provider identity, durable row is metadata only.
func TestTransientOnceNeverPersistsCredential(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	report, ref := transientRef(t, svc, "prov-transient-1", "seqpass/transient/1")
	if report.Saved {
		t.Fatalf("transient intake must not report a durable save: %+v", report)
	}
	if report.ProviderStatus != "transient_staged" || report.StagedUntil.IsZero() {
		t.Fatalf("transient report incomplete: %+v", report)
	}
	if ref.RecordID != "" || ref.BindingID != "" {
		t.Fatalf("transient ref carries provider identity pins: %+v", ref)
	}
	if ref.ReconcileStatus != types.ProvisionReconcileTransient || !ref.UseOnce {
		t.Fatalf("ref not marked transient single-use: %+v", ref)
	}
	// The mock never received a provision: the request ID has no v3
	// state at the provider — prove no durable credential exists there.
	if _, err := svc.provisionStatus(context.Background(), "prov-transient-1"); err == nil {
		t.Fatal("provider knows the transient request — a durable credential was created")
	}
}

// TestTransientOnceSingleApprovedUseConsumes: one approved operation
// consumes the staged bytes at the dispatch barrier; nothing remains.
func TestTransientOnceSingleApprovedUseConsumes(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := transientRef(t, svc, "prov-transient-2", "seqpass/transient/2")
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")

	id := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id, "worker"); err != nil {
		t.Fatalf("first transient use failed: %v", err)
	}
	// The dispatch barrier destroyed the staged bytes.
	key := transientPayloadKey(ref.ID)
	if svc.eph.HasBacking(key) || svc.eph.Live(key) {
		t.Fatal("transient payload outlived its authorized dispatch")
	}
	// The durable reference is consumed exactly once.
	got, _ := svc.db.GetSecretRef(ref.ID)
	if got == nil || got.ReconcileStatus != types.ProvisionReconcileConsumed {
		t.Fatalf("transient ref status = %+v, want consumed", got)
	}
	// A second operation cannot even be submitted (lifecycle gate).
	if _, serr := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: ref.ID, Operation: "test.credential_save", Params: map[string]string{},
	}); serr == nil {
		t.Fatal("second use request created against a consumed transient credential")
	}
}

// TestTransientOnceUnrecoverableAfterRestart: the payload lives only in
// broker memory — a restart leaves the reference permanently unusable
// (metadata survives; the credential does not).
func TestTransientOnceUnrecoverableAfterRestart(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := transientRef(t, svc, "prov-transient-3", "seqpass/transient/3")
	dbPath := svc.cfg.DBPath
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	// The durable metadata row survives…
	got, _ := svc2.db.GetSecretRef(ref.ID)
	if got == nil || got.ReconcileStatus != types.ProvisionReconcileTransient {
		t.Fatalf("transient metadata lost across restart: %+v", got)
	}
	// …but the credential is gone: submission passes (metadata-only
	// gates), the payload reservation fails closed generically.
	allowPolicy(t, svc2, "uid:1000", ref.ID, "test.credential_save", "*")
	id := submitApprovedUse(t, svc2, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc2.ExecuteUse(context.Background(), id, "worker"); err == nil {
		t.Fatal("transient credential resolved after restart — it persisted somewhere")
	}
	st, _ := svc2.db.GetUse(id)
	if st == nil || st.Status != types.StatusFailed {
		t.Fatalf("post-restart use status = %+v, want failed", st)
	}
	if svc2.eph.HasBacking(transientPayloadKey(ref.ID)) {
		t.Fatal("transient payload exists after restart")
	}
}

// TestTransientOnceExpiryUnrecoverable: past its lifetime the staged
// bytes are gone (zeroed) and the reference is dead.
func TestTransientOnceExpiryUnrecoverable(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	prev := transientOnceTTL
	transientOnceTTL = 40 * time.Millisecond
	defer func() { transientOnceTTL = prev }()
	_, ref := transientRef(t, svc, "prov-transient-4", "seqpass/transient/4")
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")
	time.Sleep(60 * time.Millisecond)

	id := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id, "worker"); err == nil {
		t.Fatal("expired transient credential resolved")
	}
	if svc.eph.HasBacking(transientPayloadKey(ref.ID)) {
		t.Fatal("expired transient payload still has backing bytes")
	}
}

// TestTransientOnceAtMostOnceDispatch: a second APPROVED operation can
// never dispatch — the first dispatch consumes both the payload and the
// reference. At-most-once dispatch, explicit failure for the loser.
func TestTransientOnceAtMostOnceDispatch(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := transientRef(t, svc, "prov-transient-5", "seqpass/transient/5")
	allowPolicy(t, svc, "uid:1000", ref.ID, "test.credential_save", "*")

	// Two approved operations exist BEFORE either dispatches.
	// submitApprovedUse submits AND approves each.
	id1 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	id2 := submitApprovedUse(t, svc, "uid:1000", ref.ID, "test.credential_save")
	if _, err := svc.ExecuteUse(context.Background(), id1, "worker"); err != nil {
		t.Fatalf("first transient use failed: %v", err)
	}
	if _, err := svc.ExecuteUse(context.Background(), id2, "worker"); err == nil {
		t.Fatal("second approved op dispatched a consumed transient credential")
	}
	st2, _ := svc.db.GetUse(id2)
	if st2 == nil || st2.Status != types.StatusFailed {
		t.Fatalf("loser status = %+v, want failed", st2)
	}
	// Exactly one execution ever happened (the receipt proves it).
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("%d use requests exist, want exactly 2 (one executed, one failed closed)", n)
	}
}
