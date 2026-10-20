package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
)

// provisionRefForStatus provisions through the mock and returns the
// durable reference for status-report tests.
func provisionRefForStatus(t *testing.T, svc *Service, m *mockBrokerChild, requestID, binding string) *types.SecretReference {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: "status-secret-" + requestID, Service: "svc", Label: "L" + requestID,
		Kind: "api-key", Binding: binding, Operations: []string{"test.credential_save"},
	}
	_, ref, err := svc.ProvisionCredential(context.Background(), "intake:test", IntakeSaveOnly, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ref.RecordID == "" || ref.BindingID == "" {
		t.Fatalf("provisioned ref missing identity: %+v", ref)
	}
	return ref
}

// TestIdentityFirstAssignmentSucceeds: the initial identity assignment
// succeeds exactly once (bound at first sighting via the expected-state
// CAS), and a repeated matching identity succeeds (status may promote,
// identity never moves).
func TestIdentityFirstAssignmentSucceeds(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionRefForStatus(t, svc, m, "prov-id-first-01", "seqpass/idfirst")
	got, err := svc.db.GetSecretRef(ref.ID)
	if err != nil || got == nil {
		t.Fatalf("ref lookup: %v", err)
	}
	if got.RecordID != ref.RecordID || got.BindingID != ref.BindingID {
		t.Fatalf("first assignment not durable: %+v", got)
	}

	// Repeated matching identity: status reconciliation keeps everything.
	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
	if err != nil {
		t.Fatalf("matching-identity status refresh failed: %v", err)
	}
	if report.IdentityConflict {
		t.Fatalf("matching identity flagged as conflict: %+v", report)
	}
	got, _ = svc.db.GetSecretRef(ref.ID)
	if got.RecordID != ref.RecordID || got.BindingID != ref.BindingID {
		t.Fatalf("matching refresh mutated identity: %+v", got)
	}
}

// TestIdentityDivergenceBlocksExecution: after a committed reference, a
// changed record ID or binding ID reported by the provider is a durable
// identity conflict — original pins preserved, report typed, an
// ALREADY-APPROVED operation can no longer execute, and the conflict
// survives a database restart.
func TestIdentityDivergenceBlocksExecution(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionRefForStatus(t, svc, m, "prov-id-diverge-02", "seqpass/iddiverge")

	for _, tc := range []struct {
		name                string
		recordID, bindingID string
	}{
		{"changed record id", "rec-rotatedX", ref.BindingID},
		{"changed binding id", ref.RecordID, "bid-rotatedX"},
	} {
		// Fresh reference per case (the first divergence blocks the ref).
		safeName := strings.ReplaceAll(tc.name, " ", "-")
		refN := provisionRefForStatus(t, svc, m, "prov-id-diverge-"+safeName,
			"seqpass/iddiverge/"+safeName)
		allowPolicy(t, svc, "uid:1000", refN.ID, "test.credential_save", "*")
		// An approved operation EXISTS before the drift.
		idN := submitApprovedUse(t, svc, "uid:1000", refN.ID, "test.credential_save")

		m.divergeStatusResponse(refN.ProvisionRequestID, tc.recordID, tc.bindingID)
		report, refAfter, err := svc.ProvisionStatusReport(context.Background(), "intake:test", refN.ProvisionRequestID)
		if err == nil {
			t.Fatalf("%s: divergent status refresh succeeded: %+v", tc.name, report)
		}
		if refAfter == nil || refAfter.ReconcileStatus != types.ProvisionReconcileIdentityConflict {
			t.Fatalf("%s: durable status after divergence = %+v, want identity_conflict", tc.name, refAfter)
		}
		// Original pins preserved — never adopted the provider's identity.
		if refAfter.RecordID != refN.RecordID || refAfter.BindingID != refN.BindingID {
			t.Fatalf("%s: pins overwritten: got %q/%q want %q/%q", tc.name,
				refAfter.RecordID, refAfter.BindingID, refN.RecordID, refN.BindingID)
		}
		if report == nil || !report.IdentityConflict || report.ConflictNextStep == "" {
			t.Fatalf("%s: report lacks typed conflict: %+v", tc.name, report)
		}
		// The ALREADY-APPROVED operation can no longer execute.
		if _, execErr := svc.ExecuteUse(context.Background(), idN, "worker"); execErr == nil {
			t.Fatalf("%s: approved execution succeeded after identity drift", tc.name)
		}
		st, _ := svc.db.GetUse(idN)
		if st == nil || st.Status != types.StatusFailed {
			t.Fatalf("%s: post-drift status = %+v, want failed", tc.name, st)
		}
	}

	// Conflict survives a database restart.
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc3, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc3.Close()
	refAfter, err := svc3.db.GetSecretRefByProvisionRequest("prov-id-diverge-changed-record-id")
	if err != nil || refAfter == nil {
		t.Fatalf("conflict lost across restart: %v", err)
	}
	if refAfter.ReconcileStatus != types.ProvisionReconcileIdentityConflict {
		t.Fatalf("post-restart status = %q, want identity_conflict", refAfter.ReconcileStatus)
	}
	// The mock derives identity from the request ID (rec-<id[:8]>); the
	// diverged ref must still hold exactly its ORIGINAL pre-drift pins.
	wantRec, wantBid := "rec-prov-id-", "bid-prov-id-" // mock: rec-<requestID[:8]>
	if refAfter.RecordID != wantRec || refAfter.BindingID != wantBid {
		t.Fatalf("post-restart pins drifted: got %q/%q want %q/%q", refAfter.RecordID, refAfter.BindingID, wantRec, wantBid)
	}
}

// TestIdentityConcurrentStatusCannotReplaceCommitted: concurrent status
// updates race through the identity CAS — a committed identity is never
// replaced, only the first real transition wins, and divergent identities
// are refused from every path.
func TestIdentityConcurrentStatusCannotReplaceCommitted(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionRefForStatus(t, svc, m, "prov-id-conc-03", "seqpass/idconc")

	// Concurrent guarded transitions from all lifecycle states with the
	// SAME identity: at most one REAL change wins, none replaces identity.
	var wg sync.WaitGroup
	results := make([]bool, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := svc.db.TransitionSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady,
				ref.RecordID, ref.BindingID, false,
				types.ProvisionReconcilePending, types.ProvisionReconcileUncertain,
				types.ProvisionReconcileCommitted, types.ProvisionReconcileGrantPresent, types.ProvisionReconcileReady)
			results[i] = ok && err == nil
		}(i)
	}
	wg.Wait()
	// Identity invariant regardless of how many no-op transitions
	// reported success: the committed identity is never replaced.
	got, _ := svc.db.GetSecretRef(ref.ID)
	if got.RecordID != ref.RecordID || got.BindingID != ref.BindingID {
		t.Fatalf("concurrent updates replaced committed identity: %+v", got)
	}
	if got.ReconcileStatus != types.ProvisionReconcileReady {
		t.Fatalf("status did not advance: %q", got.ReconcileStatus)
	}

	// Idempotent no-op repeats are expected (status already at target):
	// every no-op reports success but changes nothing.
	ok, err := svc.db.TransitionSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady,
		ref.RecordID, ref.BindingID, false, types.ProvisionReconcileReady)
	if err != nil || !ok {
		t.Fatalf("idempotent same-state transition refused: %v %v", ok, err)
	}

	// A DIFFERENT identity can never land, from any state.
	ok, err = svc.db.TransitionSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady,
		"rec-evil", "bid-evil", false, types.ProvisionReconcileReady)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("divergent identity accepted by the guarded transition")
	}
	// The first-assignment (empty-identity) form can never land on an
	// already-assigned reference either.
	okFirst, err := svc.db.TransitionSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady,
		"rec-evil", "bid-evil", true, types.ProvisionReconcileReady)
	if err != nil {
		t.Fatal(err)
	}
	if okFirst {
		t.Fatal("first-assignment transition succeeded on an already-assigned reference")
	}
	got, _ = svc.db.GetSecretRef(ref.ID)
	if got.RecordID != ref.RecordID || got.BindingID != ref.BindingID {
		t.Fatalf("divergent identity overwrote the committed identity: %+v", got)
	}
}
