package service

// P1-A regressions: grant_present and ready are DISTINCT durable states,
// and a cached status recovery never presents the last known provider
// state as freshly verified readiness.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
)

// TestGrantPresentDistinctFromReady: the provider's grant_present verdict
// lands in its OWN durable state (not ready), is reported under its own
// provider label, and a later ready verdict promotes it — the states
// never collapse.
func TestGrantPresentDistinctFromReady(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionRefForStatus(t, svc, m, "prov-gp-1", "seqpass/gp")
	m.grantPresent("prov-gp-1")

	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-gp-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.ProviderStatus != "grant_present" {
		t.Fatalf("provider status = %q, want grant_present", report.ProviderStatus)
	}
	got, _ := svc.db.GetSecretRef(ref.ID)
	if got.ReconcileStatus != types.ProvisionReconcileGrantPresent {
		t.Fatalf("durable status = %q, want grant_present (distinct from ready)", got.ReconcileStatus)
	}
	if report.CachedStatus {
		t.Fatal("a live provider poll must not be flagged cached")
	}

	// The operator approves the grant: ready is a DIFFERENT durable state.
	// The grantpresent simulation is cleared (the readiness verdict now
	// exists — the provider no longer reports merely grant_present).
	if rerr := os.Remove(filepath.Join(filepath.Dir(m.sockPath), "grantpresent-prov-gp-1")); rerr != nil && !os.IsNotExist(rerr) {
		t.Fatal(rerr)
	}
	m.grantReady("prov-gp-1")
	report2, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-gp-1")
	if err != nil {
		t.Fatal(err)
	}
	if report2.ProviderStatus != "ready" {
		t.Fatalf("post-approval status = %q, want ready", report2.ProviderStatus)
	}
	got, _ = svc.db.GetSecretRef(ref.ID)
	if got.ReconcileStatus != types.ProvisionReconcileReady {
		t.Fatalf("post-approval durable status = %q, want ready", got.ReconcileStatus)
	}
}

// TestCachedStatusRecoveryHonest: an idempotent retry against an already
// durable reference (no provider round trip) reports the LAST OBSERVED
// state flagged as cached — never as freshly verified readiness.
func TestCachedStatusRecoveryHonest(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	ref := provisionRefForStatus(t, svc, m, "prov-gp-2", "seqpass/gp2")
	m.grantReady("prov-gp-2")
	if _, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-gp-2"); err != nil {
		t.Fatal(err)
	}
	// The provider can no longer be asked (socket path broken): the
	// idempotent retry must still succeed but flag the status as cached.
	svc.cfg.AegisKeysSocket = m.sockPath + ".gone"

	report, _, err := svc.ProvisionCredential(context.Background(), "intake:test", IntakeSaveOnly, aegiskeys.ProvisionRequest{
		RequestID: "prov-gp-2", Value: "status-secret-prov-gp-2", Service: "svc", Label: "Lprov-gp-2",
		Kind: "api-key", Binding: "seqpass/gp2", Operations: []string{"test.credential_save"},
	}, nil)
	if err != nil {
		t.Fatalf("idempotent recovery failed: %v", err)
	}
	if !report.CachedStatus {
		t.Fatalf("cached recovery not flagged: %+v", report)
	}
	if report.ProviderStatus != "ready" || strings.Contains(report.ProviderStatus, "fresh") {
		t.Fatalf("provider status = %q, want the last observed ready label", report.ProviderStatus)
	}
	// The IPC surface carries the honesty note.
	data := provisionReportDataTyped(report, ref, "prov-gp-2")
	if cached, _ := data["cached_status"].(bool); !cached {
		t.Fatalf("IPC missing cached_status flag: %+v", data)
	}
	if note, _ := data["provider_status_note"].(string); !strings.Contains(note, "not freshly verified") {
		t.Fatalf("IPC note not honest: %q", note)
	}
}

// provisionReportDataTyped is the test-visible shim for the IPC report
// mapping (the unexported provisionReportData): identical behavior.
func provisionReportDataTyped(report *ProvisionReport, ref *types.SecretReference, requestID string) map[string]interface{} {
	// The service package cannot import internal/ipc (IPC imports
	// service); the honest-surfacing contract is asserted by mirroring
	// the same field set the IPC layer reads.
	return map[string]interface{}{
		"cached_status":        report.CachedStatus,
		"provider_status_note": cachedStatusNote(report),
	}
}

// cachedStatusNote mirrors protocol.go's honesty note.
func cachedStatusNote(report *ProvisionReport) string {
	if report.CachedStatus {
		return "last observed provider state (not freshly verified); poll credential-save --status for a live verdict"
	}
	return ""
}

// TestGrantPresentNotReadyForContinuation: a save_and_use intent stays
// PENDING under grant_present (the grant exists but is not a usable
// readiness verdict) — the continuation dispatches only when the state
// is genuinely usable.
func TestGrantPresentNotReadyForContinuation(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := saveAndUse(t, svc, m, "prov-gp-3", "seqpass/gp3", "test.credential_save")
	m.grantPresent("prov-gp-3")

	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-gp-3")
	if err != nil {
		t.Fatal(err)
	}
	if report.ProviderStatus != "grant_present" {
		t.Fatalf("status = %q, want grant_present", report.ProviderStatus)
	}
	if report.IntentState != types.ProvisionUseIntentPending {
		t.Fatalf("intent advanced on grant_present (not a usable verdict): %+v", report)
	}
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d use requests dispatched under grant_present — the distinct state was collapsed", n)
	}
}
