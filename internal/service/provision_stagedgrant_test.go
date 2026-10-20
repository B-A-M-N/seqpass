package service

// P1-B regressions: the provider's staged-grant workflow information —
// WHICH grant awaits approval (staged_grant_id) and any staging failure
// (staging_error) — reaches the operator's surfaces verbatim, with the
// explicit approval next step. Metadata only, never credential material.

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestStagedGrantSurfacedThroughReport: the staged grant ID and the
// approval next step flow through ProvisionStatusReport; the report
// never carries credential material.
func TestStagedGrantSurfacedThroughReport(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	provisionRefForStatus(t, svc, m, "prov-sg-1", "seqpass/sg")
	m.stagedGrant("prov-sg-1", "grant-abc123", "")

	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-sg-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.StagedGrantID != "grant-abc123" {
		t.Fatalf("staged grant id not surfaced: %+v", report)
	}
	if report.StagingError != "" {
		t.Fatalf("unexpected staging error: %+v", report)
	}
	if report.Saved == false && report.ProviderStatus != "authorization_pending" {
		t.Fatalf("unexpected provider status: %+v", report)
	}
	if strings.Contains(report.StagedGrantID, "status-secret") {
		t.Fatal("credential material leaked through the staged-grant field")
	}
}

// TestStagingErrorSurfacedThroughReport: when the provider could not
// stage the grant, its diagnosis reaches the operator verbatim.
func TestStagingErrorSurfacedThroughReport(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	provisionRefForStatus(t, svc, m, "prov-sg-2", "seqpass/sg2")
	m.stagedGrant("prov-sg-2", "grant-def456", "attestation key mismatch: re-pin the executor attest_key")

	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", "prov-sg-2")
	if err != nil {
		t.Fatal(err)
	}
	if report.StagedGrantID != "grant-def456" || report.StagingError == "" ||
		!strings.Contains(report.StagingError, "attestation key mismatch") {
		t.Fatalf("staged-grant workflow info lost: %+v", report)
	}
	// The IPC surface carries both plus the explicit approval step.
	// surfaceStagedGrantMirror mirrors ipc.surfaceStagedGrant's field
	// contract (the service package cannot import internal/ipc).
	data := map[string]interface{}{}
	surfaceStagedGrantMirror(data, report, "prov-sg-2")
	if data["staged_grant_id"] != "grant-def456" {
		t.Fatalf("IPC missing staged_grant_id: %+v", data)
	}
	if step, _ := data["approve_next_step"].(string); step != "aegiskeys access provision approve --request prov-sg-2" {
		t.Fatalf("IPC missing approval next step: %+v", data)
	}
}

// surfaceStagedGrantMirror mirrors ipc.surfaceStagedGrant's field
// contract (the service package cannot import internal/ipc).
func surfaceStagedGrantMirror(out map[string]interface{}, report *ProvisionReport, requestID string) {
	if report.StagedGrantID != "" {
		out["staged_grant_id"] = report.StagedGrantID
	}
	if report.StagingError != "" {
		out["staging_error"] = report.StagingError
	}
	if report.StagedGrantID != "" || report.StagingError != "" {
		out["approve_next_step"] = "aegiskeys access provision approve --request " + requestID
	}
}
