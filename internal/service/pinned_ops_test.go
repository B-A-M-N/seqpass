package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

const pinnedMarker = "SECRET-PINNED-e2e-8811aa2bb3cc"

// seedPinnedDest registers a pinned destination directly with the service
// (admin Go API, as the admin IPC surface does) plus the policy that lets
// uid:1000 run op against it.
func seedPinnedDest(t *testing.T, svc *Service, id, destType, endpoint, op, secretRef string) {
	t.Helper()
	dest := &types.Destination{ID: id, Name: id, Type: destType, Endpoint: endpoint}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatalf("AddDestination(%s): %v", destType, err)
	}
	seedRef(t, svc, secretRef, "")
	allowPolicy(t, svc, "uid:1000", secretRef, op, id)
}

// A full credentialed HTTP use through the real broker path: the agent
// gets the projected result and never the credential, in the result, the
// receipt, or the audit trail.
func TestPinnedHTTPUseEndToEnd(t *testing.T) {
	if _, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Skip("sandbox denies local TCP listeners")
	}
	const marker = pinnedMarker + "-http"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/whoami" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+marker {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account":"staging-bot","scopes":["repo:read"],"echo":"` + r.Header.Get("Authorization") + `"}`))
	}))
	defer srv.Close()

	svc := testService(t)
	seedPinnedDest(t, svc, "d-http", "http-pinned", srv.URL, "http.request", "staging-api")
	if err := svc.vault.Store("staging-api", []byte(marker)); err != nil {
		t.Fatal(err)
	}

	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "staging-api", Operation: "http.request", Target: "d-http",
		Params: map[string]string{"path": "/v1/whoami"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExecuteUse(context.Background(), id, "worker")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), marker) {
		t.Fatal("credential reached the agent-visible result")
	}
	if result["summary"] != "http request completed (status 200)" {
		t.Fatalf("summary = %v", result["summary"])
	}
	data := result["data"].(map[string]interface{})
	if data["account"] != "staging-bot" {
		t.Fatalf("projection lost account: %v", data)
	}
	if _, has := data["echo"]; has {
		t.Fatal("reflected credential field survived projection")
	}

	// The audit trail carries no credential either.
	logs, err := svc.DB().ListAuditLogs(50)
	if err != nil {
		t.Fatal(err)
	}
	lob, _ := json.Marshal(logs)
	if strings.Contains(string(lob), marker) {
		t.Fatal("credential reached the audit trail")
	}
}

// The same flow against a pinned executable: the credential reaches the
// child on stdin only; the operation completes with the honest
// inconclusive verification, because a generic process adapter cannot
// independently observe the external effect.
func TestPinnedProcessUseEndToEnd(t *testing.T) {
	const marker = pinnedMarker + "-proc"
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(tmp, "received.txt")
	scriptPath := filepath.Join(tmp, "pinned-consumer")
	script := "#!/bin/sh\n" +
		"cat > " + got + "\n" +
		"echo '{\"written\":true}'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	svc := testService(t)
	seedPinnedDest(t, svc, "d-proc", "process-pinned", scriptPath, "process.run", "cli-token")
	if err := svc.vault.Store("cli-token", []byte(marker)); err != nil {
		t.Fatal(err)
	}

	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "cli-token", Operation: "process.run", Target: "d-proc",
		Params: map[string]string{"arg0": "--quiet"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExecuteUse(context.Background(), id, "worker")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), marker) {
		t.Fatal("credential reached the agent-visible result")
	}
	data := result["data"].(map[string]interface{})
	if data["written"] != true || data["exit_code"] != 0.0 {
		t.Fatalf("projection = %v", data)
	}
	// The pinned executable received the credential on stdin.
	received, err := os.ReadFile(got)
	if err != nil || string(received) != marker {
		t.Fatalf("pinned executable did not receive the credential on stdin: %q %v", received, err)
	}

	// Verification records the honest inconclusive observation.
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.State != "inconclusive" {
		t.Fatalf("verification state = %s, want inconclusive (accepted is not applied)", v.State)
	}
	if v.EvidenceKind != "receipt" {
		t.Fatalf("evidence kind = %s, want receipt", v.EvidenceKind)
	}
}

// Registration through the broker boundary refuses malformed pins before
// any approval can exist.
func TestPinnedDestinationValidationAtBroker(t *testing.T) {
	svc := testService(t)
	if err := svc.AddDestination(&types.Destination{ID: "d1", Type: "http-pinned", Endpoint: "/etc/passwd"}); err == nil {
		t.Fatal("http-pinned destination accepted a filesystem path")
	}
	if err := svc.AddDestination(&types.Destination{ID: "d2", Type: "http-pinned", Endpoint: "http://api.example.com"}); err == nil {
		t.Fatal("http-pinned destination accepted plain http")
	}
	if err := svc.AddDestination(&types.Destination{ID: "d3", Type: "process-pinned", Endpoint: "relative/tool"}); err == nil {
		t.Fatal("process-pinned destination accepted a relative path")
	}
	if err := svc.AddDestination(&types.Destination{ID: "d4", Type: "process-pinned", Endpoint: "/nonexistent/tool"}); err == nil {
		t.Fatal("process-pinned destination accepted a missing executable")
	}
	// Legacy types keep their existing behavior (transfer path still
	// rejects non-recipient types at delivery).
	if err := svc.AddDestination(&types.Destination{ID: "d5", Type: "file", Endpoint: "/tmp/x"}); err != nil {
		t.Fatalf("legacy file registration broken: %v", err)
	}
}

// The agent cannot reach the pinned operations without a destination:
// SubmitUse requires the registered target and the policy grant.
func TestPinnedOpsRequireDestinationAndPolicy(t *testing.T) {
	svc := testService(t)
	seedRef(t, svc, "tok", "")
	// No destination at all.
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "tok", Operation: "http.request",
		Params: map[string]string{"path": "/v1"},
	}); err == nil {
		t.Fatal("destinationless http.request accepted")
	}
	// Destination exists, policy does not grant it.
	if err := svc.AddDestination(&types.Destination{ID: "d9", Type: "http-pinned", Endpoint: "https://api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "tok", Operation: "http.request", Target: "d9",
		Params: map[string]string{"path": "/v1"},
	}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected policy denial, got %v", err)
	}
}
