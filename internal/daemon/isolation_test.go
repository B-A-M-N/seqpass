package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
)

// Objective 4.1: a production (AegisKeys) installation defaults to strict
// isolation and refuses to start when the topology is not isolated.
func TestProductionVaultDefaultsToIsolated(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		DBPath:     filepath.Join(dir, "m.db"),
		SocketPath: filepath.Join(dir, "b.sock"),
		VaultType:  "aegiskeys",
	})
	if err == nil {
		t.Fatal("production installation started without an isolated topology")
	}
	if !strings.Contains(err.Error(), "isolated") {
		t.Fatalf("error does not explain the isolation requirement: %v", err)
	}
}

// Objective 4.1: a best-effort deployment is labelled unverified, never
// presented as protected.
func TestBestEffortReportsUnverified(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{
		DBPath:      filepath.Join(dir, "m.db"),
		SocketPath:  filepath.Join(dir, "a.sock"),
		AdminSocket: filepath.Join(dir, "a.sock.admin"),
		VaultType:   "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	if got := d.svc.HostInputAssurance(); got != string(intake.AssuranceUnverified) {
		t.Fatalf("best-effort assurance = %q, want unverified", got)
	}
	if got := d.svc.HostInputMode(); got != string(harness.InputExternalTTY) {
		t.Fatalf("best-effort input mode = %q, want external_tty", got)
	}
}

// Objective 4.4: changing a protected socket's permissions is detected as
// drift and revokes the host capability, without touching external work.
func TestSecurityDriftRevokesHostCapability(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	hostSock := filepath.Join(dir, "host.sock")
	d, err := New(Config{
		DBPath:      filepath.Join(dir, "m.db"),
		SocketPath:  filepath.Join(dir, "a.sock"),
		AdminSocket: filepath.Join(dir, "a.sock.admin"),
		HostSocket:  hostSock,
		VaultType:   "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	if drift := d.VerifySecurityBoundary(); len(drift) != 0 {
		t.Fatalf("fresh boundary already reports drift: %v", drift)
	}
	// Drift: the host socket's permissions change.
	if err := os.Chmod(hostSock, 0640); err != nil {
		t.Fatal(err)
	}
	drift := d.VerifySecurityBoundary()
	if len(drift) == 0 {
		t.Fatal("permission change was not detected as drift")
	}
	d.revokeOnDrift(drift)
	if got := d.svc.HostInputAssurance(); got != string(intake.AssuranceUnverified) {
		t.Fatalf("post-drift assurance = %q, want unverified", got)
	}
	if got := d.svc.HostInputMode(); got != string(harness.InputExternalTTY) {
		t.Fatalf("post-drift mode = %q, want external_tty", got)
	}
	// The drift is settled: re-checking after the revocation is clean.
	if again := d.VerifySecurityBoundary(); len(again) != 0 {
		t.Fatalf("drift not settled after revocation: %v", again)
	}
}

// The honest label mapping: only isolated topology may read as verified.
func TestAssuranceLabelMapping(t *testing.T) {
	if AssuranceLabel(AssuranceBestEffort) != "unverified" {
		t.Fatal("best-effort is not labelled unverified")
	}
	if AssuranceLabel(AssuranceIsolated) == "unverified" {
		t.Fatal("isolated topology labelled unverified")
	}
}
