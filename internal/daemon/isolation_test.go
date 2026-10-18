package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/isolation"
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

// Objective 4.4 with concurrency: the drift revocation rewrites assurance
// state while per-connection handlers read it. Run with -race, this asserts
// the label and the service's host facts are published safely rather than
// torn. It is the regression test for the unsynchronized assurance fields.
func TestDriftRevocationIsSafeUnderConcurrentReads(t *testing.T) {
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

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// The reads a health call and a host registration make.
				_ = d.svc.HostInputMode()
				_ = d.svc.HostInputAssurance()
				_ = d.svc.HostInputReason()
				_ = d.srv.AssuranceLabel()
				_, _ = d.svc.SelectNativeModeForRegistration(harness.HostKindOpenCode,
					"2.0", "0.1", "local", nil)
			}
		}()
	}
	for i := 0; i < 50; i++ {
		d.revokeOnDrift([]string{"synthetic drift"})
	}
	close(stop)
	wg.Wait()

	// The revocation is observable and honest.
	if got := d.srv.AssuranceLabel(); got != "unverified" {
		t.Fatalf("post-drift label = %q, want unverified", got)
	}
	if got := d.svc.HostInputAssurance(); got != string(intake.AssuranceUnverified) {
		t.Fatalf("post-drift assurance = %q, want unverified", got)
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

// Objective 4.2: the refusal must come from the LIVE boundary check, not only
// from configuration validation. The doctor is stubbed here so the refusal
// path is provable without a privileged multi-UID host.
func TestIsolatedRefusalComesFromTheLiveBoundaryCheck(t *testing.T) {
	original := isolationDoctor
	t.Cleanup(func() { isolationDoctor = original })

	unverified := isolation.Report{
		Mode: isolation.ModeIsolated,
		Checks: []isolation.Check{
			{Name: "agent_denied_broker_database", OK: false, Detail: "agent uid 65533 can access /db (world readable)"},
			{Name: "identity_disjoint", OK: true, Detail: "ok"},
		},
		Verified: false,
	}
	isolationDoctor = func(isolation.Config) (*isolation.Report, error) { return &unverified, nil }

	label, err := assessIsolation(Config{AssuranceMode: AssuranceIsolated})
	if err == nil {
		t.Fatalf("unverified live topology was accepted (label %q)", label)
	}
	if !strings.Contains(err.Error(), "live isolation check failed") {
		t.Fatalf("refusal does not name the live check: %v", err)
	}
	if !strings.Contains(err.Error(), "agent_denied_broker_database") {
		t.Fatalf("refusal does not name the failing boundary: %v", err)
	}
	if label != "" {
		t.Fatalf("a refused startup published an assurance label: %q", label)
	}

	// The positive control: only a verified report yields the verified label.
	verified := unverified
	verified.Verified = true
	verified.Checks = []isolation.Check{{Name: "identity_disjoint", OK: true}}
	isolationDoctor = func(isolation.Config) (*isolation.Report, error) { return &verified, nil }
	label, err = assessIsolation(Config{AssuranceMode: AssuranceIsolated})
	if err != nil {
		t.Fatalf("verified topology refused: %v", err)
	}
	if label != string(intake.AssuranceVerified) {
		t.Fatalf("verified topology labelled %q", label)
	}
}

// A diagnostic that cannot run is fatal too: an unproven boundary must never
// be treated as a pass.
func TestIsolationDiagnosticErrorRefusesStartup(t *testing.T) {
	original := isolationDoctor
	t.Cleanup(func() { isolationDoctor = original })
	isolationDoctor = func(isolation.Config) (*isolation.Report, error) {
		return nil, errBoom
	}
	if _, err := assessIsolation(Config{AssuranceMode: AssuranceIsolated}); err == nil {
		t.Fatal("a failing diagnostic was treated as a verified boundary")
	} else if !strings.Contains(err.Error(), "isolation diagnostic failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

var errBoom = &boomError{}

type boomError struct{}

func (e *boomError) Error() string { return "cannot evaluate topology" }

// Objective 4.1: a production vault must not be paired with a topology it
// cannot prove, even when the operator asks for it explicitly.
func TestProductionVaultRefusesBestEffort(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		DBPath:        filepath.Join(dir, "m.db"),
		SocketPath:    filepath.Join(dir, "b.sock"),
		VaultType:     "aegiskeys",
		AssuranceMode: AssuranceBestEffort,
	})
	if err == nil {
		t.Fatal("production vault started on an unverifiable best-effort topology")
	}
	if !strings.Contains(err.Error(), "best-effort is development-only") {
		t.Fatalf("error does not explain why best-effort is refused: %v", err)
	}
}

// The development vault keeps working, but is always reported unverified.
func TestDevelopmentVaultAllowsBestEffort(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{
		DBPath:        filepath.Join(dir, "m.db"),
		SocketPath:    filepath.Join(dir, "a.sock"),
		AdminSocket:   filepath.Join(dir, "a.sock.admin"),
		VaultType:     "memory-test",
		AssuranceMode: AssuranceBestEffort,
	})
	if err != nil {
		t.Fatalf("development vault refused: %v", err)
	}
	defer d.Shutdown()
	if got := d.svc.HostInputAssurance(); got != string(intake.AssuranceUnverified) {
		t.Fatalf("development assurance = %q, want unverified", got)
	}
}
