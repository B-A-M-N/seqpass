package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
)

// nativeQualifiedSnapshot builds a snapshot whose adapter passed
// qualification for an inline native (host) input surface, with only the
// properties the caller lists as verified.
func nativeQualifiedSnapshot(t *testing.T, props map[string]bool) *harness.QualificationSnapshot {
	t.Helper()
	digest, err := harness.SecurityConfigDigest(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	return &harness.QualificationSnapshot{
		HostKind: harness.HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: harness.QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: harness.AdapterQualification{
			Status: harness.QualificationPassed, HostKind: harness.HostKindOpenCode,
			HostVersion: "2.0", AdapterVersion: "0.1", InputMode: harness.QualifiedHostNative,
			ExecutionTopology: "local", SecurityConfigDigest: digest,
			VerifiedProperties: props,
			ExpiresAt:          time.Now().Add(time.Minute),
		},
	}
}

func serviceWithHostIsolation(t *testing.T, requireVerified bool, props map[string]bool) *Service {
	t.Helper()
	dir := t.TempDir()
	svc, err := New(Config{
		DBPath:                       filepath.Join(dir, "test.db"),
		VaultType:                    "memory-test",
		RequireVerifiedHostIsolation: requireVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.SetHostQualification(nativeQualifiedSnapshot(t, props))
	return svc
}

// Objective 4.3: when the broker is running a verified isolated deployment,
// inline native capture is withheld unless every agent-observable boundary
// property has been proven for this exact registration. The selector can only
// decline the stronger surface, never widen it.
func TestStrictHostIsolationWithholdsUnprovenNativeCapture(t *testing.T) {
	partial := map[string]bool{"intake_inaccessible": true, "terminal_isolated": true}

	// Control: the historic selector offers native capture on the same
	// snapshot, so the strict behaviour below is genuinely caused by the
	// isolation requirement and not by the fixture.
	permissive := serviceWithHostIsolation(t, false, partial)
	loose, err := permissive.SelectNativeModeForRegistration(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	if loose.Mode != harness.InputHostNative {
		t.Fatalf("control snapshot did not offer native capture: %+v", loose)
	}

	strict := serviceWithHostIsolation(t, true, partial)
	got, err := strict.SelectNativeModeForRegistration(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != harness.InputExternalTTY {
		t.Fatalf("unproven native capture offered under required isolation: %+v", got)
	}
	if got.AgentIsolated() {
		t.Fatalf("withheld decision claimed agent isolation: %+v", got)
	}
	if len(got.MissingBoundaries) != 2 {
		t.Fatalf("missing boundaries = %v, want the 2 unproven ones", got.MissingBoundaries)
	}
}

// A fully proven registration still gets inline capture: strictness must not
// degrade a genuinely verified boundary.
func TestStrictHostIsolationAllowsFullyVerifiedNativeCapture(t *testing.T) {
	svc := serviceWithHostIsolation(t, true, map[string]bool{
		"intake_inaccessible": true, "terminal_isolated": true,
		"process_isolated": true, "transcript_isolated": true,
	})
	got, err := svc.SelectNativeModeForRegistration(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != harness.InputHostNative || !got.AgentIsolated() {
		t.Fatalf("verified native capture was withheld: %+v", got)
	}
}
