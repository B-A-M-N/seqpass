package harness

import (
	"testing"
	"time"
)

func nativeSnapshot(t *testing.T, props map[string]bool) *QualificationSnapshot {
	t.Helper()
	digest, err := SecurityConfigDigest(HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	record := AdapterQualification{
		Status: QualificationPassed, HostKind: HostKindOpenCode,
		HostVersion: "2.0", AdapterVersion: "0.1", InputMode: QualifiedHostNative,
		ExecutionTopology: "local", SecurityConfigDigest: digest,
		VerifiedProperties: props,
		ExpiresAt:          time.Now().Add(time.Minute),
	}
	return &QualificationSnapshot{
		HostKind: HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: record,
	}
}

// Presentation and isolation are separate claims: a native surface with an
// unproven process boundary is model-blind but not agent-isolated.
func TestDecisionSeparatesPresentationFromIsolation(t *testing.T) {
	d, err := SelectNativeMode(nativeSnapshot(t, nil), HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.Presentation != InputHostNative || d.PresentationAssurance != "model_blind" {
		t.Fatalf("presentation not separated: %+v", d)
	}
	if d.IsolationAssurance != "unverified" || d.AgentIsolated() {
		t.Fatalf("unverified boundary reported isolated: %+v", d)
	}
	if len(d.MissingBoundaries) != len(boundaryProperties) {
		t.Fatalf("missing boundaries not enumerated: %+v", d.MissingBoundaries)
	}
}

// The strict selector withholds inline native capture unless every boundary
// is verified, and falls back to the external trusted terminal.
func TestStrictSelectorWithholdsUnprovenNativeCapture(t *testing.T) {
	d, err := SelectNativeModeRequiringIsolation(nativeSnapshot(t, map[string]bool{
		"intake_inaccessible": true, "terminal_isolated": true,
	}), HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != InputExternalTTY {
		t.Fatalf("unproven native capture was offered: %+v", d)
	}
	if d.AgentIsolated() {
		t.Fatalf("withheld decision claimed isolation: %+v", d)
	}
	if len(d.MissingBoundaries) != 2 {
		t.Fatalf("missing boundaries = %v, want 2", d.MissingBoundaries)
	}
}

func TestStrictSelectorAllowsFullyVerifiedNativeCapture(t *testing.T) {
	d, err := SelectNativeModeRequiringIsolation(nativeSnapshot(t, map[string]bool{
		"intake_inaccessible": true, "terminal_isolated": true,
		"process_isolated": true, "transcript_isolated": true,
	}), HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != InputHostNative || !d.AgentIsolated() {
		t.Fatalf("verified native capture not offered: %+v", d)
	}
	if len(d.MissingBoundaries) != 0 {
		t.Fatalf("unexpected missing boundaries: %v", d.MissingBoundaries)
	}
}

// The safe fallback never claims isolation.
func TestFallbackDecisionNeverClaimsIsolation(t *testing.T) {
	d, err := SelectNativeMode(nil, HostKindCodex, "1", "1", "local", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d.AgentIsolated() || d.IsolationAssurance != "unverified" || d.Presentation != InputExternalTTY {
		t.Fatalf("fallback overstated assurance: %+v", d)
	}
}
