package intake

import "testing"

func TestClassifyIsolatedSeparateTerminal(t *testing.T) {
	got := Classify("isolated", false, false)
	if got.Mode != InputExternalTTY || !got.Protected || got.SameUID || got.TerminalShared {
		t.Fatalf("isolated topology misclassified: %+v", got)
	}
	if got.Assurance != AssuranceVerified {
		t.Fatalf("isolated topology should be verified: %+v", got)
	}
}

func TestClassifyBestEffortNeverProtected(t *testing.T) {
	got := Classify("best-effort", true, false)
	if got.Protected || got.Mode != InputUnavailable {
		t.Fatalf("same-UID topology falsely claimed protected input: %+v", got)
	}
	if !got.SameUID || !got.TerminalShared {
		t.Fatalf("assurance did not expose unverified boundary: %+v", got)
	}
	if got.Assurance != AssuranceUnverified {
		t.Fatalf("best-effort should be unverified, not verified: %+v", got)
	}
}

// SP-03: an agent that can reach the intake socket must be classified
// as prohibited, not merely unverified — the gate must fail closed.
func TestClassifyIntakeAccessibleProhibited(t *testing.T) {
	got := Classify("isolated", false, true)
	if got.Assurance != AssuranceProhibited {
		t.Fatalf("intake-accessible topology should be prohibited: %+v", got)
	}
	if got.Protected || got.Mode != InputUnavailable {
		t.Fatalf("intake-accessible topology falsely claimed protection: %+v", got)
	}
	if got.Reason == "" {
		t.Fatal("prohibited classification must state its reason")
	}
}

// HI-01: denying intake access is necessary but not sufficient. A shell
// with terminal observation privileges can still undermine an inline or
// external TTY handoff, so the highest truthful classification remains
// model_blind rather than agent_isolated.
func TestClassifyTerminalObserverIsModelBlindOnly(t *testing.T) {
	got := ClassifyBoundaries(VerifiedProperties{
		IntakeInaccessible: true,
		TerminalIsolated:   false,
		ProcessIsolated:    true,
		TranscriptIsolated: true,
	}, false)
	if got.Assurance != AssuranceModelBlind {
		t.Fatalf("assurance = %q, want model_blind", got.Assurance)
	}
	if got.Assurance == AssuranceAgentIsolated {
		t.Fatal("unproven terminal boundary must not claim full isolation")
	}
	if got.Properties.TerminalIsolated {
		t.Fatal("properties must preserve the unverified terminal fact")
	}
}

func TestClassifyCompletePropertiesAreAgentIsolated(t *testing.T) {
	got := ClassifyBoundaries(VerifiedProperties{
		IntakeInaccessible: true,
		TerminalIsolated:   true,
		ProcessIsolated:    true,
		TranscriptIsolated: true,
	}, false)
	if got.Assurance != AssuranceAgentIsolated || !got.Protected {
		t.Fatalf("assurance = %+v, want protected agent_isolated", got)
	}
}

func TestClassifyIntakeAccessRemainsProhibited(t *testing.T) {
	got := ClassifyBoundaries(VerifiedProperties{
		IntakeInaccessible: false,
		TerminalIsolated:   true,
		ProcessIsolated:    true,
		TranscriptIsolated: true,
	}, true)
	if got.Assurance != AssuranceProhibited || got.Protected {
		t.Fatalf("assurance = %+v, want prohibited", got)
	}
}
