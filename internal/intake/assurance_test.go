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
