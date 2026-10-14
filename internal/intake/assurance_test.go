package intake

import "testing"

func TestClassifyIsolatedSeparateTerminal(t *testing.T) {
	got := Classify("isolated", false)
	if got.Mode != InputExternalTTY || !got.Protected || got.SameUID || got.TerminalShared {
		t.Fatalf("isolated topology misclassified: %+v", got)
	}
}

func TestClassifyBestEffortNeverProtected(t *testing.T) {
	got := Classify("best-effort", true)
	if got.Protected || got.Mode != InputUnavailable {
		t.Fatalf("same-UID topology falsely claimed protected input: %+v", got)
	}
	if !got.SameUID || !got.TerminalShared {
		t.Fatalf("assurance did not expose unverified boundary: %+v", got)
	}
}
