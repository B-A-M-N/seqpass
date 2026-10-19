package qual

import (
	"os"
	"runtime"
	"testing"
)

// TestQualPrivilegedSyntheticUse is the synthetic cross-broker credential
// tier (qual/PRIVILEGED.md): a protocol-faithful in-process AegisKeys mock
// and a real credentialed mock provider replace the live deployment, so the
// full credentialed scenarios (authorized read, adversarial echo,
// unauthorized operation, rotation, revocation) run in any disposable
// multi-UID Linux lab — no production AegisKeys installation required.
//
// The tier still launches the REAL SeqPass broker under a dedicated service
// UID and drives it only through the real agent MCP adapter under a
// separate agent UID. The mock AegisKeys socket is group-isolated so the
// kernel denies the agent exactly as with a live deployment. Credential
// values never appear in retained evidence: digests only.
//
// Required lab inputs are the same identity/artifact variables the
// process-boundary tier documents in qual/PRIVILEGED.md, except that the
// AegisKeys installation variables are NOT used here.
func TestQualPrivilegedSyntheticUse(t *testing.T) {
	h := &harness{t: t, dir: t.TempDir(), uid: "synthetic-tier", topology: map[string]string{}}
	if os.Getenv("SEQPASS_QUAL_PRIVILEGED") != "1" {
		h.recordBlocked("synthetic-credential-tier", tierSystem,
			"the real broker resolves a synthetic credential through the AegisKeys contract and dispatches it to a real consuming application without any agent-visible disclosure",
			"SEQPASS_QUAL_PRIVILEGED!=1 (opt-in not set)")
		recordPrivilegedScenariosNotExercised(h, "synthetic tier not opted in")
		writeManifest(t, h, "aegiskeys-synthetic")
		t.Skip("synthetic tier not opted in; recorded as blocked, not passed")
	}
	if runtime.GOOS != "linux" {
		h.recordBlocked("synthetic-credential-tier", tierSystem,
			"Linux peer credentials and process UID separation are exercised",
			"the synthetic credential tier requires Linux")
		recordPrivilegedScenariosNotExercised(h, "not running on Linux")
		writeManifest(t, h, "aegiskeys-synthetic")
		t.Skip("synthetic tier requires Linux")
	}
	if os.Geteuid() != 0 {
		h.recordBlocked("synthetic-credential-tier", tierSystem,
			"broker and agent probes run under distinct OS identities",
			"the test process needs root to launch disposable child processes under configured UIDs")
		recordPrivilegedScenariosNotExercised(h, "not running as root")
		writeManifest(t, h, "aegiskeys-synthetic")
		t.Skip("synthetic tier needs root for UID separation")
	}

	ready, blocked := runPrivilegedSyntheticUse(t, h)
	if !ready {
		h.recordBlocked("synthetic-credential-tier", tierSystem,
			"the real broker resolves a synthetic credential through the AegisKeys contract and dispatches it to a real consuming application without any agent-visible disclosure",
			blocked)
		recordPrivilegedScenariosNotExercised(h, blocked)
		writeManifest(t, h, "aegiskeys-synthetic")
		t.Skip("synthetic tier prerequisites missing: " + blocked)
	}

	recordPrivilegedScenariosNotExercisedExcept(h,
		"the synthetic tier covers only the scenarios its cases exercised; the remaining ones still require a live deployment run",
		"authorized-credentialed-read", "adversarial-credential-echo",
		"unauthorized-operation", "credential-rotation", "revocation-barrier")
	writeManifest(t, h, "aegiskeys-synthetic")
}
