package qual

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestQualPrivileged exercises the Linux process boundary when explicitly
// opted in. The test never provisions system users, changes AegisKeys, or
// writes outside a disposable /tmp directory. The socket/file boundary tier
// is deliberately separate from the full cross-broker credentialed tier.
//
// Required lab inputs are documented in qual/PRIVILEGED.md. Without them this
// test records blocked/not_exercised cases and skips; it never reports a pass.
func TestQualPrivileged(t *testing.T) {
	h := &harness{t: t, dir: t.TempDir(), uid: "privileged-tier"}
	if os.Getenv("SEQPASS_QUAL_PRIVILEGED") != "1" {
		h.recordBlocked("privileged-boundary", tierSystem,
			"real SeqPass broker runs as a dedicated UID while a separate agent UID can reach only the agent socket",
			"SEQPASS_QUAL_PRIVILEGED!=1 (opt-in not set)")
		recordPrivilegedScenariosNotExercised(h, "privileged tier not opted in")
		writeManifest(t, h, "aegiskeys")
		t.Skip("privileged tier not opted in; recorded as blocked, not passed")
	}
	if runtime.GOOS != "linux" {
		h.recordBlocked("privileged-boundary", tierSystem,
			"Linux peer credentials and process UID separation are exercised",
			"the executable qualification requires Linux")
		recordPrivilegedScenariosNotExercised(h, "not running on Linux")
		writeManifest(t, h, "aegiskeys")
		t.Skip("privileged tier requires Linux")
	}
	if os.Geteuid() != 0 {
		h.recordBlocked("privileged-boundary", tierSystem,
			"broker and agent probes run under distinct OS identities",
			"the test process needs root to launch disposable child processes under configured UIDs")
		recordPrivilegedScenariosNotExercised(h, "not running as root")
		writeManifest(t, h, "aegiskeys")
		t.Skip("privileged tier needs root for UID separation")
	}

	ready, blocked := runPrivilegedBoundary(t, h)
	if !ready {
		h.recordBlocked("privileged-boundary", tierSystem,
			"real SeqPass broker runs as a dedicated UID while a separate agent UID can reach only the agent socket",
			blocked)
		recordPrivilegedScenariosNotExercised(h, blocked)
		writeManifest(t, h, "aegiskeys")
		t.Skip("privileged boundary prerequisites missing: " + blocked)
	}

	recordPrivilegedScenariosNotExercised(h,
		"the executable tier proves only local UID/socket/file separation; no real credentialed provider operation was dispatched")
	writeManifest(t, h, "aegiskeys")
}

func isProtectedRelayCase(name string) bool {
	if strings.HasPrefix(name, "protected-relay") || strings.HasPrefix(name, "agent-process-") {
		return true
	}
	switch name {
	case "agent-cannot-read-relay-payload", "agent-mcp-message-nondisclosure", "agent-mcp-clean-exit",
		"agent-mcp-stderr-nondisclosure", "broker-log-nondisclosure", "broker-receipt-nondisclosure",
		"trusted-intake-fulfillment":
		return true
	default:
		return false
	}
}

func summarizeProtectedRelay(cases []caseResult) (string, string) {
	var relevant, failed, blocked, notExercised []string
	for _, c := range cases {
		if !isProtectedRelayCase(c.Name) {
			continue
		}
		relevant = append(relevant, c.Name)
		switch c.Status {
		case "failed":
			failed = append(failed, c.Name)
		case "blocked":
			blocked = append(blocked, c.Name)
		case "not_exercised":
			notExercised = append(notExercised, c.Name)
		case "passed":
		default:
			failed = append(failed, c.Name+"(unknown-status)")
		}
	}
	if len(relevant) == 0 {
		return "not_exercised", "no protected-relay subchecks were recorded"
	}
	if len(failed) > 0 {
		return "failed", "failed subchecks=" + strings.Join(failed, ",")
	}
	if len(blocked) > 0 {
		return "blocked", "blocked subchecks=" + strings.Join(blocked, ",")
	}
	if len(notExercised) > 0 {
		return "not_exercised", "not exercised subchecks=" + strings.Join(notExercised, ",")
	}
	return "passed", fmt.Sprintf("all %d protected-relay subchecks passed", len(relevant))
}

func recordProtectedRelayAggregate(h *harness, cases []caseResult) {
	status, observed := summarizeProtectedRelay(cases)
	intent := "complete the trusted-terminal relay while the agent remains unable to observe the value"
	expected := "trusted intake delivers the synthetic value; agent only receives status; all process and durable-store observations pass"
	switch status {
	case "passed":
		h.recordTier("protected-relay", tierSystem, intent, expected, observed, true)
	case "failed":
		h.recordTier("protected-relay", tierSystem, intent, expected, observed, false)
	case "blocked":
		h.recordBlocked("protected-relay", tierSystem, intent, observed)
	default:
		h.recordNotExercised("protected-relay", tierSystem, expected, observed)
	}
}

func recordPrivilegedScenariosNotExercised(h *harness, reason string) {
	recordPrivilegedScenariosNotExercisedExcept(h, reason)
}

func TestSummarizeProtectedRelayRequiresAllChecks(t *testing.T) {
	passed := []caseResult{
		{Name: "protected-relay-mcp-request", Status: "passed"},
		{Name: "trusted-intake-fulfillment", Status: "passed"},
		{Name: "agent-mcp-message-nondisclosure", Status: "passed"},
	}
	if status, _ := summarizeProtectedRelay(passed); status != "passed" {
		t.Fatalf("all passing checks summarized as %q", status)
	}
	if status, _ := summarizeProtectedRelay(append(append([]caseResult(nil), passed...),
		caseResult{Name: "agent-process-memory-observation", Status: "blocked"})); status != "blocked" {
		t.Fatalf("unobservable memory summarized as %q", status)
	}
	if status, _ := summarizeProtectedRelay(append(append([]caseResult(nil), passed...),
		caseResult{Name: "broker-receipt-nondisclosure", Status: "failed"})); status != "failed" {
		t.Fatalf("failed disclosure check summarized as %q", status)
	}
	if status, _ := summarizeProtectedRelay([]caseResult{{Name: "protected-relay-setup", Status: "passed"},
		{Name: "broker-log-nondisclosure", Status: "not_exercised"}}); status != "not_exercised" {
		t.Fatalf("unexercised check summarized as %q", status)
	}
}

func TestProtectedRelayManifestHasSingleAggregateCase(t *testing.T) {
	h := &harness{t: t}
	subchecks := []caseResult{
		{Name: "protected-relay-mcp-request", Status: "passed", Pass: true},
		{Name: "trusted-intake-fulfillment", Status: "passed", Pass: true},
		{Name: "agent-mcp-message-nondisclosure", Status: "passed", Pass: true},
	}
	recordProtectedRelayAggregate(h, subchecks)
	recordPrivilegedScenariosNotExercised(h, "the credentialed tier was not run")
	protectedRelayCount := 0
	credentialReadCount := 0
	for _, c := range h.cases {
		switch c.Name {
		case "protected-relay":
			protectedRelayCount++
			if c.Status != "passed" || !c.Pass {
				t.Errorf("protected relay aggregate = %+v, want passed", c)
			}
		case "authorized-credentialed-read":
			credentialReadCount++
			if c.Status != "not_exercised" {
				t.Errorf("credentialed read case = %+v, want not_exercised", c)
			}
		}
	}
	if protectedRelayCount != 1 || credentialReadCount != 1 {
		t.Fatalf("manifest case multiplicity: protected-relay=%d authorized-credentialed-read=%d", protectedRelayCount, credentialReadCount)
	}
}

func TestMissingRelayAggregateRemainsNotExercised(t *testing.T) {
	h := &harness{t: t, cases: []caseResult{{Name: "isolated-broker-start", Status: "failed"}}}
	recordPrivilegedScenariosNotExercised(h, "broker failed before the relay stage")
	count := 0
	for _, c := range h.cases {
		if c.Name == "protected-relay" {
			count++
			if c.Status != "not_exercised" {
				t.Errorf("missing relay aggregate = %+v, want not_exercised", c)
			}
		}
	}
	if count != 1 {
		t.Fatalf("protected-relay manifest entry count = %d, want 1", count)
	}
}

func recordPrivilegedScenariosNotExercisedExcept(h *harness, reason string, exercised ...string) {
	skip := make(map[string]bool, len(exercised))
	for _, name := range exercised {
		skip[name] = true
	}
	for _, item := range []struct{ name, expected string }{
		{"authorized-credentialed-read", "controlled credential reaches mock provider while absent from every agent-visible surface"},
		{"unauthorized-operation", "no provider request and no AegisKeys resolve"},
		{"revocation-barrier", "revocation before dispatch prevents provider request; post-dispatch revocation remains in-flight"},
		{"credential-rotation", "next resolution uses new binding and old value is rejected"},
		{"concurrent-consumers", "independent operations complete without credential mix-up or deadlock"},
		{"protected-relay", "trusted terminal fulfills and recipient durably accepts while agent sees opaque status"},
		{"lost-ack-reconciliation", "uncertain result is reconciled independently without replay"},
		{"restart-and-ephemeral-payload", "durable evidence remains truthful and in-memory payload is unavailable after restart"},
		{"adversarial-credential-echo", "literal and JSON-escaped credential echoes are rejected before persistence/publication"},
		{"config-overlay-concurrency", "overlapping launches restore baseline or preserve/report external edits"},
	} {
		if skip[item.name] || hasRecordedScenario(h, item.name) {
			continue
		}
		h.recordNotExercised(item.name, tierSystem, item.expected, reason)
	}
}

func hasRecordedScenario(h *harness, name string) bool {
	if h == nil {
		return false
	}
	for _, c := range h.cases {
		if c.Name == name {
			return true
		}
	}
	return false
}
