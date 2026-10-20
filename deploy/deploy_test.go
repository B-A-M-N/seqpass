// Package deploy validates the shipped systemd unit file. Go package tests
// cannot execute systemd, but they CAN parse the unit and assert the
// directive placements systemd itself enforces — the deployment audit found
// ExecStartPre in [Unit] and StartLimit* in [Service], both silently
// ignored by systemd (surfaced only by systemd-analyze verify). This test
// pins the correct placements, the two-stage gate contract, and the
// complete topology argument set, and additionally runs systemd-analyze
// verify when the binary is available on the host.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const unitFile = "seqpass-broker.service"

// parseUnit returns a map of section name -> ordered directives
// (lower-cased key -> full joined value with continuations folded).
func parseUnit(t *testing.T) map[string][][2]string {
	t.Helper()
	raw, err := os.ReadFile(unitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	sections := map[string][][2]string{}
	current := ""
	var key, value string
	flush := func() {
		if key == "" {
			return
		}
		if current == "" {
			t.Fatalf("directive %q before any section header", key)
		}
		sections[current] = append(sections[current], [2]string{strings.ToLower(key), value})
		key, value = "", ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Continuation state (systemd semantics): a directive line ending
		// in "\" opens a continuation; every following line appends to it,
		// and the first line NOT ending in "\" closes the directive.
		if key != "" {
			value += " " + strings.TrimSuffix(line, "\\")
			if !strings.HasSuffix(line, "\\") {
				flush()
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			current = strings.Trim(line, "[]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unparseable unit line: %q", line)
		}
		key, value = k, strings.TrimSuffix(v, "\\")
		if !strings.HasSuffix(v, "\\") {
			flush()
		}
	}
	flush()
	return sections
}

func directives(t *testing.T, sections map[string][][2]string, section, key string) []string {
	t.Helper()
	want := strings.ToLower(key)
	var out []string
	for _, kv := range sections[section] {
		if kv[0] == want {
			out = append(out, kv[1])
		}
	}
	return out
}

func has(sections map[string][][2]string, section, key string) bool {
	want := strings.ToLower(key)
	for _, kv := range sections[section] {
		if kv[0] == want {
			return true
		}
	}
	return false
}

func join(vals []string) string { return strings.Join(vals, "\n") }

// TestUnitDirectivePlacement pins the systemd section semantics: startup
// commands belong to [Service], restart-rate-limiting to [Unit].
func TestUnitDirectivePlacement(t *testing.T) {
	sections := parseUnit(t)
	if has(sections, "Unit", "ExecStartPre") {
		t.Fatal("ExecStartPre in [Unit] is silently ignored by systemd (deployment audit defect); it belongs in [Service]")
	}
	for _, key := range []string{"startlimitintervalsec", "startlimitburst"} {
		if has(sections, "Service", key) {
			t.Fatalf("%s in [Service] is silently ignored by systemd (deployment audit defect); it belongs in [Unit]", key)
		}
		if !has(sections, "Unit", key) {
			t.Fatalf("[Unit] is missing %s: an unbounded restart loop must stay bounded", key)
		}
	}
	if len(directives(t, sections, "Service", "ExecStartPre")) == 0 {
		t.Fatal("[Service] is missing the ExecStartPre preflight gate")
	}
}

// TestUnitTwoStageGate pins the gate honesty contract: the pre-start
// preflight must NOT demand --require-verified (a preflight cannot prove
// the isolation of a broker that has not started — doctor exits non-zero
// if asked), while the post-start readiness gate must.
func TestUnitTwoStageGate(t *testing.T) {
	sections := parseUnit(t)
	pre := join(directives(t, sections, "Service", "ExecStartPre"))
	if strings.Contains(pre, "--require-verified") {
		t.Fatal("ExecStartPre must not pass --require-verified: the preflight verdict is 'nothing provably wrong', never 'verified'; the gate would fail every startup")
	}
	post := join(directives(t, sections, "Service", "ExecStartPost"))
	if !strings.Contains(post, "--require-verified") {
		t.Fatal("ExecStartPost readiness gate must pass --require-verified: only a running broker can demonstrate the verified boundary")
	}
	if !strings.Contains(post, "sh -c") {
		t.Fatal("ExecStartPost must be a bounded retry: the broker socket may not be listening the instant the unit forks")
	}
}

// TestUnitCompleteTopologyArguments pins the complete isolated-deployment
// argument set: the broker and the preflight must receive the full identity
// topology (UIDs, groups, sockets, AegisKeys endpoint), not a partial
// configuration that silently degrades to euid-only defaults.
func TestUnitCompleteTopologyArguments(t *testing.T) {
	sections := parseUnit(t)
	required := []string{
		"--vault", "--db", "--socket", "--admin-socket", "--intake-socket",
		"--agent-uid", "--admin-uid", "--intake-uid",
		"--socket-group", "--intake-group", "--aegiskeys-socket",
	}
	for _, surface := range []string{"ExecStart", "ExecStartPre"} {
		argv := join(directives(t, sections, "Service", surface))
		if surface == "ExecStart" && !strings.Contains(argv, "broker") {
			t.Fatalf("ExecStart does not start the broker: %q", argv)
		}
		if surface == "ExecStartPre" && !strings.Contains(argv, "--topology") {
			t.Fatalf("ExecStartPre is not the topology preflight: %q", argv)
		}
		for _, flag := range required {
			if !strings.Contains(argv, flag) {
				t.Fatalf("%s is missing %s: incomplete deployment configuration", surface, flag)
			}
		}
	}
	// ExecStartPre and ExecStart must agree on the topology: both expand
	// the same EnvironmentFile keys. Compare the variable sets.
	preVars := envVarsIn(join(directives(t, sections, "Service", "ExecStartPre")))
	startVars := envVarsIn(join(directives(t, sections, "Service", "ExecStart")))
	topology := []string{"SEQPASS_DB", "SEQPASS_SOCKET", "SEQPASS_ADMIN_SOCKET", "SEQPASS_INTAKE_SOCKET",
		"SEQPASS_AGENT_UIDS", "SEQPASS_ADMIN_UIDS", "SEQPASS_INTAKE_UIDS",
		"SEQPASS_SOCKET_GROUP", "SEQPASS_INTAKE_GROUP", "SEQPASS_AEGISKEYS_SOCKET"}
	for _, v := range topology {
		if !preVars[v] || !startVars[v] {
			t.Fatalf("topology variable %s must appear in both ExecStartPre and ExecStart (preflight/broker drift): pre=%v start=%v", v, preVars, startVars)
		}
	}
	// P0-1: the broker (not the preflight) must be configured with the
	// trusted resolve helper — the long-lived broker is non-dumpable and
	// cannot pass AegisKeys /proc/<pid>/exe peer verification itself.
	startArgv := join(directives(t, sections, "Service", "ExecStart"))
	if !strings.Contains(startArgv, "--aegiskeys-resolve-helper ${SEQPASS_RESOLVE_HELPER}") {
		t.Fatalf("ExecStart is missing the trusted resolve helper argument: %q", startArgv)
	}
}

// TestUnitSeparateAgentSocketDirectory pins the isolated-topology directory
// split: the agent socket lives in its OWN runtime directory
// (/run/seqpass-agent), admin and intake sockets in /run/seqpass which the
// first ExecStartPre tightens to 0700 BEFORE the doctor preflight runs. The
// broker's isolated-assurance validation refuses an agent socket sharing a
// directory with admin/intake sockets (sameSocketDir check in daemon.New),
// so the advertised configuration must provision two directories, and the
// trusted directory must not be group-readable when the broker starts.
// systemd-analyze verify does NOT check any of this — it validates unit
// syntax, not SeqPass's security topology.
func TestUnitSeparateAgentSocketDirectory(t *testing.T) {
	sections := parseUnit(t)
	var runtimeDirs []string
	var runtimeMode string
	for _, kv := range sections["Service"] {
		switch kv[0] {
		case "runtimedirectory":
			runtimeDirs = append(runtimeDirs, strings.Fields(kv[1])...)
		case "runtimedirectorymode":
			runtimeMode = kv[1]
		}
	}
	found := map[string]bool{}
	for _, d := range runtimeDirs {
		found[d] = true
	}
	if !found["seqpass"] || !found["seqpass-agent"] {
		t.Fatalf("RuntimeDirectory must provision both the trusted dir and the separate agent dir, got %v", runtimeDirs)
	}
	if runtimeMode != "0750" {
		t.Fatalf("RuntimeDirectoryMode = %q, want 0750 (group traverse for the agent dir; the trusted dir is tightened by ExecStartPre)", runtimeMode)
	}
	pre := directives(t, sections, "Service", "ExecStartPre")
	if len(pre) < 2 {
		t.Fatal("ExecStartPre is missing the directory hardening or the doctor preflight")
	}
	if !strings.Contains(pre[0], "chmod 0700 /run/seqpass") {
		t.Fatalf("first ExecStartPre must tighten /run/seqpass to 0700 (admin dir must not be group-readable), got %q", pre[0])
	}
	if !strings.Contains(pre[1], "--topology") {
		t.Fatalf("the doctor preflight must run AFTER the directory hardening, got %q", pre[1])
	}
	// The documented production defaults must reflect the split topology:
	// agent socket in its own runtime directory, admin/intake in the
	// tightened trusted directory. The defaults live in the unit's comment
	// header (operators override via /etc/default/seqpass), so pin them
	// there — a doc/topology divergence is exactly how shared-directory
	// configurations reappear.
	doc, err := os.ReadFile(unitFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		varName string
		want    string
	}{
		{"SEQPASS_SOCKET", "/run/seqpass-agent/broker.sock"},
		{"SEQPASS_ADMIN_SOCKET", "/run/seqpass/admin.sock"},
		{"SEQPASS_INTAKE_SOCKET", "/run/seqpass/intake.sock"},
	} {
		found := false
		for _, line := range strings.Split(string(doc), "\n") {
			if strings.HasPrefix(line, "#") && strings.Contains(line, c.varName) && strings.Contains(line, c.want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unit documentation for %s must advertise the separate-directory default %s (comment lines are the advertised production configuration)", c.varName, c.want)
		}
	}
}

func envVarsIn(s string) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			continue
		}
		if s[i+1] == '$' { // escaped literal $
			i++
			continue
		}
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				break
			}
			out[s[i+2:i+2+end]] = true
			i += 2 + end
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '_' || isAlnum(s[j])) {
			j++
		}
		if j > i+1 {
			out[s[i+1:j]] = true
			i = j - 1
		}
	}
	return out
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// TestUnitNoCredentialEnvironment pins the environment discipline: the unit
// carries path/UID configuration only — no credential-bearing Environment
// assignments, and the EnvironmentFile is mandatory (no "-" prefix) so an
// incomplete installation fails the unit instead of silently narrowing.
func TestUnitNoCredentialEnvironment(t *testing.T) {
	sections := parseUnit(t)
	for _, section := range []string{"Unit", "Service", "Install"} {
		for _, kv := range sections[section] {
			if kv[0] == "environment" {
				t.Fatalf("Environment= assignment in [%s] invites credential drift: %s=%s", section, kv[0], kv[1])
			}
		}
	}
	env := directives(t, sections, "Service", "EnvironmentFile")
	if len(env) == 0 {
		t.Fatal("EnvironmentFile is missing: the topology must come from one required, reviewable file")
	}
	for _, e := range env {
		if strings.HasPrefix(e, "-") {
			t.Fatalf("EnvironmentFile must be mandatory (fail closed on missing configuration), got: %s", e)
		}
	}
}

// TestUnitIsolationProfile pins the filesystem isolation decisions that the
// deployment audit called out, plus the writable-location boundary.
func TestUnitIsolationProfile(t *testing.T) {
	sections := parseUnit(t)
	get := func(section, key string) string {
		v := directives(t, sections, section, key)
		if len(v) == 0 {
			t.Fatalf("[%s] missing %s", section, key)
		}
		return v[0]
	}
	if ph := get("Service", "ProtectHome"); strings.EqualFold(ph, "yes") {
		t.Fatal("ProtectHome=yes makes the service user's AegisKeys data under /home inaccessible; use read-only (dial-only) and tighten via drop-in when the socket lives outside /home")
	}
	if get("Service", "Restart") != "on-failure" {
		t.Fatal("Restart=on-failure is the contracted policy")
	}
	for _, key := range []string{"runtimedirectory", "statedirectory"} {
		if !has(sections, "Service", key) {
			t.Fatalf("[Service] missing %s: systemd must pre-create runtime/state dirs with the service identity", key)
		}
	}
	rw := join(directives(t, sections, "Service", "ReadWritePaths"))
	for _, p := range []string{"/run/seqpass", "/var/lib/seqpass"} {
		if !strings.Contains(rw, p) {
			t.Fatalf("ReadWritePaths missing %s: %q", p, rw)
		}
	}
}

// TestUnitSystemdAnalyzeVerify runs the real systemd parser when it is
// available on the host and fails on reported errors. Skipped where
// systemd-analyze does not exist (the parse tests above remain the
// portable gate).
func TestUnitSystemdAnalyzeVerify(t *testing.T) {
	path, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available on this host")
	}
	abs, err := filepath.Abs(unitFile)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(abs)
	out, err := exec.Command(path, "verify", abs).CombinedOutput()
	var defects []string
	for _, line := range strings.Split(string(out), "\n") {
		// Only our unit's lines matter; systemd-analyze also surfaces
		// unrelated noise from the host's installed units.
		if !strings.Contains(line, base) {
			continue
		}
		// A missing binary on the inspecting host is a deployment
		// prerequisite, not a unit defect.
		if strings.Contains(line, "not executable") || strings.Contains(line, "not installed") {
			continue
		}
		defects = append(defects, line)
	}
	if err != nil && len(defects) == 0 {
		// Non-zero exit with only filtered lines (e.g. the not-executable
		// prerequisite) is still acceptable: the placement/parse checks ran.
		t.Skipf("systemd-analyze exited %v with only prerequisite lines:\n%s", err, out)
	}
	if len(defects) > 0 {
		t.Fatalf("systemd-analyze verify reported unit defects:\n%s", strings.Join(defects, "\n"))
	}
}
