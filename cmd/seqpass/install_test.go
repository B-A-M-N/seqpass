package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/config"
)

// The canonical pi snippet used by the write-behavior tests.
func piSnippetTest() []byte {
	b, err := piSnippet("/run/s/i.sock", "/run/s/h.sock", "/run/s/b.sock")
	if err != nil {
		panic(err)
	}
	return b
}

// An unknown adapter is refused with the valid choices named, so the
// operator is never left guessing what install accepts.
func TestAdapterSnippetRejectsUnknownAdapter(t *testing.T) {
	for _, bad := range []string{"", "claude", "codex", "OPCODE", "pi;rm", ".."} {
		_, err := adapterSnippet(bad, "/i", "/h", "/b")
		if err == nil {
			t.Errorf("adapterSnippet(%q) accepted an unknown adapter", bad)
			continue
		}
		if !strings.Contains(err.Error(), "opencode, pi, mcp") {
			t.Errorf("adapterSnippet(%q) error does not name the valid adapters: %v", bad, err)
		}
	}
	for _, good := range []string{"opencode", "pi", "mcp"} {
		if _, err := adapterSnippet(good, "/i", "/h", "/b"); err != nil {
			t.Errorf("adapterSnippet(%q) refused a valid adapter: %v", good, err)
		}
	}
}

// The opencode/pi adapters dial the intake and host sockets; an
// installation that has not declared them must be refused here, not
// produce a config that fails later with a worse error.
func TestAdapterSnippetRefusesMissingRequiredEndpoints(t *testing.T) {
	for _, adapter := range []string{"opencode", "pi"} {
		if _, err := adapterSnippet(adapter, "", "/h", "/b"); err == nil {
			t.Errorf("%s accepted a missing intake socket", adapter)
		}
		if _, err := adapterSnippet(adapter, "/i", "", "/b"); err == nil {
			t.Errorf("%s accepted a missing host socket", adapter)
		}
	}
	// MCP only dials the agent socket, so it must not require the others.
	if _, err := adapterSnippet("mcp", "", "", "/b.sock"); err != nil {
		t.Errorf("mcp refused with only the agent socket: %v", err)
	}
}

// The generated snippets carry endpoints only: session IDs and tokens are
// minted by host.register at runtime and must never be persisted by install.
func TestInstallSnippetsCarryEndpointsOnly(t *testing.T) {
	oc, err := opencodeSnippet("/run/s/i.sock", "/run/s/h.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"intakeSocket", "hostSocket", "/run/s/i.sock", "/run/s/h.sock"} {
		if !strings.Contains(string(oc), want) {
			t.Errorf("opencode snippet missing %q:\n%s", want, oc)
		}
	}
	for _, forbidden := range []string{"sessionToken", "sessionID", "token", "credential"} {
		if strings.Contains(strings.ToLower(string(oc)), strings.ToLower(forbidden)) {
			t.Errorf("opencode snippet mentions %q:\n%s", forbidden, oc)
		}
	}

	pi, err := piSnippet("/run/s/i.sock", "/run/s/h.sock", "/run/s/b.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"intakeSocket", "hostSocket", "agentSocket", "/run/s/b.sock"} {
		if !strings.Contains(string(pi), want) {
			t.Errorf("pi snippet missing %q:\n%s", want, pi)
		}
	}
	if strings.Contains(strings.ToLower(string(pi)), "sessiontoken") {
		t.Errorf("pi snippet carries a session token:\n%s", pi)
	}

	mcp, err := mcpSnippet("/run/s/b.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mcp), "mcp") || !strings.Contains(string(mcp), "SEQ_PASS_SOCKET") {
		t.Errorf("mcp stanza does not invoke `mcp` with the pinned socket:\n%s", mcp)
	}
}

// install is idempotent: writing identical content twice leaves the same
// file and reports it as already configured.
func TestInstallIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pi.json")
	if err := writeAdapterConfig(target, piSnippetTest(), false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAdapterConfig(target, piSnippetTest(), false); err != nil {
		t.Fatalf("second identical install refused: %v", err)
	}
	second, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("idempotent install changed the file:\n%s\nvs\n%s", first, second)
	}
}

// A differing config is refused without --force, and --force replaces it.
// This pins the negative control: install must never silently repair a
// stale endpoint into a new one.
func TestInstallRefusesDifferingConfigWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pi.json")
	if err := os.WriteFile(target, []byte(`{"intakeSocket": "/old/intake.sock"}`), 0600); err != nil {
		t.Fatal(err)
	}
	snippet := piSnippetTest()
	if err := writeAdapterConfig(target, snippet, false); err == nil {
		t.Fatal("install overwrote a differing config without --force")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"intakeSocket": "/old/intake.sock"}` {
		t.Fatalf("refused install still modified the file:\n%s", got)
	}
	if err := writeAdapterConfig(target, snippet, true); err != nil {
		t.Fatalf("--force refused to overwrite: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(snippet) {
		t.Fatalf("--force did not write the new config:\n%s", got)
	}
}

// The written file (and its parent directory) must never become group- or
// world-readable: it names the installation's sockets even though it
// carries no credential.
func TestInstallWritesOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "pi.json")
	if err := writeAdapterConfig(target, piSnippetTest(), false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		t.Fatalf("config file is readable by other identities: %v", fi.Mode().Perm())
	}
}

// The mcp stanza registers this binary as an MCP server that launches the
// same installation: absolute command path and the `mcp` subcommand.
func TestMCPStanzaUsesThisBinary(t *testing.T) {
	stanza, err := mcpSnippet("/run/s/b.sock")
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if exe != "" && !strings.Contains(string(stanza), exe) {
		t.Errorf("mcp stanza does not reference this binary (%s):\n%s", exe, stanza)
	}
}

// The endpoint environment layer is part of the shared resolution contract:
// explicit flag > environment > config file > defaults. install must honor
// it, or it can publish a config-file endpoint while the broker actually
// listens on the environment override — the adapter would dial a different
// installation than the one serving traffic.
func TestInstallHonorsEndpointEnvironment(t *testing.T) {
	t.Setenv(config.EnvSocket, "/run/env/broker.sock")
	t.Setenv(config.EnvIntakeSocket, "/run/env/intake.sock")

	mcp, err := mcpSnippet(loadBaseForTest(t).SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mcp), "/run/env/broker.sock") {
		t.Fatalf("mcp stanza ignored the SEQ_PASS_SOCKET environment override:\n%s", mcp)
	}

	pi, err := piSnippet("/run/env/intake.sock", "/run/env/host.sock", "/run/env/broker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pi), "/run/env/intake.sock") {
		t.Fatalf("pi snippet lost the environment-resolved intake socket:\n%s", pi)
	}
}

// loadBaseForTest resolves the deployment the same way installCmd does
// (config file + endpoint environment), isolated from the machine's real
// configuration file.
func loadBaseForTest(t *testing.T) config.Deployment {
	t.Helper()
	t.Setenv(config.EnvConfig, "")
	if os.Geteuid() != 0 {
		d, err := config.Load("")
		if err != nil {
			t.Fatal(err)
		}
		d.ApplyEnv()
		return d
	}
	d := config.Defaults()
	d.ApplyEnv()
	return d
}

// installCmd's flag defaults must come from the environment-aware base, so
// a bare `seqpass install mcp` emits the stanza for the installation that
// is actually listening. This drives the real flag-default path.
func TestInstallCmdDefaultsWithEnvironment(t *testing.T) {
	t.Setenv(config.EnvSocket, "/run/env/broker.sock")
	out := captureStdout(t, func() {
		installCmd([]string{"mcp"})
	})
	if !strings.Contains(out, "/run/env/broker.sock") {
		t.Fatalf("install mcp ignored the socket environment override:\n%s", out)
	}
}
