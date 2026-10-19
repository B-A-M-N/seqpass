package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Load must resolve the installation-wide configuration with the documented
// precedence: configuration file over defaults, environment over the file,
// and the per-UID home defaults only when no system-scoped installation
// exists. The tests below pin the loader's own layer; the environment layer
// is ApplyEnv's, which the other tests in this file already cover.

func writeConfigFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A system-scoped configuration file resolves the system paths as the base
// and overlays exactly the fields the file sets.
func TestLoadSystemScopedConfigOverlaysFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, `{
		"socket_path": "/run/seqpass/broker.sock",
		"intake_socket": "/run/seqpass/broker.sock.intake",
		"vault": "aegiskeys",
		"agent_uids": [2001, 2002],
		"socket_group": "seqpass-agents",
		"default_op_ttl": "10m"
	}`)
	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.SocketPath != "/run/seqpass/broker.sock" {
		t.Fatalf("socket = %q", d.SocketPath)
	}
	if d.IntakeSocket != "/run/seqpass/broker.sock.intake" {
		t.Fatalf("intake = %q", d.IntakeSocket)
	}
	// The untouched system default must survive: /run/seqpass/broker.sock.admin.
	if d.AdminSocket != "/run/seqpass/broker.sock.admin" {
		t.Fatalf("admin = %q", d.AdminSocket)
	}
	if d.DBPath != filepath.Join(SystemStateDir, "metadata.db") {
		t.Fatalf("db = %q", d.DBPath)
	}
	if d.VaultType != VaultAegisKeys {
		t.Fatalf("vault = %q", d.VaultType)
	}
	if len(d.AgentUIDs) != 2 || d.AgentUIDs[0] != 2001 || d.AgentUIDs[1] != 2002 {
		t.Fatalf("agent uids = %v", d.AgentUIDs)
	}
	if d.SocketGroup != "seqpass-agents" {
		t.Fatalf("socket group = %q", d.SocketGroup)
	}
	if d.DefaultOpTTL != 10*time.Minute {
		t.Fatalf("op ttl = %s", d.DefaultOpTTL)
	}
}

// A malformed configuration is a hard error, never a silent fallback to the
// defaults: the surfaces that consult the file must not silently disagree.
func TestLoadFailsClosedOnMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{"broken json", "{\"socket_path\": ", "malformed configuration"},
		{"unknown field", `{"socket_path": "/run/x.sock", "password": "hunter2"}`, "malformed configuration"},
		{"unknown vault", `{"vault": "sqlite"}`, "unknown vault"},
		{"unknown assurance", `{"assurance": "probably-fine"}`, "unknown assurance mode"},
		{"duplicate uid", `{"agent_uids": [2001, 2001]}`, "duplicate UID"},
		{"negative ops", `{"max_concurrent_ops": -1}`, "negative"},
		{"bad ttl", `{"default_op_ttl": "soon"}`, "invalid default_op_ttl"},
	} {
		path := writeConfigFile(t, dir, tc.content)
		_, err := Load(path)
		if err == nil {
			t.Errorf("%s: Load accepted a malformed configuration", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to contain %q", tc.name, err, tc.want)
		}
	}
}

// An explicitly named file that is missing is an error. The environment
// override behaves like an explicit file: it must never silently fall back.
func TestLoadRefusesMissingExplicitConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := Load(missing); err == nil {
		t.Fatal("Load accepted a missing explicit configuration file")
	}
	t.Setenv(EnvConfig, missing)
	if _, err := Load(""); err == nil {
		t.Fatal("Load accepted a missing environment-configured file")
	}
	t.Setenv(EnvConfigAlt, missing)
	if _, err := Load(""); err == nil {
		t.Fatal("Load accepted a missing file named by the alt environment variable")
	}
}

// Without a configuration file the loader falls back to the single-UID dev
// defaults unchanged. This is the contract the existing tests and dev
// workflows rely on.
func TestLoadDevFallbackUnchanged(t *testing.T) {
	t.Setenv(EnvConfig, "")
	t.Setenv(EnvConfigAlt, "")
	if _, err := os.Stat(SystemConfigPath); err == nil {
		t.Skipf("%s exists on this machine; dev fallback not testable", SystemConfigPath)
	}
	d, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	if d.DBPath != want.DBPath || d.SocketPath != want.SocketPath ||
		d.AdminSocket != want.AdminSocket || d.IntakeSocket != want.IntakeSocket {
		t.Fatalf("dev fallback = %+v, want the ~/.seqpass defaults %+v", d, want)
	}
}

// ConfigPath honors both environment variable spellings, in documented
// order, and defaults to the system path.
func TestConfigPathPrecedence(t *testing.T) {
	if got := ConfigPath(); got != SystemConfigPath {
		t.Fatalf("ConfigPath with no environment = %q", got)
	}
	t.Setenv(EnvConfig, "/a/config.json")
	t.Setenv(EnvConfigAlt, "/b/config.json")
	if got := ConfigPath(); got != "/a/config.json" {
		t.Fatalf("ConfigPath = %q, want the primary override", got)
	}
	os.Unsetenv(EnvConfig)
	if got := ConfigPath(); got != "/b/config.json" {
		t.Fatalf("ConfigPath = %q, want the alt override", got)
	}
}

// RenderConfig must serialize endpoints, vault and identities only. A
// credential or session token has no field to land in, and the rendered
// form must round-trip through Load.
func TestRenderConfigRoundTripWithoutSecrets(t *testing.T) {
	d := Defaults()
	d.VaultType = VaultAegisKeys
	d.AssuranceMode = AssuranceIsolated
	d.AgentUIDs = []uint32{2001}
	d.IntakeUIDs = []uint32{1000}
	d.AdminUIDs = []uint32{1000}
	d.SocketGroup = "seqpass-agents"
	d.HostSocket = "/run/seqpass/host.sock"
	raw, err := RenderConfig(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "secret", "password", "credential"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Errorf("rendered config mentions %q:\n%s", forbidden, raw)
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SocketPath != d.SocketPath || got.AdminSocket != d.AdminSocket ||
		got.IntakeSocket != d.IntakeSocket || got.HostSocket != d.HostSocket ||
		got.VaultType != d.VaultType || got.SocketGroup != d.SocketGroup ||
		len(got.AgentUIDs) != 1 || got.AgentUIDs[0] != 2001 {
		t.Fatalf("round trip lost configuration: %+v vs %+v", got, d)
	}
}
