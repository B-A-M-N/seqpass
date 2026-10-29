package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemDefaultsSeparateAgentAndTrustedSocketDirs(t *testing.T) {
	d := systemDefaults()
	agentDir := filepath.Dir(d.SocketPath)
	if agentDir == filepath.Dir(d.AdminSocket) || agentDir == filepath.Dir(d.IntakeSocket) {
		t.Fatalf("agent socket directory %q must be separate from trusted sockets (%q, %q)", agentDir, d.AdminSocket, d.IntakeSocket)
	}
	if filepath.Dir(d.AdminSocket) != filepath.Dir(d.IntakeSocket) {
		t.Fatalf("admin and intake should share the trusted socket directory: %q, %q", d.AdminSocket, d.IntakeSocket)
	}
}

func TestParseUIDsFailsClosed(t *testing.T) {
	for _, bad := range []string{"abc", "1001,,1002", "1001,abc", ",1001", "1001,1001", "-1", "99999999999999999999"} {
		if _, err := ParseUIDs(bad); err == nil {
			t.Fatalf("ParseUIDs(%q) accepted malformed input", bad)
		}
	}
	if got, err := ParseUIDs("   "); err != nil || got != nil {
		t.Fatalf("blank list = %v, %v; want nil, nil", got, err)
	}
	got, err := ParseUIDs(" 1001 , 1002,1003 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1001 || got[1] != 1002 || got[2] != 1003 {
		t.Fatalf("parsed %v", got)
	}
}

// A production vault may never be paired with an unverifiable topology, and a
// development vault may never run without the explicit acknowledgement.
func TestValidateRefusesUnsafeCombinations(t *testing.T) {
	prod := Defaults()
	prod.VaultType = VaultAegisKeys
	// A production vault defaults to an isolated claim, which needs the
	// identities that make the claim provable.
	prod.AgentUIDs = []uint32{2001}
	prod.IntakeUIDs = []uint32{1000}
	prod.AdminUIDs = []uint32{1000}
	prod.SocketGroup = "seqpass-agents"
	prod.AegisKeysResolveHelper = "/usr/local/bin/seqpass"
	prod.AegisKeysResolveHelperSHA256 = strings.Repeat("a", 64)
	if err := prod.Validate(); err != nil {
		t.Fatalf("production default rejected: %v", err)
	}
	prod.AssuranceMode = AssuranceBestEffort
	if err := prod.Validate(); err == nil {
		t.Fatal("production vault accepted a best-effort topology")
	}

	// The identities are not optional decoration: without them the isolated
	// claim cannot be demonstrated, so the configuration is refused.
	bare := Defaults()
	bare.VaultType = VaultAegisKeys
	err := bare.Validate()
	if err == nil {
		t.Fatal("production vault accepted without the identities that prove isolation")
	}
	if !strings.Contains(err.Error(), "agent-uid") {
		t.Fatalf("refusal does not name the missing input: %v", err)
	}

	relayOnly := Defaults()
	relayOnly.VaultType = VaultRelayOnly
	relayOnly.AgentUIDs = []uint32{2001}
	relayOnly.IntakeUIDs = []uint32{1000}
	relayOnly.AdminUIDs = []uint32{1000}
	relayOnly.SocketGroup = "seqpass-agents"
	if err := relayOnly.Validate(); err != nil {
		t.Fatalf("isolated relay-only production mode rejected: %v", err)
	}
	if !relayOnly.IsProductionVault() || relayOnly.EffectiveAssurance() != AssuranceIsolated {
		t.Fatal("relay-only did not retain production isolated assurance")
	}
	relayOnly.AssuranceMode = AssuranceBestEffort
	if err := relayOnly.Validate(); err == nil {
		t.Fatal("relay-only accepted a best-effort topology")
	}
	relayOnly.AssuranceMode = AssuranceIsolated
	relayOnly.Dev = true
	if err := relayOnly.Validate(); err == nil {
		t.Fatal("relay-only accepted the memory-test --dev acknowledgement")
	}

	dev := Defaults()
	dev.VaultType = VaultMemoryTest
	if err := dev.Validate(); err == nil {
		t.Fatal("memory vault accepted without --dev")
	}
	dev.Dev = true
	if err := dev.Validate(); err != nil {
		t.Fatalf("explicit development vault rejected: %v", err)
	}

	missing := Defaults()
	if err := missing.Validate(); err == nil {
		t.Fatal("missing vault accepted")
	}

	unknown := Defaults()
	unknown.VaultType = "sqlite"
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown vault accepted")
	}

	badMode := Defaults()
	badMode.VaultType = VaultAegisKeys
	badMode.AssuranceMode = "probably-fine"
	if err := badMode.Validate(); err == nil {
		t.Fatal("unknown assurance mode accepted")
	}
}

// An isolated claim without the identities to prove it is not a valid
// configuration; "we will add the agent UIDs later" is how a deployment ends
// up unable to demonstrate denial.
func TestValidateIsolatedRequiresIdentities(t *testing.T) {
	d := Defaults()
	d.VaultType = VaultAegisKeys
	d.AssuranceMode = AssuranceIsolated
	if err := d.Validate(); err == nil {
		t.Fatal("isolated topology accepted without agent/intake identities")
	}
	d.AgentUIDs = []uint32{2001}
	d.IntakeUIDs = []uint32{1000}
	d.SocketGroup = "seqpass-agents"
	d.AegisKeysResolveHelper = "/usr/local/bin/seqpass"
	d.AegisKeysResolveHelperSHA256 = strings.Repeat("a", 64)
	if err := d.Validate(); err != nil {
		t.Fatalf("complete isolated topology rejected: %v", err)
	}
}

// The broker and the doctor derive the topology and the doctor inputs from the
// same function, so a pre-flight verdict cannot be about a different system
// than the one that serves traffic.
func TestEffectiveAssuranceDefaultsByVault(t *testing.T) {
	d := Defaults()
	d.VaultType = VaultAegisKeys
	if got := d.EffectiveAssurance(); got != AssuranceIsolated {
		t.Fatalf("production default assurance = %q, want isolated", got)
	}
	d.VaultType = VaultMemoryTest
	if got := d.EffectiveAssurance(); got != AssuranceBestEffort {
		t.Fatalf("development default assurance = %q, want best-effort", got)
	}
	d.AssuranceMode = AssuranceIsolated
	if got := d.EffectiveAssurance(); got != AssuranceIsolated {
		t.Fatalf("explicit assurance ignored: %q", got)
	}
}

func TestIsolationCarriesEveryProtectedObject(t *testing.T) {
	d := Defaults()
	d.VaultType = VaultAegisKeys
	d.AssuranceMode = AssuranceIsolated
	d.AgentUIDs = []uint32{2001}
	d.IntakeUIDs = []uint32{1000}
	d.AdminUIDs = []uint32{1000}
	d.SocketGroup = "seqpass-agents"
	d.HostSocket = "/run/seqpass/host/broker.sock"
	d.AegisKeysSocket = "/run/aegiskeys/keys.sock"
	d.AegisKeysDir = "/etc/aegiskeys"

	iso := d.Isolation(4242)
	if iso.AssuranceMode != AssuranceIsolated {
		t.Fatalf("assurance = %q", iso.AssuranceMode)
	}
	if iso.BrokerUID != uint32(os.Geteuid()) {
		t.Fatalf("broker uid = %d", iso.BrokerUID)
	}
	if iso.AgentSocket != d.SocketPath || iso.AdminSocket != d.AdminSocket ||
		iso.IntakeSocket != d.IntakeSocket || iso.HostSocket != d.HostSocket ||
		iso.DBPath != d.DBPath || iso.AegisKeysDir != d.AegisKeysDir ||
		iso.AegisKeysSocket != d.AegisKeysSocket {
		t.Fatalf("protected object mapping lost a path: %+v", iso)
	}
	if iso.BrokerPID != 4242 {
		t.Fatalf("broker pid = %d", iso.BrokerPID)
	}
	if len(iso.AgentUIDs) != 1 || iso.AgentUIDs[0] != 2001 {
		t.Fatalf("agent uids = %v", iso.AgentUIDs)
	}
}

// Only endpoints may be overridden from the environment. An attacker-supplied
// environment must not be able to widen who is authorized.
func TestApplyEnvOnlyOverridesEndpoints(t *testing.T) {
	t.Setenv(EnvSocket, "/tmp/env.sock")
	t.Setenv(EnvAdminSocket, "/tmp/env.admin.sock")
	t.Setenv(EnvIntakeSocket, "/tmp/env.intake.sock")
	d := Defaults()
	d.AgentUIDs = []uint32{2001}
	d.AdminUIDs = []uint32{1000}
	d.ApplyEnv()
	if d.SocketPath != "/tmp/env.sock" || d.AdminSocket != "/tmp/env.admin.sock" || d.IntakeSocket != "/tmp/env.intake.sock" {
		t.Fatalf("endpoint overrides not applied: %+v", d)
	}
	if len(d.AgentUIDs) != 1 || d.AgentUIDs[0] != 2001 || len(d.AdminUIDs) != 1 || d.AdminUIDs[0] != 1000 {
		t.Fatalf("environment changed identities: %+v", d)
	}
}

func TestStateDirFollowsDatabasePath(t *testing.T) {
	dir := t.TempDir()
	d := Defaults()
	d.DBPath = filepath.Join(dir, "sub", "meta.db")
	if got := d.StateDir(); got != filepath.Join(dir, "sub") {
		t.Fatalf("StateDir = %q", got)
	}
	d.DBPath = ""
	if got := d.StateDir(); got != "" {
		t.Fatalf("empty database path produced %q", got)
	}
}
