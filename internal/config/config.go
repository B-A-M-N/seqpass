// Package config centralizes SeqPass deployment configuration: the paths,
// identities and topology facts that the broker, the admin CLI, `seqpass
// doctor` and `seqpass init` all have to agree on.
//
// A disagreement between two surfaces is a security problem, not a cosmetic
// one: if the broker is configured with one agent identity set while the
// doctor checks another, the doctor's verdict is about a different system
// than the one that will serve traffic. So there is exactly one parser for
// the identity lists, one defaults function, and one mapping from deployment
// values to the isolation doctor's inputs.
//
// This package deliberately does not import the daemon. The daemon owns the
// authoritative topology validation and the live boundary check; this package
// owns input-level rules so an operator-facing command can fail early with the
// same rules instead of inventing its own.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/isolation"
)

// Assurance labels. They mirror the daemon's accepted values; the broker
// remains the authority that validates and acts on them.
const (
	AssuranceIsolated   = "isolated"
	AssuranceBestEffort = "best-effort"

	VaultAegisKeys  = "aegiskeys"
	VaultMemoryTest = "memory-test"
)

// Env variable names. The socket overrides exist so a harness or a
// non-default installation can point its client at the right endpoint
// without repeating every path on the command line.
const (
	EnvSocket       = "SEQ_PASS_SOCKET"
	EnvAdminSocket  = "SEQ_PASS_ADMIN_SOCKET"
	EnvIntakeSocket = "SEQ_PASS_INTAKE_SOCKET"
)

// Installation-wide configuration (objective §8). The agent, the operator and
// the broker run under different UIDs; each of them resolves $HOME
// differently, so a home-relative default cannot be shared configuration. A
// single root-owned file carries the endpoints every surface must agree on.
const (
	// SystemConfigPath is the installation-wide configuration file. It
	// contains endpoints, the vault type and UID lists — never a secret.
	SystemConfigPath = "/etc/seqpass/config.json"

	// SystemSocketDir and SystemStateDir are the secure system defaults for
	// a multi-UID installation: sockets under /run (tmpfs, wiped on boot and
	// recreated by the broker), broker-owned durable state under /var/lib.
	SystemSocketDir = "/run/seqpass"
	SystemStateDir  = "/var/lib/seqpass"
)

// Config-file environment override. SEQ_PASS_CONFIG follows the package's
// existing endpoint-variable spelling. It must point at a file, and a
// missing or malformed explicit file is an error, never a silent fallback.
const EnvConfig = "SEQ_PASS_CONFIG"

// systemDefaults returns the multi-UID installation defaults: sockets under
// /run/seqpass and broker state under /var/lib/seqpass. They are only used
// when the installation is system-scoped (see Load), because /run and
// /var/lib are not writable by an unprivileged development user.
func systemDefaults() Deployment {
	sock := filepath.Join(SystemSocketDir, "broker.sock")
	return Deployment{
		DBPath:       filepath.Join(SystemStateDir, "metadata.db"),
		SocketPath:   sock,
		AdminSocket:  sock + ".admin",
		IntakeSocket: sock + ".intake",
	}
}

// configFile mirrors the JSON schema of the installation-wide configuration.
// Pointer fields distinguish "absent" from "zero" so loading a sparse file
// never zeroes a path that the defaults already resolved.
type configFile struct {
	DBPath        *string  `json:"db_path,omitempty"`
	SocketPath    *string  `json:"socket_path,omitempty"`
	AdminSocket   *string  `json:"admin_socket,omitempty"`
	IntakeSocket  *string  `json:"intake_socket,omitempty"`
	HostSocket    *string  `json:"host_socket,omitempty"`
	VaultType     *string  `json:"vault,omitempty"`
	Assurance     *string  `json:"assurance,omitempty"`
	Dev           *bool    `json:"dev,omitempty"`
	AgentUIDs     []uint32 `json:"agent_uids,omitempty"`
	AdminUIDs     []uint32 `json:"admin_uids,omitempty"`
	IntakeUIDs    []uint32 `json:"intake_uids,omitempty"`
	SocketGroup   *string  `json:"socket_group,omitempty"`
	IntakeGroup   *string  `json:"intake_group,omitempty"`
	AegisSocket   *string  `json:"aegiskeys_socket,omitempty"`
	AegisDir      *string  `json:"aegiskeys_dir,omitempty"`
	MaxConcOps    *int     `json:"max_concurrent_ops,omitempty"`
	DefaultTTL    *string  `json:"default_op_ttl,omitempty"`
	AutoExecute   *bool    `json:"auto_execute,omitempty"`
	NoAutoDeliver *bool    `json:"no_relay_auto_deliver,omitempty"`
}

// ConfigPath resolves which configuration file governs this installation:
// the environment override when set, otherwise /etc/seqpass/config.json.
func ConfigPath() string {
	for _, name := range []string{EnvConfig} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return SystemConfigPath
}

// Load resolves the installation-wide Deployment.
//
// Precedence, from strongest to weakest: explicit flags (applied by the
// caller after Load) > endpoint environment (ApplyEnv) > configuration file
// > defaults. The base defaults are system paths (/run, /var/lib) when the
// process is root or the configuration file exists — those are the markers
// of a real multi-UID installation — and the per-UID home directory
// otherwise, which keeps single-UID development working unchanged.
//
// The function fails closed: a configuration file that exists but cannot be
// read or parsed is an error, and so is an explicitly named file that is
// missing. Load never invents a configuration the operator did not write.
func Load(explicitPath string) (Deployment, error) {
	path := explicitPath
	envNamed := false
	if path == "" {
		for _, name := range []string{EnvConfig} {
			if v := os.Getenv(name); v != "" {
				path = v
				envNamed = true
				break
			}
		}
	}
	if path == "" {
		path = SystemConfigPath
	}

	if fi, err := os.Stat(path); err == nil {
		if fi.IsDir() {
			return Deployment{}, fmt.Errorf("configuration path %s is a directory", path)
		}
		// A system-scoped configuration file is exactly the signal that
		// this is a multi-UID installation: resolve the system paths as
		// the base and let the file refine them.
		d := systemDefaults()
		if err := applyConfigFile(&d, path); err != nil {
			return Deployment{}, err
		}
		return d, nil
	} else if !os.IsNotExist(err) {
		return Deployment{}, fmt.Errorf("cannot inspect configuration %s: %w", path, err)
	} else if explicitPath != "" || envNamed {
		// The operator (or the environment) named this file; pretending
		// it does not exist would silently reconfigure the installation
		// to the per-UID default.
		return Deployment{}, fmt.Errorf("configuration file %s not found", path)
	}

	// No configuration file anywhere. Root means the installation is
	// system-scoped (services do not share root's home directory layout
	// with the agent and operator UIDs), so use the system paths; the
	// unprivileged single-UID development case keeps ~/.seqpass.
	if os.Geteuid() == 0 {
		return systemDefaults(), nil
	}
	return Defaults(), nil
}

// applyConfigFile parses the installation configuration and overlays it onto
// d. Every field that the file can express is validated here: a bad value is
// a hard error, because a half-applied configuration is worse than a refused
// one — the surfaces that read it must not disagree.
func applyConfigFile(d *Deployment, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read configuration %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fc configFile
	if err := dec.Decode(&fc); err != nil {
		return fmt.Errorf("malformed configuration %s: %w", path, err)
	}
	if fc.DBPath != nil {
		d.DBPath = *fc.DBPath
	}
	if fc.SocketPath != nil {
		d.SocketPath = *fc.SocketPath
	}
	if fc.AdminSocket != nil {
		d.AdminSocket = *fc.AdminSocket
	}
	if fc.IntakeSocket != nil {
		d.IntakeSocket = *fc.IntakeSocket
	}
	if fc.HostSocket != nil {
		d.HostSocket = *fc.HostSocket
	}
	if fc.VaultType != nil {
		if err := validateVault(*fc.VaultType); err != nil {
			return fmt.Errorf("configuration %s: %w", path, err)
		}
		d.VaultType = *fc.VaultType
	}
	if fc.Assurance != nil {
		switch *fc.Assurance {
		case "", AssuranceIsolated, AssuranceBestEffort:
		default:
			return fmt.Errorf("configuration %s: unknown assurance mode %q (want %s or %s)", path, *fc.Assurance, AssuranceIsolated, AssuranceBestEffort)
		}
		d.AssuranceMode = *fc.Assurance
	}
	if fc.Dev != nil {
		d.Dev = *fc.Dev
	}
	uidFields := []struct {
		name string
		uids []uint32
		set  func([]uint32)
	}{
		{"agent_uids", fc.AgentUIDs, func(u []uint32) { d.AgentUIDs = u }},
		{"admin_uids", fc.AdminUIDs, func(u []uint32) { d.AdminUIDs = u }},
		{"intake_uids", fc.IntakeUIDs, func(u []uint32) { d.IntakeUIDs = u }},
	}
	for _, f := range uidFields {
		if f.uids == nil {
			continue
		}
		seen := map[uint32]bool{}
		for _, uid := range f.uids {
			if seen[uid] {
				return fmt.Errorf("configuration %s: duplicate UID %d in %s", path, uid, f.name)
			}
			seen[uid] = true
		}
		f.set(f.uids)
	}
	if fc.SocketGroup != nil {
		d.SocketGroup = *fc.SocketGroup
	}
	if fc.IntakeGroup != nil {
		d.IntakeGroup = *fc.IntakeGroup
	}
	if fc.AegisSocket != nil {
		d.AegisKeysSocket = *fc.AegisSocket
	}
	if fc.AegisDir != nil {
		d.AegisKeysDir = *fc.AegisDir
	}
	if fc.MaxConcOps != nil {
		if *fc.MaxConcOps < 0 {
			return fmt.Errorf("configuration %s: max_concurrent_ops cannot be negative", path)
		}
		d.MaxConcurrentOps = *fc.MaxConcOps
	}
	if fc.DefaultTTL != nil {
		ttl, err := time.ParseDuration(*fc.DefaultTTL)
		if err != nil {
			return fmt.Errorf("configuration %s: invalid default_op_ttl %q: %w", path, *fc.DefaultTTL, err)
		}
		if ttl < 0 {
			return fmt.Errorf("configuration %s: default_op_ttl cannot be negative", path)
		}
		d.DefaultOpTTL = ttl
	}
	if fc.AutoExecute != nil {
		d.AutoExecute = *fc.AutoExecute
	}
	if fc.NoAutoDeliver != nil {
		d.NoRelayAutoDeliver = *fc.NoAutoDeliver
	}
	return nil
}

func validateVault(v string) error {
	switch v {
	case VaultAegisKeys, VaultMemoryTest:
		return nil
	default:
		return fmt.Errorf("unknown vault %q (want %s or %s)", v, VaultAegisKeys, VaultMemoryTest)
	}
}

// RenderConfig renders the deployment as the JSON form of the
// installation-wide configuration file. Only endpoints, the vault type and
// identity lists are serialized: a credential or a session token must never
// reach this structure, and init writes exactly this rendering.
func RenderConfig(d Deployment) ([]byte, error) {
	fc := configFile{
		DBPath:       &d.DBPath,
		SocketPath:   &d.SocketPath,
		AdminSocket:  &d.AdminSocket,
		IntakeSocket: &d.IntakeSocket,
	}
	if d.HostSocket != "" {
		fc.HostSocket = &d.HostSocket
	}
	if d.VaultType != "" {
		fc.VaultType = &d.VaultType
	}
	if d.AssuranceMode != "" {
		fc.Assurance = &d.AssuranceMode
	}
	if d.Dev {
		fc.Dev = &d.Dev
	}
	fc.AgentUIDs = d.AgentUIDs
	fc.AdminUIDs = d.AdminUIDs
	fc.IntakeUIDs = d.IntakeUIDs
	if d.SocketGroup != "" {
		fc.SocketGroup = &d.SocketGroup
	}
	if d.IntakeGroup != "" {
		fc.IntakeGroup = &d.IntakeGroup
	}
	if d.AegisKeysSocket != "" {
		fc.AegisSocket = &d.AegisKeysSocket
	}
	if d.AegisKeysDir != "" {
		fc.AegisDir = &d.AegisKeysDir
	}
	if d.MaxConcurrentOps > 0 {
		fc.MaxConcOps = &d.MaxConcurrentOps
	}
	if d.DefaultOpTTL != 0 {
		s := d.DefaultOpTTL.String()
		fc.DefaultTTL = &s
	}
	if d.AutoExecute {
		fc.AutoExecute = &d.AutoExecute
	}
	if d.NoRelayAutoDeliver {
		fc.NoAutoDeliver = &d.NoRelayAutoDeliver
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Deployment is the operator-supplied description of an installation.
// It is plain data: constructing one never touches the filesystem and never
// reads a secret.
type Deployment struct {
	DBPath      string
	SocketPath  string
	AdminSocket string
	HostSocket  string
	// IntakeSocket is the trusted human-side endpoint. It is owner-only by
	// default because a human who can write there can authorize operations.
	IntakeSocket string

	VaultType string
	// AssuranceMode is the topology claim. Empty means "let the broker
	// choose its default", which is isolated for a production vault.
	AssuranceMode string
	// Dev acknowledges the ephemeral development vault. Without it the
	// memory vault is refused, so a production deployment cannot silently
	// fall back to a vault that holds nothing durable.
	Dev bool

	AdminUIDs  []uint32
	AgentUIDs  []uint32
	IntakeUIDs []uint32

	SocketGroup string
	IntakeGroup string

	AegisKeysSocket string
	AegisKeysDir    string

	DefaultOpTTL     time.Duration
	MaxConcurrentOps int

	AutoExecute        bool
	NoRelayAutoDeliver bool
}

// EnvEndpoint returns the operator's environment override for one endpoint,
// or "" when unset. Every command resolves its socket the same way: an
// explicit flag, then the environment, then the shared default — so a client
// cannot end up on a different installation than the broker it was started
// with. Only endpoints are env-overridable, never identities.
func EnvEndpoint(name string) string {
	return os.Getenv(name)
}

// Defaults returns the single-user development installation under
// ~/.seqpass. It is what every command uses when no path is given, so the
// broker and the CLIs that talk to it cannot drift apart.
func Defaults() Deployment {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".seqpass")
	sock := filepath.Join(base, "broker.sock")
	return Deployment{
		DBPath:       filepath.Join(base, "metadata.db"),
		SocketPath:   sock,
		AdminSocket:  sock + ".admin",
		IntakeSocket: sock + ".intake",
	}
}

// Paths returns the four default paths. It exists for the callers that only
// need the endpoints.
func Paths() (db, sock, admin, intake string) {
	d := Defaults()
	return d.DBPath, d.SocketPath, d.AdminSocket, d.IntakeSocket
}

// ParseUIDs parses a comma-separated UID list. It fails closed: a malformed,
// empty or duplicated token is an error, never a silently narrowed identity
// set, because dropping an agent UID would quietly widen who may reach the
// broker and dropping an admin UID would quietly change who may approve.
func ParseUIDs(s string) ([]uint32, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []uint32
	seen := map[uint32]bool{}
	for _, part := range strings.Split(s, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			return nil, fmt.Errorf("empty UID in list %q", s)
		}
		n, err := strconv.ParseUint(token, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid UID %q in list %q", token, s)
		}
		uid := uint32(n)
		if seen[uid] {
			return nil, fmt.Errorf("duplicate UID %d in list %q", uid, s)
		}
		seen[uid] = true
		out = append(out, uid)
	}
	return out, nil
}

// ApplyEnv overlays the endpoint environment overrides onto the deployment.
// It only fills endpoints, never identities: an attacker-controlled
// environment must not be able to widen who is authorized. Call it after the
// flags are parsed, before validation.
func (d *Deployment) ApplyEnv() {
	if v := EnvEndpoint(EnvSocket); v != "" {
		d.SocketPath = v
	}
	if v := EnvEndpoint(EnvAdminSocket); v != "" {
		d.AdminSocket = v
	}
	if v := EnvEndpoint(EnvIntakeSocket); v != "" {
		d.IntakeSocket = v
	}
}

// IsProductionVault reports whether the vault is the durable, encrypted
// production store rather than the development fixture.
func (d Deployment) IsProductionVault() bool {
	return d.VaultType == VaultAegisKeys
}

// EffectiveAssurance returns the topology the broker will actually run.
// A production vault defaults to isolated; anything else defaults to
// best-effort, which is always reported unverified.
func (d Deployment) EffectiveAssurance() string {
	if d.AssuranceMode != "" {
		return d.AssuranceMode
	}
	if d.IsProductionVault() {
		return AssuranceIsolated
	}
	return AssuranceBestEffort
}

// Validate applies the input-level rules shared by every surface. The broker
// re-validates and is authoritative; failing here only means the operator
// learns about a bad configuration before anything is created.
func (d Deployment) Validate() error {
	switch d.VaultType {
	case "":
		return fmt.Errorf("missing vault: choose %s (production) or %s with --dev (development only)", VaultAegisKeys, VaultMemoryTest)
	case VaultAegisKeys:
		if d.AssuranceMode == AssuranceBestEffort {
			return fmt.Errorf("a production (%s) vault cannot run a best-effort topology: best-effort is development-only and cannot be verified", VaultAegisKeys)
		}
	case VaultMemoryTest:
		if !d.Dev {
			return fmt.Errorf("the %s vault is a development fixture and requires an explicit --dev acknowledgement", VaultMemoryTest)
		}
	default:
		return fmt.Errorf("unknown vault %q (want %s or %s)", d.VaultType, VaultAegisKeys, VaultMemoryTest)
	}

	switch d.AssuranceMode {
	case "", AssuranceIsolated, AssuranceBestEffort:
	default:
		return fmt.Errorf("unknown assurance mode %q (want %s or %s)", d.AssuranceMode, AssuranceIsolated, AssuranceBestEffort)
	}

	if d.EffectiveAssurance() == AssuranceIsolated {
		if len(d.AgentUIDs) == 0 || len(d.IntakeUIDs) == 0 || d.SocketGroup == "" {
			return fmt.Errorf("isolated assurance requires explicit --agent-uid, --intake-uid and --socket-group")
		}
	}

	if d.MaxConcurrentOps < 0 {
		return fmt.Errorf("max-concurrent-ops cannot be negative")
	}
	if d.DefaultOpTTL < 0 {
		return fmt.Errorf("default-op-ttl cannot be negative")
	}
	return nil
}

// Isolation maps the deployment onto the isolation doctor's inputs. Both the
// broker and `seqpass doctor` use this one mapping, so a pre-flight verdict
// and a startup verdict are about the same system.
//
// brokerPID is the process whose /proc entry should be checked for
// agent-readable disclosure. Pass the running broker's PID, or 0 to skip the
// process-inspection check (for example when checking a configuration that is
// not running yet).
func (d Deployment) Isolation(brokerPID int) isolation.Config {
	return isolation.Config{
		AssuranceMode:   d.EffectiveAssurance(),
		BrokerUID:       uint32(os.Geteuid()),
		BrokerGID:       uint32(os.Getegid()),
		AgentUIDs:       d.AgentUIDs,
		IntakeUIDs:      d.IntakeUIDs,
		AdminUIDs:       d.AdminUIDs,
		AgentSocket:     d.SocketPath,
		AdminSocket:     d.AdminSocket,
		IntakeSocket:    d.IntakeSocket,
		HostSocket:      d.HostSocket,
		DBPath:          d.DBPath,
		AegisKeysDir:    d.AegisKeysDir,
		AegisKeysSocket: d.AegisKeysSocket,
		BrokerPID:       brokerPID,
	}
}

// IsolationPreflight maps the deployment onto the doctor's inputs for a
// topology that is not running yet: the process-inspection check is skipped
// (there is no broker process) and broker-owned objects that do not exist yet
// are informational. A reachable object is still reported as a failure.
func (d Deployment) IsolationPreflight() isolation.Config {
	cfg := d.Isolation(0)
	cfg.Preflight = true
	return cfg
}

// StateDir returns the directory that holds the installation's state, taken
// from the database path so the socket and database cannot disagree about
// where the installation lives.
func (d Deployment) StateDir() string {
	if d.DBPath == "" {
		return ""
	}
	return filepath.Dir(d.DBPath)
}
