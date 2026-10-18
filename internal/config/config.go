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
