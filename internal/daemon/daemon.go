package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/secretbridge/secretbridge/internal/config"
	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/isolation"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// shutdownWorkerTimeout bounds the wait for in-flight execution to
// settle during Shutdown. It is a variable (not a constant) so tests
// can compress the terminal failure path without waiting it out.
var shutdownWorkerTimeout = 90 * time.Second

// driftInterval is how often the broker re-verifies its security boundary
// (objective 4.4). It is a variable so tests can compress it.
var driftInterval = 30 * time.Second

const (
	AssuranceBestEffort = "best-effort"
	AssuranceIsolated   = "isolated"
)

// AssuranceLabel is the honest assurance label for a topology: only
// "isolated" topology that has been verified may claim anything else than
// unverified. best-effort is always labelled "unverified" (objective 4.1).
func AssuranceLabel(mode string) string {
	if mode == AssuranceIsolated {
		return string(intake.AssuranceVerified)
	}
	return isolation.LabelUnverified
}

// Config for the privileged broker. No TCP listeners, no HTTP, no browser UI.
// AdminUIDs is the explicit administrator allowlist: only these UIDs may use
// the admin socket, even if another local process can reach it. Defaults to
// the broker's own user (operator runs broker + admin CLI as one dedicated
// identity, agents as separate users).
// AgentUIDs is the explicit agent allowlist for the agent-request socket
// (C02). Empty defaults to the broker euid only (fail closed): the operator
// must list every approved agent UID. The agent socket is 0660 in a 0710
// directory so the agent group can connect; the admin socket stays 0600 in
// a 0700 directory, unreachable to agent identities.
type Config struct {
	// AssuranceMode labels the process topology. best-effort preserves the
	// compatible local setup; isolated validates distinct Linux service and
	// agent identities plus a private trusted-intake surface.
	AssuranceMode string
	DBPath        string
	VaultType     string
	SocketPath    string
	AdminSocket   string
	// IntakeSocket serves the trusted human-side intake domain
	// (QR-02/SP-TUI-04) on its own owner-only socket. Empty defaults
	// to <agent-socket>.intake.
	IntakeSocket string
	AdminUIDs    []uint32
	AgentUIDs    []uint32
	// IntakeUIDs names the human-side identities allowed to review
	// requests and release values (QR-02). Empty defaults to the
	// admin set. Agent UIDs are never sufficient unless explicitly
	// listed here — and listing them documents a same-user
	// best-effort deployment (SP-TUI-04 caveat), not the strong
	// agent-cannot-access guarantee separate identities provide.
	IntakeUIDs []uint32
	// SocketGroup is the agent Unix group that owns the agent socket and
	// its directory (SC-04). Plain socket bind does not inherit the
	// directory's group, so the broker assigns it explicitly and verifies
	// the result. Empty means single-user (broker euid only). Multi-user
	// production deployments must set this to the approved agent group.
	SocketGroup     string
	AegisKeysSocket string
	AegisKeysDir    string
	// AutoExecute runs the trusted in-broker worker that executes
	// authorized operations without manual `admin execute` (C13).
	// Approval is still required: only authorized ops are consumed, and
	// only through the same claim path as manual execution.
	AutoExecute bool
	// IntakeGroup names an explicitly configured trusted intake group
	// (F04): when set, the intake socket is group-accessible (0660) so a
	// human identity distinct from the broker UID can traverse and
	// connect, while peer-credential authorization still applies. Empty
	// keeps the owner-only default. Never the agent group.
	IntakeGroup string
	// HostSocket, when set, enables the display-only native-host adapter
	// presentation domain (HI-02/HI-03). It is owner-only and must remain
	// separate from every other socket directory. Empty keeps it disabled.
	HostSocket string
	// HostQualification, when supplied, is the broker-side accepted record
	// for a native adapter. It must exactly match the running host version,
	// adapter revision, topology, and security configuration or the broker
	// refuses the stronger host-native assurance. Empty uses the external
	// TTY fallback.
	HostQualification harness.AdapterQualification
	// NoRelayAutoDeliver disables the default broker-managed relay job
	// queue (F05). By default fulfilled quick relays dispatch without
	// requiring --auto-execute; this flag opts out explicitly.
	NoRelayAutoDeliver bool
	// DefaultOpTTL bounds the operator approval window for new
	// requests (G04/P1-6). Zero keeps the 5-minute default; the
	// service clamps to [1 minute, 24 hours].
	DefaultOpTTL time.Duration
	// MaxConcurrentOps bounds the auto worker's execution pool
	// (concurrency design). Zero means 4. Clamped to [1, 32].
	MaxConcurrentOps int
}

type Daemon struct {
	cfg      Config
	svc      *service.Service
	srv      *ipc.Server
	worker   context.CancelFunc
	workerWg sync.WaitGroup
	// lease is the exclusive database ownership held for the whole
	// broker lifetime (G05). A second broker on the same store is
	// refused before it can reconcile the live broker's work.
	lease *metadata.DBLock
	// securityFP is the verified topology fingerprint; drift from it
	// revokes the affected host capability (objective 4.4).
	securityFP isolation.Fingerprint
	// hostPresentation is true when the broker enabled a native host
	// presentation surface, so drift has something to revoke.
	hostPresentation bool
}

// isProductionVault reports whether the vault type is a production store.
func isProductionVault(vaultType string) bool {
	return vaultType == "aegiskeys"
}

// lookupGroupGID resolves a group name to its numeric GID. Fail closed:
// an unresolvable group is a startup error, never a silently owner-only
// socket in a deployment that expects group access (SC-04).
func lookupGroupGID(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("unknown socket group %q: %w", name, err)
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid GID for group %q: %w", name, err)
	}
	return uint32(n), nil
}

func New(cfg Config) (*Daemon, error) {
	if cfg.DBPath == "" || cfg.SocketPath == "" {
		return nil, fmt.Errorf("db path and socket path are required")
	}
	if cfg.VaultType == "" {
		return nil, fmt.Errorf("explicit vault type required: aegiskeys (production) or memory-test (dev only)")
	}
	if cfg.AssuranceMode == "" {
		// Objective 4.1: a production (AegisKeys) installation defaults to
		// strict isolation and refuses to start unless the topology is
		// actually isolated. The development memory vault keeps the
		// compatible local setup, always labelled unverified.
		if isProductionVault(cfg.VaultType) {
			cfg.AssuranceMode = AssuranceIsolated
		} else {
			cfg.AssuranceMode = AssuranceBestEffort
		}
	}
	if cfg.AssuranceMode != AssuranceBestEffort && cfg.AssuranceMode != AssuranceIsolated {
		return nil, fmt.Errorf("unknown assurance mode %q (want %s or %s)", cfg.AssuranceMode, AssuranceBestEffort, AssuranceIsolated)
	}
	// Objective 4.1: a production installation must not run on a topology it
	// cannot prove. best-effort exists only for the development vault, so a
	// production vault paired with best-effort is refused outright rather
	// than started with an unverified boundary.
	if isProductionVault(cfg.VaultType) && cfg.AssuranceMode != AssuranceIsolated {
		return nil, fmt.Errorf("production vault %q requires %s assurance: best-effort is development-only and does not establish a boundary against an agent with local shell access", cfg.VaultType, AssuranceIsolated)
	}
	if cfg.AssuranceMode == AssuranceIsolated {
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("isolated assurance requires Linux peer credentials")
		}
		if len(cfg.AgentUIDs) == 0 || len(cfg.IntakeUIDs) == 0 || cfg.SocketGroup == "" {
			return nil, fmt.Errorf("isolated assurance requires explicit --agent-uid, --intake-uid, and --socket-group")
		}
	}
	if cfg.AdminSocket == "" {
		cfg.AdminSocket = cfg.SocketPath + ".admin"
	}
	if cfg.IntakeSocket == "" {
		cfg.IntakeSocket = cfg.SocketPath + ".intake"
	}
	if len(cfg.AdminUIDs) == 0 {
		cfg.AdminUIDs = []uint32{uint32(os.Geteuid())}
	}
	if len(cfg.AgentUIDs) == 0 {
		cfg.AgentUIDs = []uint32{uint32(os.Geteuid())}
	}
	// Default intake to the admin set AFTER admin defaults resolve:
	// copying an empty admin list would silently deny every human.
	if len(cfg.IntakeUIDs) == 0 {
		cfg.IntakeUIDs = cfg.AdminUIDs
	}
	if cfg.AssuranceMode == AssuranceIsolated {
		if err := validateIsolationTopology(cfg, uint32(os.Geteuid())); err != nil {
			return nil, err
		}
		gid, err := lookupGroupGID(cfg.SocketGroup)
		if err != nil {
			return nil, err
		}
		if err := validateAgentGroupMembership(cfg.AgentUIDs, gid); err != nil {
			return nil, err
		}
		if cfg.IntakeGroup != "" {
			if cfg.IntakeGroup == cfg.SocketGroup {
				return nil, fmt.Errorf("isolated assurance refuses intake and agent group overlap")
			}
			intakeGID, err := lookupGroupGID(cfg.IntakeGroup)
			if err != nil {
				return nil, err
			}
			if err := validateUIDGroupMembership(cfg.IntakeUIDs, intakeGID, true, "intake"); err != nil {
				return nil, err
			}
			if err := validateUIDGroupMembership(cfg.AgentUIDs, intakeGID, false, "agent"); err != nil {
				return nil, err
			}
		}
		if sameSocketDir(cfg.SocketPath, cfg.AdminSocket) || sameSocketDir(cfg.SocketPath, cfg.IntakeSocket) {
			return nil, fmt.Errorf("isolated assurance requires a separate agent socket directory from admin and intake")
		}
	}
	// Ownership first (G05): no Service, no reconciliation, no sockets
	// until this process exclusively owns the state store. The service
	// opens the lease's canonical path (P1-2) — never the caller's
	// original spelling — so the guarded file and the live database
	// cannot diverge through a pathname alias.
	lease, err := metadata.AcquireDBLock(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	dbPath := lease.CanonicalPath()
	if dbPath == "" {
		dbPath = cfg.DBPath
	}
	svc, err := service.New(service.Config{
		DBPath:           dbPath,
		VaultType:        cfg.VaultType,
		AegisKeysSocket:  cfg.AegisKeysSocket,
		AegisKeysDir:     cfg.AegisKeysDir,
		DefaultOpTTL:     cfg.DefaultOpTTL,
		MaxConcurrentOps: cfg.MaxConcurrentOps,
		// Objective 4.3: an isolated deployment withholds inline native
		// capture unless every boundary property is proven. A best-effort
		// deployment keeps the historic selector because it makes no
		// isolation claim to begin with.
		RequireVerifiedHostIsolation: cfg.AssuranceMode == AssuranceIsolated,
	})
	if err != nil {
		lease.Release()
		return nil, err
	}
	// Freeze the driver/verifier registries once the broker is live
	// (CV-07): late registration would silently change the active
	// completion contract, so it is refused after this point.
	if err := secureops.FreezeRegistries(); err != nil {
		_ = svc.Close()
		lease.Release()
		return nil, err
	}
	allow := map[uint32]bool{}
	for _, u := range cfg.AdminUIDs {
		allow[u] = true
	}
	agents := map[uint32]bool{}
	for _, u := range cfg.AgentUIDs {
		agents[u] = true
	}
	intakeUIDs := map[uint32]bool{}
	for _, u := range cfg.IntakeUIDs {
		intakeUIDs[u] = true
	}
	srv := ipc.NewServer(svc, cfg.SocketPath, cfg.AdminSocket, nil,
		&ipc.UIDAuthorizer{AdminUIDs: allow, AgentUIDs: agents, IntakeUIDs: intakeUIDs})
	srv.IntakeSocket = cfg.IntakeSocket
	srv.HostSocket = cfg.HostSocket
	if cfg.HostSocket != "" {
		// SP-01: validate the host socket path before starting the IPC server
		// so a configured but nonexistent or invalid path fails startup
		// cleanly, rather than silently creating a socket in a new directory.
		hostDir := filepath.Dir(cfg.HostSocket)
		if fi, err := os.Lstat(hostDir); err != nil || !fi.IsDir() {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("host socket directory does not exist: %s", hostDir)
		}
		if err := svc.SetHostInputAssurance(string(harness.InputExternalTTY), string(intake.AssuranceModelBlind)); err != nil {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("host assurance configuration failed: %w", err)
		}
	}
	srv.AssuranceMode = cfg.AssuranceMode
	// Objective 4.1: the honest assurance label starts unverified and is
	// upgraded only after the live boundary check below proves the running
	// topology. This closes the window between binding sockets and verifying
	// them, during which a health call must not read a guarantee.
	srv.SetAssuranceLabel(isolation.LabelUnverified)
	// HI-05: qualification is accepted only as a complete record. Empty
	// configuration remains fail-closed external TTY/model-blind.
	if !cfg.HostQualification.QualifiedAt.IsZero() || cfg.HostQualification.Status != "" {
		digest, err := harness.SecurityConfigDigest(cfg.HostQualification.HostKind,
			cfg.HostQualification.HostVersion, cfg.HostQualification.AdapterVersion,
			cfg.HostQualification.ExecutionTopology, nil)
		if err != nil {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("host qualification metadata invalid: %w", err)
		}
		if cfg.HostQualification.SecurityConfigDigest == "" {
			cfg.HostQualification.SecurityConfigDigest = digest
		}
		if err := cfg.HostQualification.ValidFor(cfg.HostQualification.HostKind,
			cfg.HostQualification.HostVersion, cfg.HostQualification.AdapterVersion,
			harness.HostInputMode(cfg.HostQualification.InputMode),
			cfg.HostQualification.ExecutionTopology, cfg.HostQualification.SecurityConfigDigest,
			time.Now()); err != nil {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("host qualification rejected: %w", err)
		}
		// CORE-04: match the accepted snapshot against its own exact facts
		// before enabling native mode. Registration claims are never used
		// as qualification evidence.
		snapshot := &harness.QualificationSnapshot{
			HostKind:       cfg.HostQualification.HostKind,
			HostVersion:    cfg.HostQualification.HostVersion,
			AdapterVersion: cfg.HostQualification.AdapterVersion,
			InputMode:      cfg.HostQualification.InputMode,
			Topology:       cfg.HostQualification.ExecutionTopology,
			ConfigDigest:   cfg.HostQualification.SecurityConfigDigest,
			Record:         cfg.HostQualification,
		}
		svc.SetHostQualification(snapshot)
		decision, err := harness.SelectNativeMode(snapshot,
			cfg.HostQualification.HostKind, cfg.HostQualification.HostVersion,
			cfg.HostQualification.AdapterVersion, cfg.HostQualification.ExecutionTopology,
			nil, time.Now())
		if err != nil || !decision.Qualified || decision.RecordUsed != true {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("host qualification did not select native mode: %w", err)
		}
	}
	if cfg.SocketGroup != "" {
		gid, err := lookupGroupGID(cfg.SocketGroup)
		if err != nil {
			_ = svc.Close()
			lease.Release()
			return nil, err
		}
		srv.AgentGID = &gid
	}
	if cfg.IntakeGroup != "" {
		if cfg.IntakeGroup == cfg.SocketGroup {
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("intake group must differ from the agent group")
		}
		gid, err := lookupGroupGID(cfg.IntakeGroup)
		if err != nil {
			_ = svc.Close()
			lease.Release()
			return nil, err
		}
		srv.IntakeGID = &gid
	}
	if err := srv.Start(); err != nil {
		_ = svc.Close()
		lease.Release()
		return nil, fmt.Errorf("broker IPC failed: %w", err)
	}
	// Verify socket permissions: agent socket group-accessible but never
	// world-accessible (0660 or tighter); admin socket owner-only (0600).
	// Intake is owner-only by default, or group-accessible (0660) when an
	// explicit trusted intake group is configured (F04) — never
	// world-accessible, never the agent group. Peer-UID allowlists remain
	// the authorization control (QR-02).
	socketChecks := []struct {
		path   string
		admin  bool
		intake bool
	}{
		{cfg.SocketPath, false, false},
		{cfg.AdminSocket, true, false},
		{cfg.IntakeSocket, true, true},
	}
	if cfg.HostSocket != "" {
		socketChecks = append(socketChecks, struct {
			path   string
			admin  bool
			intake bool
		}{cfg.HostSocket, false, false})
	}
	for _, sp := range socketChecks {
		st, err := os.Stat(sp.path)
		if err != nil {
			_ = srv.Close()
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf("broker socket missing: %w", err)
		}
		perm := st.Mode().Perm()
		fail := func(format string, args ...interface{}) (*Daemon, error) {
			_ = srv.Close()
			_ = svc.Close()
			lease.Release()
			return nil, fmt.Errorf(format, args...)
		}
		if perm&0007 != 0 {
			return fail("broker socket %s is world-accessible (mode %o)", sp.path, perm)
		}
		if sp.intake && cfg.IntakeGroup != "" {
			if perm != 0660 && perm != 0640 && perm != 0600 {
				return fail("intake socket %s has unexpected mode %o", sp.path, perm)
			}
		} else if sp.admin {
			if perm&0077 != 0 {
				return fail("admin socket %s is not owner-only (mode %o)", sp.path, perm)
			}
		} else if perm != 0600 && perm != 0640 && perm != 0660 {
			// Agent socket is 0600 (single-user dev) or 0640/0660
			// (approved agent group); never anything else.
			return fail("agent socket %s has unexpected mode %o", sp.path, perm)
		}
	}
	d := &Daemon{cfg: cfg, svc: svc, srv: srv, lease: lease}
	d.hostPresentation = cfg.HostSocket != ""
	// Objective 4.2: verify the ACTIVE boundary before serving traffic, not
	// only the configured values. In isolated mode a failure is fatal.
	if cfg.AssuranceMode == AssuranceIsolated {
		label, aerr := assessIsolation(cfg)
		if aerr != nil {
			_ = srv.Close()
			_ = svc.Close()
			lease.Release()
			return nil, aerr
		}
		// The running topology is verified: the honest label may now be
		// upgraded, and remains revocable if the boundary later drifts.
		srv.SetAssuranceLabel(label)
	} else {
		// best-effort is never advertised as verified (objective 4.1).
		svc.SetHostInputUnverified("best-effort topology: same-UID operation does not establish a boundary against an agent with local shell access")
	}
	// Objective 4.4: record the verified topology so later drift can revoke
	// the affected host capability instead of silently degrading.
	d.securityFP = isolation.CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), d.protectedPaths())
	if d.hostPresentation {
		ctx, cancel := context.WithCancel(context.Background())
		prevDrift := d.worker
		d.worker = func() {
			cancel()
			if prevDrift != nil {
				prevDrift()
			}
		}
		d.workerWg.Add(1)
		go func() {
			defer d.workerWg.Done()
			d.monitorSecurityDrift(ctx)
		}()
	}
	if cfg.AutoExecute {
		ctx, cancel := context.WithCancel(context.Background())
		// Compose with any existing worker cancel rather than replacing it,
		// so a previously installed supervisor (for example the security
		// drift monitor) is still canceled and its goroutine group is not
		// left blocking shutdown.
		prevWorker := d.worker
		d.worker = func() {
			cancel()
			if prevWorker != nil {
				prevWorker()
			}
		}
		d.workerWg.Add(1)
		go func() {
			defer d.workerWg.Done()
			svc.RunAutoWorker(ctx, 0)
		}()
	}
	// F05/F12: broker-managed relay delivery + lifecycle maintenance run
	// by default, independent of the general auto-execution switch. The
	// relay queue executes ONLY relay-backed transfers; the lifecycle
	// loop expires requests and purges payloads even with no worker.
	// Both share the daemon worker group for supervised shutdown.
	// F12/C04: lifecycle maintenance runs unconditionally, independent of
	// relay delivery or general auto-execution, so expiry and payload
	// cleanup never depend on an execution switch.
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	prevLifecycle := d.worker
	d.worker = func() {
		lifecycleCancel()
		if prevLifecycle != nil {
			prevLifecycle()
		}
	}
	d.workerWg.Add(1)
	go func() {
		defer d.workerWg.Done()
		svc.RunLifecycleLoop(lifecycleCtx, 0)
	}()
	if !cfg.NoRelayAutoDeliver {
		relayCtx, relayCancel := context.WithCancel(context.Background())
		prevRelay := d.worker
		d.worker = func() {
			relayCancel()
			if prevRelay != nil {
				prevRelay()
			}
		}
		d.workerWg.Add(1)
		go func() {
			defer d.workerWg.Done()
			svc.RunRelayWorker(relayCtx, 0)
		}()
	}
	return d, nil
}

// AssuranceMode returns the effective, validated topology label chosen at
// construction (including the production default).
func (d *Daemon) AssuranceMode() string { return d.cfg.AssuranceMode }

// protectedPaths lists every object whose identity or permissions must not
// change under a verified boundary.
func (d *Daemon) protectedPaths() []string {
	paths := []string{d.cfg.AdminSocket, d.cfg.IntakeSocket}
	if d.cfg.HostSocket != "" {
		paths = append(paths, d.cfg.HostSocket)
	}
	if d.cfg.DBPath != "" {
		paths = append(paths, d.cfg.DBPath)
	}
	if d.cfg.AegisKeysDir != "" {
		paths = append(paths, d.cfg.AegisKeysDir)
	}
	if d.cfg.AegisKeysSocket != "" {
		paths = append(paths, d.cfg.AegisKeysSocket)
	}
	return paths
}

// isolationConfigFor builds the live doctor input for this broker.
//
// The field mapping itself lives in config.Deployment.Isolation, the single
// mapping shared with `seqpass doctor --topology`, so a preflight verdict and
// a startup verdict are always about the same system. This wrapper exists
// because the broker's Config is a different (richer) type than the shared
// Deployment, and because the live check needs the real PID. The claim is
// passed through untouched: New resolves the default before the first check,
// so the mapping's defaulting must never re-derive a different mode.
func isolationConfigFor(cfg Config) isolation.Config {
	dep := config.Deployment{
		DBPath:          cfg.DBPath,
		SocketPath:      cfg.SocketPath,
		AdminSocket:     cfg.AdminSocket,
		IntakeSocket:    cfg.IntakeSocket,
		HostSocket:      cfg.HostSocket,
		AssuranceMode:   cfg.AssuranceMode,
		AdminUIDs:       cfg.AdminUIDs,
		AgentUIDs:       cfg.AgentUIDs,
		IntakeUIDs:      cfg.IntakeUIDs,
		AegisKeysDir:    cfg.AegisKeysDir,
		AegisKeysSocket: cfg.AegisKeysSocket,
	}
	return dep.Isolation(os.Getpid())
}

// isolationDoctor runs the live boundary check. It is a package variable so
// the refusal path can be proven without a privileged multi-UID host, and so
// a future re-implementation is a single substitution.
var isolationDoctor = isolation.Doctor

// assessIsolation performs the objective-4.2 live check for an isolated
// deployment and returns the assurance label to publish. An unverified
// topology is fatal: the broker must never serve an unproven boundary, and
// the label may only read "verified" once the running topology has been
// checked.
func assessIsolation(cfg Config) (string, error) {
	rep, err := isolationDoctor(isolationConfigFor(cfg))
	if err != nil {
		return "", fmt.Errorf("isolation diagnostic failed: %w", err)
	}
	if !rep.Verified {
		return "", fmt.Errorf("broker refused to start: live isolation check failed (%v)", rep.FailedNames())
	}
	return string(intake.AssuranceVerified), nil
}

// VerifySecurityBoundary re-runs the live doctor and compares the running
// topology against the verified fingerprint. It returns the list of drift
// reasons (empty when the boundary is intact).
func (d *Daemon) VerifySecurityBoundary() []string {
	var drift []string
	if d.cfg.AssuranceMode == AssuranceIsolated {
		if rep, err := isolation.Doctor(isolationConfigFor(d.cfg)); err == nil && !rep.Verified {
			drift = append(drift, rep.FailedNames()...)
		}
	}
	now := isolation.CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), d.protectedPaths())
	drift = append(drift, d.securityFP.Drift(now)...)
	return drift
}

// monitorSecurityDrift periodically re-verifies the boundary and revokes the
// host capability when it drifts, falling back to the external trusted
// terminal (objective 4.4). It never terminates already-committed external
// operations: only presentation assurance is withdrawn.
func (d *Daemon) monitorSecurityDrift(ctx context.Context) {
	ticker := time.NewTicker(driftInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if drift := d.VerifySecurityBoundary(); len(drift) > 0 {
				d.revokeOnDrift(drift)
			}
		}
	}
}

// revokeOnDrift withdraws the verified host capability and records why.
func (d *Daemon) revokeOnDrift(drift []string) {
	reason := "security drift detected: " + joinDrift(drift)
	d.svc.SetHostQualification(nil)
	d.svc.SetHostInputUnverified(reason)
	if d.srv != nil {
		d.srv.SetAssuranceLabel(isolation.LabelUnverified)
	}
	if db := d.svc.DB(); db != nil {
		_ = db.WriteAuditLog(&types.AuditLog{
			OperationID: "", Action: "security_drift_revocation", Actor: "broker",
			Outcome: reason,
		})
	}
	// Refresh the fingerprint so one drift event does not repeatedly fire.
	d.securityFP = isolation.CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), d.protectedPaths())
}

func joinDrift(drift []string) string {
	out := ""
	for i, s := range drift {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	if out == "" {
		return "unspecified"
	}
	return out
}

func validateIsolationTopology(cfg Config, brokerUID uint32) error {
	if brokerUID == 0 {
		return fmt.Errorf("isolated assurance requires a non-root dedicated broker UID")
	}
	trustedUIDs := append(append([]uint32(nil), cfg.AdminUIDs...), cfg.IntakeUIDs...)
	for _, uid := range cfg.AgentUIDs {
		if uid == brokerUID {
			return fmt.Errorf("isolated assurance refused: broker UID %d is also an agent UID", brokerUID)
		}
		for _, trusted := range trustedUIDs {
			if uid == trusted {
				return fmt.Errorf("isolated assurance refused: agent UID %d overlaps trusted admin/intake UID %d", uid, trusted)
			}
		}
	}
	// The admin socket is owner-only. A separate intake identity is supported
	// only when an explicit non-agent intake group is configured for its
	// socket; otherwise both trusted surfaces must use the broker UID.
	for _, uid := range cfg.AdminUIDs {
		if uid != brokerUID {
			return fmt.Errorf("isolated assurance requires admin UID %d to match owner-only broker UID %d", uid, brokerUID)
		}
	}
	for _, uid := range cfg.IntakeUIDs {
		if uid != brokerUID && cfg.IntakeGroup == "" {
			return fmt.Errorf("isolated assurance requires a trusted intake group when intake UID %d differs from broker UID %d", uid, brokerUID)
		}
	}
	if cfg.IntakeGroup != "" && cfg.IntakeGroup == cfg.SocketGroup {
		return fmt.Errorf("isolated assurance refuses intake and agent group overlap")
	}
	return nil
}

func validateAgentGroupMembership(agentUIDs []uint32, gid uint32) error {
	return validateUIDGroupMembership(agentUIDs, gid, true, "agent")
}

func validateUIDGroupMembership(uids []uint32, gid uint32, wantMember bool, role string) error {
	for _, uid := range uids {
		u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return fmt.Errorf("isolated assurance cannot resolve %s UID %d: %w", role, uid, err)
		}
		groups, err := u.GroupIds()
		if err != nil {
			return fmt.Errorf("isolated assurance cannot read groups for %s UID %d: %w", role, uid, err)
		}
		member := false
		for _, group := range groups {
			if group == strconv.FormatUint(uint64(gid), 10) {
				member = true
				break
			}
		}
		if member != wantMember {
			if wantMember {
				return fmt.Errorf("isolated assurance %s UID %d is not a member of required socket group GID %d", role, uid, gid)
			}
			return fmt.Errorf("isolated assurance %s UID %d belongs to protected socket group GID %d", role, uid, gid)
		}
	}
	return nil
}

func sameSocketDir(a, b string) bool {
	da, errA := filepath.Abs(filepath.Dir(a))
	db, errB := filepath.Abs(filepath.Dir(b))
	return errA == nil && errB == nil && filepath.Clean(da) == filepath.Clean(db)
}

func (d *Daemon) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return d.Shutdown()
}

// Shutdown stops admission first (close IPC listeners), then stops the
// auto worker and waits for in-flight execution to settle (bounded by the
// driver's I/O deadlines), and only then closes the database (SC-07). No
// new claim can start after the listeners close, and no DB write happens
// after Close.
func (d *Daemon) Shutdown() error {
	if d.srv != nil {
		_ = d.srv.Close()
	}
	if d.worker != nil {
		d.worker()
		done := make(chan struct{})
		go func() { d.workerWg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(shutdownWorkerTimeout):
			// P1-5: the worker is still capable of external side
			// effects. Closing the database and releasing the lease
			// now would let a successor broker reconcile this
			// broker's LIVE work as its own, violating the
			// single-owner invariant. Retain ownership (database
			// stays open, lease held) and report failed termination:
			// the supervisor must terminate this process before
			// starting a replacement. Never a graceful result here.
			return errors.New("shutdown: worker did not terminate within timeout; " +
				"database lease retained — terminate this process before starting a replacement")
		}
	}
	// The lease drops only after workers stop and the database closes:
	// until then this process still owns recovery (G05).
	if d.svc != nil {
		err := d.svc.Close()
		if d.lease != nil {
			d.lease.Release()
		}
		return err
	}
	if d.lease != nil {
		d.lease.Release()
	}
	return nil
}
