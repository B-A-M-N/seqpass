// Package isolation provides live, runtime verification of the SeqPass
// security boundary.
//
// Assurance must never be derived from configured strings alone: a
// deployment can be configured "isolated" while the running topology still
// lets the agent read the broker database, the protected intake socket, the
// AegisKeys material, or the broker's memory. This package inspects the
// actual on-disk objects and the effective identities, evaluates them from
// the agent's point of view, and reports a fail-closed verdict.
package isolation

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/secretbridge/secretbridge/internal/intake"
)

// Mode labels mirror the daemon's assurance modes.
const (
	ModeBestEffort = "best-effort"
	ModeIsolated   = "isolated"
)

// LabelUnverified is the honest assurance label for any topology that has
// not been proven isolated. It is reported everywhere best-effort is used.
const LabelUnverified = "unverified"

// LabelProvisional is the verdict of a preflight check: no boundary problem
// was found, but the boundary was not observed while serving, so it is not
// verified. It exists so a preflight can neither be mistaken for a guarantee
// nor be reported as failing when nothing is wrong.
const LabelProvisional = "provisional"

// Config describes the running topology to inspect. Paths are the live
// objects, not intended values.
type Config struct {
	AssuranceMode string
	BrokerUID     uint32
	BrokerGID     uint32
	AgentUIDs     []uint32
	IntakeUIDs    []uint32
	AdminUIDs     []uint32

	AgentSocket  string
	AdminSocket  string
	IntakeSocket string
	HostSocket   string

	DBPath          string
	AegisKeysDir    string
	AegisKeysSocket string

	// RecipientEndpoints are pinned recipient socket paths. When set, they
	// must not be reachable by an agent identity.
	RecipientEndpoints []string
	RecipientUIDs      []uint32

	// BrokerPID, when > 0, enables the process-inspection check against
	// /proc/<pid>.
	BrokerPID int

	// Preflight marks a check of a topology that has not been started yet.
	//
	// In preflight mode a broker-owned object that does not exist yet is
	// reported as informational instead of failing, because the broker will
	// create it with the correct mode when it starts; failing there would make
	// a pre-flight check useless. It never turns a reachable object into a
	// pass, so a genuinely world-readable database or socket still fails, and
	// it does not affect the live check the running broker performs.
	Preflight bool
}

// Check is one live verification result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is the doctor's verdict.
type Report struct {
	Mode       string                    `json:"mode"`
	Verified   bool                      `json:"verified"`
	Unverified bool                      `json:"unverified"`
	Label      string                    `json:"label"`
	Reason     string                    `json:"reason"`
	Checks     []Check                   `json:"checks"`
	Properties intake.VerifiedProperties `json:"properties"`
}

// FailedNames returns the names of failing checks.
func (r *Report) FailedNames() []string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

// Doctor inspects the running topology and returns a fail-closed verdict.
// An error is returned only for unusable input; topology problems are
// reported as failing checks inside the report, never as a benign error.
func Doctor(cfg Config) (*Report, error) {
	rep := &Report{Mode: cfg.AssuranceMode}
	// observed records whether a check actually inspected a real object. A
	// check that passed because the object does not exist yet proves nothing
	// about reachability, so it must not feed a "verified" property claim.
	observed := map[string]bool{}
	add := func(name string, ok bool, detail string) {
		rep.Checks = append(rep.Checks, Check{Name: name, OK: ok, Detail: detail})
	}
	addObserved := func(name string, ok bool, detail string) {
		observed[name] = true
		add(name, ok, detail)
	}

	if cfg.AssuranceMode == ModeBestEffort || cfg.AssuranceMode == "" {
		rep.Unverified = true
		rep.Label = LabelUnverified
		rep.Reason = "best-effort topology: same-UID operation does not establish a boundary against an agent with local shell access"
		add("assurance_mode", false, rep.Reason)
		// Still report the observable topology so operators see the truth.
		collectAccessChecks(cfg, add, addObserved)
		return rep, nil
	}
	if cfg.AssuranceMode != ModeIsolated {
		return nil, fmt.Errorf("unknown assurance mode %q", cfg.AssuranceMode)
	}

	addObserved("broker_uid_nonroot", cfg.BrokerUID != 0,
		fmt.Sprintf("broker uid=%d", cfg.BrokerUID))
	disjoint := true
	detail := "agent identities are disjoint from broker and trusted identities"
	if cfg.BrokerUID == 0 {
		disjoint = false
		detail = "broker runs as root"
	}
	for _, a := range cfg.AgentUIDs {
		if a == cfg.BrokerUID {
			disjoint = false
			detail = fmt.Sprintf("agent uid %d equals broker uid", a)
		}
		for _, t := range append(append([]uint32{}, cfg.IntakeUIDs...), cfg.AdminUIDs...) {
			if a == t {
				disjoint = false
				detail = fmt.Sprintf("agent uid %d overlaps trusted uid %d", a, t)
			}
		}
	}
	addObserved("identity_disjoint", disjoint, detail)

	collectAccessChecks(cfg, add, addObserved)

	// Process-inspection boundary.
	if cfg.BrokerPID > 0 {
		ok, detail := processInspectionDenied(cfg)
		addObserved("process_inspection_denied", ok, detail)
	}

	// Objective 4.3: report only what this doctor actually verified. The
	// doctor proves the boundaries it can observe from the agent's point of
	// view (intake reachability, process inspection, transcript/DB reads)
	// but it cannot establish terminal isolation, which is a property of the
	// specific terminal the human types into and is decided by the host
	// qualification. Claiming it here would let VerifiedProperties.Complete()
	// report agent_isolated from an unverified fact, so it stays false.
	rep.Properties = intake.VerifiedProperties{
		IntakeInaccessible: observed["agent_denied_intake_socket"] && checkByName(rep, "agent_denied_intake_socket"),
		TerminalIsolated:   false,
		ProcessIsolated:    observed["process_inspection_denied"] && checkByName(rep, "process_inspection_denied"),
		TranscriptIsolated: observed["agent_denied_broker_database"] && checkByName(rep, "agent_denied_broker_database"),
	}
	rep.Verified = true
	for _, c := range rep.Checks {
		if !c.OK {
			rep.Verified = false
			break
		}
	}
	// A preflight check cannot confirm the boundary: the broker is not
	// serving yet, so the process boundary could not be inspected and the
	// objects it will create do not exist. The honest verdict is "no problem
	// found", never "verified". Only the running broker may claim verified.
	if cfg.Preflight {
		rep.Verified = false
		rep.Unverified = true
		rep.Label = LabelProvisional
		if rep.AnyFailed() {
			rep.Reason = "preflight: the topology has problems that would prevent startup: " + joinNames(rep.FailedNames())
		} else {
			rep.Reason = "preflight: no boundary problem found before startup; the running broker must confirm the verdict"
		}
		return rep, nil
	}
	if rep.Verified {
		rep.Label = string(intake.AssuranceVerified)
		rep.Reason = "live topology confirms the agent identity cannot reach broker state, trusted sockets or the broker process"
	} else {
		rep.Unverified = true
		rep.Label = LabelUnverified
		rep.Reason = "live topology does not satisfy the isolated boundary: " + joinNames(rep.FailedNames())
	}
	return rep, nil
}

// AnyFailed reports whether any check failed. A preflight verdict is "nothing
// is provably wrong", which is exactly the absence of failing checks.
func (r *Report) AnyFailed() bool { return len(r.FailedNames()) > 0 }

func checkByName(r *Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.OK
		}
	}
	return false
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	if out == "" {
		out = "no failing checks"
	}
	return out
}

// collectAccessChecks evaluates each protected object from every agent
// identity's point of view. addObserved is used for checks that inspected a
// real object; add for checks that only report absence or configuration.
func collectAccessChecks(cfg Config, add func(string, bool, string), addObserved func(string, bool, string)) {
	if len(cfg.AgentUIDs) == 0 {
		add("agent_identities_configured", false, "no agent identities configured: cannot prove denial")
		return
	}
	type target struct {
		name     string
		path     string
		write    bool
		required bool
		// mustExist marks an object the broker itself is supposed to own and
		// serve. Its absence is a topology fault, not proof of protection.
		mustExist bool
	}
	targets := []target{
		{"agent_denied_admin_socket", cfg.AdminSocket, false, cfg.AdminSocket != "", true},
		{"agent_denied_intake_socket", cfg.IntakeSocket, false, cfg.IntakeSocket != "", true},
		{"agent_denied_host_socket", cfg.HostSocket, false, cfg.HostSocket != "", true},
		{"agent_denied_broker_database", cfg.DBPath, false, cfg.DBPath != "", true},
		{"agent_denied_aegiskeys_dir", cfg.AegisKeysDir, false, cfg.AegisKeysDir != "", false},
		{"agent_denied_aegiskeys_socket", cfg.AegisKeysSocket, false, cfg.AegisKeysSocket != "", false},
	}
	for _, ep := range cfg.RecipientEndpoints {
		targets = append(targets, target{"agent_denied_recipient_socket", ep, false, true, false})
	}
	for _, t := range targets {
		if !t.required || t.path == "" {
			continue
		}
		// Objective 4.2: absence is reported for what it is. A missing
		// protected object must never be scored as though the agent were
		// denied access to it, and a broker-owned object that does not exist
		// is a failing check rather than a pass.
		if _, err := os.Lstat(t.path); err != nil {
			if os.IsNotExist(err) {
				switch {
				case t.mustExist && !cfg.Preflight:
					add(t.name, false, fmt.Sprintf("required protected object %s does not exist", t.path))
				case t.mustExist:
					add(t.name, true, fmt.Sprintf("not created yet: %s will be created by the broker on start", t.path))
				default:
					add(t.name, true, fmt.Sprintf("absent: %s is not currently present, so there is nothing for an agent to reach", t.path))
				}
			} else {
				add(t.name, false, fmt.Sprintf("cannot stat %s: %v", t.path, err))
			}
			continue
		}
		ok := true
		detail := "protected"
		for _, a := range cfg.AgentUIDs {
			gids, unknown, err := groupIDs(a)
			if err != nil {
				ok = false
				detail = fmt.Sprintf("cannot resolve groups for agent uid %d: %v", a, err)
				break
			}
			if accessible, why := accessibleBy(t.path, a, gids, unknown, t.write); accessible {
				ok = false
				detail = fmt.Sprintf("agent uid %d can access %s (%s)", a, t.path, why)
				break
			}
		}
		addObserved(t.name, ok, detail)
	}
}

// groupIDs returns the supplementary group IDs for a UID. When the account
// cannot be resolved the caller must assume the worst case (unknown=true:
// treat every group bit as granting access) rather than skipping the check.
func groupIDs(uid uint32) ([]uint32, bool, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, true, nil
	}
	gs, err := u.GroupIds()
	if err != nil {
		return nil, true, nil
	}
	out := make([]uint32, 0, len(gs))
	for _, g := range gs {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, true, nil
		}
		out = append(out, uint32(n))
	}
	return out, false, nil
}

// accessibleBy reports whether uid (with gids) can open path, evaluating
// the real mode bits and every ancestor directory's traverse permission.
// unknownGroups forces group bits to be treated as granting access.
func accessibleBy(path string, uid uint32, gids []uint32, unknownGroups, write bool) (bool, string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return true, "path resolution failed: " + err.Error()
	}
	// Walk ancestors (excluding root) for traverse permission.
	var parts []string
	for p := abs; p != "/" && p != "." && p != ""; p = filepath.Dir(p) {
		parts = append(parts, p)
	}
	for i := len(parts) - 1; i >= 1; i-- {
		fi, err := os.Lstat(parts[i])
		if err != nil {
			if os.IsNotExist(err) {
				return false, "absent"
			}
			return true, "stat failed: " + err.Error()
		}
		perm := fi.Mode().Perm()
		if !dirTraversable(perm, ownerOf(fi), groupOf(fi), uid, gids, unknownGroups) {
			return false, "ancestor " + parts[i] + " is not traversable"
		}
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "absent"
		}
		return true, "stat failed: " + err.Error()
	}
	perm := fi.Mode().Perm()
	if permitted(perm, ownerOf(fi), groupOf(fi), uid, gids, unknownGroups, write) {
		return true, fmt.Sprintf("mode %o grants access", perm)
	}
	return false, "mode denies access"
}

func dirTraversable(perm os.FileMode, owner, group, uid uint32, gids []uint32, unknownGroups bool) bool {
	if perm&0001 != 0 {
		return true
	}
	if uid == owner && perm&0100 != 0 {
		return true
	}
	if (unknownGroups || inGroup(gids, group)) && perm&0010 != 0 {
		return true
	}
	return false
}

func permitted(perm os.FileMode, owner, group, uid uint32, gids []uint32, unknownGroups, write bool) bool {
	need := os.FileMode(4)
	if write {
		need = 2
	}
	if perm&0007&need != 0 {
		return true
	}
	if uid == owner && perm&0700&(need<<6) != 0 {
		return true
	}
	if (unknownGroups || inGroup(gids, group)) && perm&0070&(need<<3) != 0 {
		return true
	}
	return false
}

func inGroup(gids []uint32, group uint32) bool {
	for _, g := range gids {
		if g == group {
			return true
		}
	}
	return false
}

func ownerOf(fi os.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return ^uint32(0)
}

func groupOf(fi os.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Gid
	}
	return ^uint32(0)
}

// processInspectionDenied reports whether an agent identity can inspect the
// broker process.
func processInspectionDenied(cfg Config) (bool, string) {
	for _, a := range cfg.AgentUIDs {
		if a == cfg.BrokerUID {
			return false, "agent shares the broker UID: /proc exchange and ptrace are possible"
		}
	}
	// Yama ptrace_scope >= 1 restricts ptrace to descendants unless
	// CAP_SYS_PTRACE. Same-UID /proc/<pid>/mem is still gated by the
	// kernel's dumpable rules, which is why distinct UIDs matter.
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		if len(data) > 0 && data[0] == '0' {
			return false, "yama ptrace_scope=0 permits any identity to ptrace the broker"
		}
	}
	return true, "distinct identities and ptrace restrictions deny process inspection"
}
