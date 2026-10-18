package daemon

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/isolation"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/testruntime"
)

// isolatedFixture finds an (agentUID, groupName) pair this host can actually
// exercise: a resolvable identity distinct from the broker identity, and a
// group that contains it and that the broker identity belongs to as well (so
// the broker is permitted to change a socket to that group).
//
// ok is false when the host cannot present the fixture: no second identity to
// isolate, a root broker, or a kernel that lets any identity inspect a
// process regardless of UID. Those are properties of the environment, not of
// SeqPass, so the caller skips with the returned reason; every other
// precondition is asserted so a real regression fails instead of skipping.
func isolatedFixture(t *testing.T) (agentUID uint32, group, reason string, ok bool) {
	t.Helper()
	brokerUID := uint32(os.Geteuid())
	if brokerUID == 0 {
		return 0, "", "fixture needs a non-root broker identity", false
	}
	// The running boundary check refuses a host that permits any identity to
	// ptrace the broker, so the fixture cannot be verified there.
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		if len(data) > 0 && data[0] == '0' {
			return 0, "", "kernel permits any identity to ptrace the broker (yama ptrace_scope=0)", false
		}
	}
	me, err := user.Current()
	if err != nil {
		return 0, "", "cannot resolve the broker identity: " + err.Error(), false
	}
	gids, err := me.GroupIds()
	if err != nil {
		return 0, "", "cannot resolve the broker groups: " + err.Error(), false
	}
	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		for _, name := range groupMemberNames(gid) {
			u, err := user.Lookup(name)
			if err != nil {
				continue
			}
			n, err := strconv.ParseUint(u.Uid, 10, 32)
			if err != nil || uint32(n) == brokerUID || n == 0 {
				continue
			}
			return uint32(n), g.Name, "", true
		}
	}
	return 0, "", "host has no second identity sharing a group with the broker identity", false
}

// groupMemberNames reads the supplementary member list of one group. os/user
// exposes membership per user, not per group, and the point of the fixture is
// to find a second user that shares a group with the broker user.
func groupMemberNames(gid string) []string {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 || fields[2] != gid {
			continue
		}
		if fields[3] == "" {
			return nil
		}
		return strings.Split(fields[3], ",")
	}
	return nil
}

// isolatedTestConfig assembles a complete isolated topology under dir that
// passes the broker's own configuration validation, so the only thing left to
// decide is the live boundary check.
func isolatedTestConfig(root string, agentUID uint32, group string) Config {
	agentDir := filepath.Join(root, "agent")
	trustedDir := filepath.Join(root, "trusted")
	return Config{
		DBPath:        filepath.Join(trustedDir, "meta.db"),
		SocketPath:    filepath.Join(agentDir, "broker.sock"),
		AdminSocket:   filepath.Join(trustedDir, "broker.sock.admin"),
		IntakeSocket:  filepath.Join(trustedDir, "broker.sock.intake"),
		VaultType:     "memory-test",
		AssuranceMode: AssuranceIsolated,
		AgentUIDs:     []uint32{agentUID},
		AdminUIDs:     []uint32{uint32(os.Geteuid())},
		IntakeUIDs:    []uint32{uint32(os.Geteuid())},
		SocketGroup:   group,
	}
}

// prepareIsolatedDirs creates the two socket directories the isolated topology
// requires: a group-traversable agent directory (0710) and an owner-only
// trusted directory (0700).
func prepareIsolatedDirs(t *testing.T, root string) {
	t.Helper()
	for _, d := range []struct {
		name string
		mode os.FileMode
	}{
		{"agent", 0710},
		{"trusted", 0700},
	} {
		p := filepath.Join(root, d.name)
		if err := os.Mkdir(p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
}

// Objective 4.1/4.2 end to end: when the live boundary check does not confirm
// the isolated topology, the broker must refuse to start, and the refusal must
// unwind cleanly so a corrected deployment can start afterwards.
//
// The check is stubbed here on purpose: this test is about what daemon.New
// does with an unconfirmed verdict, not about how the verdict is computed
// (which the isolation package tests cover directly).
func TestIsolatedRefusalHappensAtTheLiveBoundary(t *testing.T) {
	requireSocketFixture(t)
	agentUID, group, reason, ok := isolatedFixture(t)
	if !ok {
		t.Skip(reason)
	}
	root, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	prepareIsolatedDirs(t, root)

	orig := isolationDoctor
	isolationDoctor = func(cfg isolation.Config) (*isolation.Report, error) {
		return &isolation.Report{
			Mode: cfg.AssuranceMode,
			Checks: []isolation.Check{
				{Name: "agent_denied_broker_database", OK: false, Detail: "stubbed: boundary unconfirmed"},
				{Name: "identity_disjoint", OK: true, Detail: "ok"},
			},
			Verified: false,
		}, nil
	}
	defer func() { isolationDoctor = orig }()

	cfg := isolatedTestConfig(root, agentUID, group)
	d, err := New(cfg)
	if err == nil {
		_ = d.Shutdown()
		t.Fatal("isolated broker started although the live boundary check did not confirm it")
	}
	// The failure must be the boundary verdict, not an earlier configuration
	// rule: this asserts the specific stage, which a substring check on
	// "isolated" could not.
	if !strings.Contains(err.Error(), "live isolation check failed") {
		t.Fatalf("refusal did not come from the live boundary check: %v", err)
	}
	if !strings.Contains(err.Error(), "agent_denied_broker_database") {
		t.Fatalf("refusal did not name the failing boundary: %v", err)
	}

	// The refusal unwinds: the socket is gone and the database lease is free.
	if _, err := os.Stat(cfg.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("agent socket left behind after refusal (err=%v)", err)
	}
	lease, err := metadata.AcquireDBLock(cfg.DBPath)
	if err != nil {
		t.Fatalf("database lease was not released by the refused start: %v", err)
	}
	lease.Release()
}

// Objective 4.1/4.2 end to end, positive control: with a real isolated
// topology the live check confirms, the broker starts and reports the honest
// verified label. Without this the refusal test above could pass because
// startup never succeeds at all.
func TestIsolatedDeploymentStartsWithVerifiedBoundary(t *testing.T) {
	requireSocketFixture(t)
	agentUID, group, reason, ok := isolatedFixture(t)
	if !ok {
		t.Skip(reason)
	}
	root, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	prepareIsolatedDirs(t, root)

	cfg := isolatedTestConfig(root, agentUID, group)
	// Every environmental precondition is checked above, so a failure here is
	// a defect in the isolated startup path, not a missing capability. Failing
	// rather than skipping keeps this test a real positive control: without it
	// the refusal test above could pass because startup never succeeds at all.
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("isolated deployment did not start on a topology that satisfies every precondition: %v", err)
	}
	defer d.Shutdown()

	if got := d.srv.AssuranceLabel(); got != "verified" {
		t.Fatalf("assurance label = %q, want verified for a confirmed isolated topology", got)
	}
	// A verified start must also report an intact boundary: the fingerprint
	// captured at startup has to match the topology that is now running.
	if drift := d.VerifySecurityBoundary(); len(drift) != 0 {
		t.Fatalf("boundary drifted immediately after a verified start: %v", drift)
	}
	// The store the agent identity is denied must really exist and be
	// owner-only; a missing file would make the denial vacuous.
	fi, err := os.Stat(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		t.Fatalf("database mode = %v, want owner-only", perm)
	}
}
