//go:build linux

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// dumpableStatus reads the per-process dumpable flag via
// prctl(PR_GET_DUMPABLE). 0 = SUID_DUMP_DISABLE (PR_SET_DUMPABLE 0 took
// effect). The /proc/self/status "CoreDumping" field is NOT suitable:
// it reads 1 only while a dump is in progress, not whether dumps are
// permitted.
func dumpableStatus(t *testing.T) int {
	t.Helper()
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Skipf("prctl PR_GET_DUMPABLE unavailable: %v", err)
	}
	return d
}

// §11 crash outputs: the broker stages relay payloads in memory, so a
// core dump would persist plaintext outside every guarded surface. The
// broker must start with core production disabled: RLIMIT_CORE soft
// limit 0 (blocks file dumps) AND the process marked non-dumpable
// (blocks piped handlers such as apport/systemd-coredump, which bypass
// RLIMIT_CORE entirely).
//
// The test first RAISES the soft core limit (always permitted up to the
// hard limit) so the enforcement has real work to do even on hosts whose
// ulimit -c is already 0 — otherwise the rlimit assertion would be
// vacuous and a regression to a no-op helper would go unnoticed.
func TestBrokerDisablesCoreDumps(t *testing.T) {
	var orig unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_CORE here: %v", err)
	}
	if orig.Max == 0 {
		t.Skip("host hard-limits core size to 0; the rlimit control is environmental here")
	}
	// Raise the soft limit to the hard limit for this test process.
	// Children inherit rlimits across exec, so the broker child below
	// genuinely starts with core dumps enabled.
	raised := unix.Rlimit{Cur: orig.Max, Max: orig.Max}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &raised); err != nil {
		t.Skipf("cannot raise RLIMIT_CORE to its hard limit here: %v", err)
	}
	// No cleanup that pretends to restore: the helper zeroes the HARD
	// limit too (so unprivileged children cannot re-enable dumps), and
	// raising a hard limit back needs CAP_SYS_RESOURCE. The test binary
	// simply keeps cores disabled afterwards — harmless for tests.
	dir := t.TempDir()
	bin := filepath.Join(dir, "seqpass")
	build := exec.Command("go", "build", "-o", bin, "./seqpass")
	build.Dir = "../../cmd"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// "broker" with no vault flag exits(1) after the core-dump call and
	// before any socket work — the stderr line proves the warning path
	// did NOT fire.
	cmd := exec.Command(bin, "broker")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("broker with no --vault must exit non-zero")
	}
	out := stderr.String()
	if strings.Contains(out, "could not disable core dumps") {
		t.Fatalf("broker could not disable core dumps: %s", out)
	}
	if !strings.Contains(out, "broker requires --vault") {
		t.Fatalf("unexpected startup output: %s", out)
	}
	// Direct assertion: the helper disables both mechanisms in-process.
	if err := disableCoreDumps(); err != nil {
		t.Fatalf("disableCoreDumps: %v", err)
	}
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != 0 {
		t.Fatalf("RLIMIT_CORE soft = %d, want 0", after.Cur)
	}
	if d := dumpableStatus(t); d != 0 {
		t.Fatalf("process still dumpable=%d after disableCoreDumps; piped core handlers (apport/systemd-coredump) would persist the heap", d)
	}
}
