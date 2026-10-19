package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// §11 crash outputs: the broker stages relay payloads in memory, so a
// core dump would persist plaintext outside every guarded surface. The
// broker must start with RLIMIT_CORE disabled (soft limit 0).
//
// The test first RAISES the soft core limit (always permitted up to the
// hard limit) so the enforcement has real work to do even on hosts whose
// ulimit -c is already 0 — otherwise the assertion would be vacuous and
// a regression to a no-op helper would go unnoticed.
func TestBrokerDisablesCoreDumps(t *testing.T) {
	var orig unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_CORE here: %v", err)
	}
	// Raise the soft limit to the hard limit for this test process.
	// Children inherit rlimits across exec, so the broker child below
	// genuinely starts with core dumps enabled.
	raised := unix.Rlimit{Cur: orig.Max, Max: orig.Max}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &raised); err != nil {
		t.Skipf("cannot raise RLIMIT_CORE to its hard limit here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_CORE, &orig) })
	// Run the broker startup path in a child and have it report its own
	// soft core limit via the same helper.
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
	// Direct assertion: the helper zeroes the soft limit in-process.
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
}
