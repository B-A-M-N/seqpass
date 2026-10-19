//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDumps disables core production for the broker process. The
// broker stages relay payloads in memory; a crash dumping the heap would
// persist plaintext outside every guarded surface (§11 crash outputs).
// Two mechanisms are needed:
//
//   - RLIMIT_CORE=0 blocks file-backed core dumps. It does NOT govern
//     piped handlers: when core_pattern names a userspace collector
//     (apport, systemd-coredump — the default on modern distros), the
//     kernel bypasses the rlimit and hands the full heap to that
//     program, which persists it (man 5 core).
//   - PR_SET_DUMPABLE=0 marks the task non-dumpable, which the kernel
//     checks BEFORE invoking any handler (file or pipe), and which
//     additionally blocks unprivileged ptrace of staged plaintext.
//
// Children (pinned drivers) inherit both properties. Best effort: a
// refusal is a startup warning, not a hard failure.
func disableCoreDumps() error {
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &old); err != nil {
		return fmt.Errorf("read RLIMIT_CORE: %w", err)
	}
	if old.Cur != 0 {
		zero := unix.Rlimit{Cur: 0, Max: 0}
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &zero); err != nil {
			// Some systems allow raising soft limits only up to the
			// hard limit; try zeroing the soft limit alone.
			soft := unix.Rlimit{Cur: 0, Max: old.Max}
			if err2 := unix.Setrlimit(unix.RLIMIT_CORE, &soft); err2 != nil {
				return fmt.Errorf("set RLIMIT_CORE: %w", err)
			}
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", err)
	}
	return nil
}
