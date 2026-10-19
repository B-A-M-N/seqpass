//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDumps sets RLIMIT_CORE to zero for the broker process. The
// broker stages relay payloads in memory; a crash dumping the heap to a
// core file would persist plaintext outside every guarded surface (§11
// crash outputs). Applied at startup so every child inherits the limit.
func disableCoreDumps() error {
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &old); err != nil {
		return fmt.Errorf("read RLIMIT_CORE: %w", err)
	}
	if old.Cur == 0 {
		return nil
	}
	zero := unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &zero); err != nil {
		// Some systems allow raising soft limits only up to the hard
		// limit; try zeroing the soft limit alone before giving up.
		soft := unix.Rlimit{Cur: 0, Max: old.Max}
		if err2 := unix.Setrlimit(unix.RLIMIT_CORE, &soft); err2 != nil {
			return fmt.Errorf("set RLIMIT_CORE: %w", err)
		}
	}
	return nil
}
