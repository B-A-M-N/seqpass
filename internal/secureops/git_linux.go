//go:build linux

package secureops

import (
	"golang.org/x/sys/unix"
)

// gitChildLimits bounds what a runaway git child can take with it, on the
// same principle as the pinned-process profile. The file-size cap is
// larger than the generic one because a legitimate packfile is not
// bounded by one MiB; the remote is still an operator-pinned fact.
func gitChildLimits() []unixRlimit {
	lim := func(cur, max uint64) unix.Rlimit {
		return unix.Rlimit{Cur: cur, Max: max}
	}
	return []unixRlimit{
		{unix.RLIMIT_CPU, lim(10, 10)},
		{unix.RLIMIT_AS, lim(512<<20, 512<<20)},
		{unix.RLIMIT_FSIZE, lim(64<<20, 64<<20)},
		{unix.RLIMIT_NOFILE, lim(64, 64)},
	}
}

// applyGitLimits installs the limits on the started git child, before the
// timeout window matters. Best effort: a child that exits before the call
// lands simply completed; the operation reports its real outcome either
// way.
func applyGitLimits(pid int) {
	if pid <= 0 {
		return
	}
	for _, l := range gitChildLimits() {
		_ = unix.Prlimit(pid, l.res, &l.lim, nil)
	}
}
