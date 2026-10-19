//go:build linux

package secureops

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// pinnedProcAttr gives the pinned child its own process group, so the
// timeout kill takes the whole tree rather than only the direct child.
// Resource limits are applied after start via applyPinnedLimits; this
// platform's SysProcAttr carries no Rlimit field.
func pinnedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// pinnedChildLimits bounds what a runaway pinned executable can take with
// it: modest CPU and address space, a small file-size cap and a tight
// descriptor budget. They are a blast-radius measure, not a sandbox — the
// operator still pins only executables the broker identity may be trusted
// to run.
func pinnedChildLimits() []unixRlimit {
	lim := func(cur, max uint64) unix.Rlimit {
		return unix.Rlimit{Cur: cur, Max: max}
	}
	return []unixRlimit{
		{unix.RLIMIT_CPU, lim(10, 10)},
		{unix.RLIMIT_AS, lim(512<<20, 512<<20)},
		{unix.RLIMIT_FSIZE, lim(1<<20, 1<<20)},
		{unix.RLIMIT_NOFILE, lim(64, 64)},
	}
}

type unixRlimit struct {
	res int
	lim unix.Rlimit
}

// applyPinnedLimits installs the limits on the started child, before the
// timeout window matters. Best effort: a child that exits before the call
// lands simply completed; the operation reports its real outcome either
// way. The window between Start and this call is accepted because the
// executable is an operator-pinned, identity-checked file — the limits
// bound accidents, not adversary-controlled code.
func applyPinnedLimits(pid int) {
	if pid <= 0 {
		return
	}
	for _, l := range pinnedChildLimits() {
		_ = unix.Prlimit(pid, l.res, &l.lim, nil)
	}
}

// killProcessGroup takes down the whole pinned process tree after a
// timeout. Best effort by design: the operation already reports a
// timeout failure.
func killProcessGroup(p *os.Process) {
	if p == nil {
		return
	}
	_ = unix.Kill(-p.Pid, unix.SIGKILL)
}
