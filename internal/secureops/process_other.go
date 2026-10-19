//go:build !linux

package secureops

import (
	"os"
	"os/exec"
)

// pinnedProcAttr gives the pinned child its own process group on
// non-Linux platforms where the field is available; SeqPass does not
// claim resource-limit protection it does not enforce. The pinned
// profile's other guarantees (fixed environment, stdin-only credential,
// no shell, projected output) are platform-independent.
func pinnedProcAttr() *exec.SysProcAttr {
	return &exec.SysProcAttr{Setpgid: true}
}

// killProcessGroup takes down the pinned child after a timeout. On
// non-Linux platforms only the direct child is targeted; the operation
// already reports a timeout failure either way.
func killProcessGroup(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
}
