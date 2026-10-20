//go:build linux

package aegiskeys

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// socketPair creates a private SOCK_STREAM AF_UNIX pair and returns the
// parent end as a net.Conn (deadlines work on net.Conn; a raw *os.File
// opened over a socketpair fd does not support SetDeadline on all hosts).
func socketPair() (server net.Conn, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	serverFile := os.NewFile(uintptr(fds[0]), "seqpass-helper-parent")
	child = os.NewFile(uintptr(fds[1]), "seqpass-helper-child")
	server, err = net.FileConn(serverFile)
	if err != nil {
		serverFile.Close() //nolint:errcheck
		child.Close()      //nolint:errcheck
		return nil, nil, err
	}
	serverFile.Close() //nolint:errcheck — FileConn duplicated the descriptor
	return server, child, nil
}

// TestingHelperCommand, when non-nil, replaces the default helper exec
// builder. Test-only: unit tests re-exec the test binary itself in helper
// mode (env-dispatched TestMain), because the test binary does not
// understand the `resolve-helper` subcommand argv. Production builds never
// set it.
var TestingHelperCommand func(ctx context.Context, helperPath, aegisSocket string, child *os.File) *exec.Cmd

// helperCommand builds the exec of the trusted resolve helper. The child
// receives the socketpair exclusively as fd 3; it inherits NO secret-bearing
// environment (the parent environment contains paths and SeqPass
// configuration only — the broker never holds credentials in env) and no
// argv secrets (only the helper mode, the AegisKeys socket PATH, and the
// fd number are on argv).
//
// PR_SET_DUMPABLE is deliberately NOT touched here: the helper's purpose
// is that AegisKeys can read /proc/<pid>/exe to authenticate it. Core
// files are disabled inside the helper itself (RLIMIT_CORE=0).
func helperCommand(ctx context.Context, helperPath, aegisSocket string, child *os.File) *exec.Cmd {
	if TestingHelperCommand != nil {
		return TestingHelperCommand(ctx, helperPath, aegisSocket, child)
	}
	cmd := exec.CommandContext(ctx, helperPath, "resolve-helper",
		"--socket", aegisSocket,
		"--fd", fmt.Sprint(helperDescriptorNumber))
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = os.Environ()
	return cmd
}
