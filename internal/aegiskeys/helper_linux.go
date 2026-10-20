//go:build linux

package aegiskeys

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

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

// helperEnvAllowlist is the closed set of environment variables the helper
// may inherit: Go runtime knobs only. Everything else in the broker's
// environment — including anything secret-shaped — is dropped. The helper
// needs none of the parent's application configuration: the AegisKeys
// socket path travels on argv, the request on the inherited descriptor.
// Non-matching variables are never forwarded, so the broker's environment
// can never become an implicit credential channel to the helper.
var helperEnvAllowlist = map[string]bool{
	"GODEBUG":    true,
	"GOGC":       true,
	"GOMEMLIMIT": true,
	"GOMAXPROCS": true,
}

// minimalHelperEnv builds the helper's explicit environment from the
// allowlist above.
func minimalHelperEnv() []string {
	return HelperEnv()
}

// HelperEnv returns the helper child's environment: only allowlisted Go
// runtime knobs from the current process environment. Exported for tests
// that re-exec the test binary in helper mode (the hook must reproduce the
// production environment exactly) and for deployment tooling that needs
// the same filter.
func HelperEnv() []string {
	env := make([]string, 0, len(helperEnvAllowlist))
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 && helperEnvAllowlist[kv[:i]] {
			env = append(env, kv)
		}
	}
	return env
}

// helperCommand builds the exec of the trusted resolve helper. The child
// receives the socketpair exclusively as fd 3; it inherits NO secret-bearing
// environment — only allowlisted Go runtime knobs (helperEnvAllowlist) —
// and no argv secrets (only the helper mode, the AegisKeys socket PATH, and
// the fd number are on argv).
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
	cmd.Env = minimalHelperEnv()
	return cmd
}
