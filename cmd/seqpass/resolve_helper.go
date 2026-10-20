package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
)

// resolveHelperCmd implements the trusted credential-resolution helper
// (P0-1): a short-lived, one-request process spawned by the broker's
// authorized execution path. It exists so that AegisKeys' /proc/<pid>/exe
// peer verification can authenticate the resolving process while the
// long-lived broker itself stays non-dumpable (PR_SET_DUMPABLE=0).
//
// Process contract:
//   - ONE request on the inherited descriptor (fd 3, a private CLOEXEC
//     socketpair end), ONE response on the same descriptor, exit.
//   - No listening socket; direct agent connections are unrepresentable.
//   - Credential material travels only on the inherited descriptor. This
//     command never writes to stdout or stderr on the credential path, and
//     its stdout/stderr are /dev/null by the spawner.
//   - Core files are disabled via RLIMIT_CORE=0. PR_SET_DUMPABLE is
//     deliberately LEFT ALONE (default 1): being dumpable-by-the-kernel is
//     the mechanism by which AegisKeys can verify this process's
//     executable identity. The single in-flight credential is the only
//     plaintext present, for the process's millisecond-scale lifetime.
//   - The helper performs no authorization decisions: it forwards the
//     approved (binding, operation, operation_id) triple; AegisKeys'
//     grant + operation-allowlist enforcement is unchanged.
//
// Exit codes: 0 = response delivered (even if the response reports a
// broker denial); 2 = protocol/usage failure (no response delivered).
func resolveHelperCmd(args []string) {
	fs := flag.NewFlagSet("resolve-helper", flag.ExitOnError)
	sockF := fs.String("socket", "", "AegisKeys broker socket (HTTP-over-Unix)")
	fdF := fs.Int("fd", 3, "inherited descriptor number for the broker exchange")
	_ = fs.Parse(args)

	// RLIMIT_CORE=0 only — see the process contract above for why
	// PR_SET_DUMPABLE must stay at its default for this process. Best
	// effort: a refusal is a warning on stderr (never the credential
	// channel).
	if err := disableCoreFiles(); err != nil {
		fmt.Fprintf(os.Stderr, "resolve-helper: could not disable core files: %v\n", err)
	}
	// Ignore SIGINT/SIGTERM handlers beyond default: the process is
	// one-shot; a signal kill leaves at most the single in-flight
	// credential in a core that RLIMIT_CORE=0 prevents.
	signal.Ignore(syscall.SIGHUP)

	if *sockF == "" {
		fmt.Fprintln(os.Stderr, "resolve-helper: --socket is required")
		os.Exit(2)
	}
	conn, err := aegiskeys.LoadHelperConnAt(*fdF)
	if err != nil {
		// No inherited descriptor: nothing to serve, nothing to leak.
		fmt.Fprintf(os.Stderr, "resolve-helper: inherited descriptor: %v\n", err)
		os.Exit(2)
	}
	if err := aegiskeys.HelperServe(conn, *sockF); err != nil {
		// The sentinel response (if any) already went to the descriptor.
		// Never echo the error text: it may quote request material.
		fmt.Fprintln(os.Stderr, "resolve-helper: exchange failed")
		conn.Close() //nolint:errcheck
		os.Exit(2)
	}
	conn.Close() //nolint:errcheck
}
