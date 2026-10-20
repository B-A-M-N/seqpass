// Package testruntime provides a configurable trusted-root helper for
// Unix-socket integration tests. It never weakens SeqPass's ancestor
// validation: it only chooses where to create a uniquely named test
// directory and records a structured blocked result when prerequisites
// are unavailable.
package testruntime

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// BlockedError reports a test-runtime prerequisite failure. Tests can
// surface this as a structured blocked result rather than a false pass.
type BlockedError struct {
	Path string
	Err  error
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("test runtime %s blocked: %v", e.Path, e.Err)
}

func (e *BlockedError) Unwrap() error { return e.Err }

// Dir returns a unique test directory under the operator-provided trusted
// root. The root must already exist and pass the same ancestor checks the
// broker uses; this helper does not create or mutate ancestors.
func Dir(t interface{ Name() string }) (string, error) {
	root := os.Getenv("SEQPASS_TEST_RUNTIME_DIR")
	if root == "" {
		return "", &BlockedError{Path: root, Err: fmt.Errorf("SEQPASS_TEST_RUNTIME_DIR is not set")}
	}
	fi, err := os.Lstat(root)
	if err != nil {
		return "", &BlockedError{Path: root, Err: err}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", &BlockedError{Path: root, Err: fmt.Errorf("trusted root is a symlink")}
	}
	if !fi.IsDir() {
		return "", &BlockedError{Path: root, Err: fmt.Errorf("trusted root is not a directory")}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
			return "", &BlockedError{Path: root, Err: fmt.Errorf("trusted root is not owned by broker or root")}
		}
		if fi.Mode().Perm()&0022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return "", &BlockedError{Path: root, Err: fmt.Errorf("trusted root is group/other-writable without sticky bit")}
		}
	}
	// t.Name() contains "/" for subtests, which MkdirTemp rejects as a
	// pattern, so a subtest could never obtain a runtime directory and would
	// silently skip even when the socket suites are required to run.
	//
	// The name is also TRUNCATED: AF_UNIX bind addresses are limited to
	// 107 bytes, and these directories host sockets (broker.sock etc.). A
	// long test name pushed the socket path past the limit and the bind
	// failed with EINVAL ("bind: invalid argument") — only visible when
	// SEQPASS_TEST_RUNTIME_DIR is set, i.e. exactly during qualification.
	// Uniqueness comes from MkdirTemp's random suffix, not the name.
	name := strings.ReplaceAll(t.Name(), "/", "_")
	if len(name) > 24 {
		name = name[:24]
	}
	dir, err := os.MkdirTemp(root, "seqpass-test-"+name+"-")
	if err != nil {
		return "", &BlockedError{Path: root, Err: err}
	}
	return dir, nil
}

// Skip records a structured blocked result for Unix-socket fixtures whose
// trusted runtime prerequisites are unavailable.
//
// A coverage run must not pass while silently omitting the socket suites, so
// SEQPASS_REQUIRE_RUNTIME turns a blocked prerequisite into a failure. The
// default stays portable: without the variable the suite skips.
func Skip(t interface {
	Skipf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}, err error) {
	if os.Getenv("SEQPASS_REQUIRE_RUNTIME") != "" {
		t.Fatalf("REQUIRED: %v (SEQPASS_REQUIRE_RUNTIME is set, so this suite must run)", err)
		return
	}
	t.Skipf("BLOCKED: %v", err)
}

// DirOrTemp is for service-level tests that do not bind sockets: it uses
// the configured trusted root when available, and otherwise falls back to
// the Go test temp dir. This avoids hardcoding /tmp while preserving
// normal CI behavior for non-socket tests.
func DirOrTemp(t interface {
	Name() string
	TempDir() string
}) string {
	if root := os.Getenv("SEQPASS_TEST_RUNTIME_DIR"); root != "" {
		if dir, err := Dir(t); err == nil {
			return dir
		}
	}
	return t.TempDir()
}

// NamedFunc adapts a plain function name to the Dir helper's minimal
// naming interface. It is not used for socket tests that need real
// per-test uniqueness.
type NamedFunc string

func (n NamedFunc) Name() string { return string(n) }
