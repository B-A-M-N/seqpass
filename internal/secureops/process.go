package secureops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/secretbridge/secretbridge/internal/types"
)

func init() {
	Register(&processRun{})
	if err := RegisterVerifierEx("process.run", "seqpass.process", "1", processVerifier{}); err != nil {
		panic(err.Error())
	}
}

// Pinned process adapter (objective §7): for commands where no typed API
// driver exists, the operator pins an executable on a registered
// process-pinned destination and the broker runs it with a constrained
// profile. This is NOT an unrestricted command executor, and it must not
// become one:
//
//   - the executable is a trusted-registration fact (absolute path,
//     regular file, no symlink components, owner root or the broker's
//     own UID, not group/world writable, no group/world-writable ancestor
//     directory) — never an agent parameter;
//   - arguments arrive only through the typed arg0..arg7 slots, one argv
//     element each; there is no shell, so no quoting, interpolation or
//     injection layer exists at all. To pin fixed flags, the operator
//     wraps the real command in a script and registers the wrapper;
//   - the child environment is fixed (no inheritance), so an inherited
//     environment can never carry credential material;
//   - the credential is delivered on stdin ONLY. A profile that would
//     need it in argv or the environment is structurally impossible;
//   - stdin/stdout/stderr are pipes owned by the broker — the child never
//     touches the operator's terminal, so no agent-accessible terminal
//     exists for this profile;
//   - output is never returned raw. The model-visible contract is the
//     exit status, or a closed projection of stdout parsed as JSON.
//     Free-form output is drained and discarded, not redacted;
//   - the child runs under bounded resource limits and a hard timeout,
//     in its own process group that is killed on timeout.
//
// Completion is ExternalPostcondition with an always-inconclusive
// verifier: a generic adapter cannot independently observe the pinned
// command's external effect, so the operation reports "exited 0; effect
// not independently verified" and post-dispatch failures surface as
// uncertain, never as confident success. Operators who need verified
// application write a typed driver with a real verifier instead.
const (
	DestTypeProcessPinned = "process-pinned"

	processMaxArgs     = 8
	processArgMax      = 1024
	processTimeout     = 30 * time.Second
	processJSONMax     = 64 * 1024
	processStderrDrain = 256 * 1024
	processMaxFieldStr = 512
)

type processRun struct{}

func (p *processRun) Name() string               { return "process.run" }
func (p *processRun) Completion() CompletionMode { return ExternalPostcondition }
func (p *processRun) RequiresDestination() bool  { return true }
func (p *processRun) Describe() DriverInfo {
	return DriverInfo{
		Description: "Run an operator-pinned executable with a constrained profile: fixed environment, no shell, credential on stdin only, exit status or projected JSON output",
		Params: []ParamInfo{
			{Name: "arg0", Description: "One argv element (optional; arg0..arg7 in order)"},
			{Name: "arg1", Description: "One argv element (optional)"},
			{Name: "arg2", Description: "One argv element (optional)"},
			{Name: "arg3", Description: "One argv element (optional)"},
			{Name: "arg4", Description: "One argv element (optional)"},
			{Name: "arg5", Description: "One argv element (optional)"},
			{Name: "arg6", Description: "One argv element (optional)"},
			{Name: "arg7", Description: "One argv element (optional)"},
		},
		ResourceKind: "process.executable",
		Completion:   ExternalPostcondition,
		Destination:  true,
	}
}

// AllowedParams returns the typed argument slots. They are deliberately
// positional and bounded: a single free-form "args" string would re-open
// the quoting and interpolation layer this driver exists to avoid.
func (p *processRun) AllowedParams() []string {
	return []string{"arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7"}
}

func (p *processRun) Resource(params map[string]string) ResourceDescriptor {
	// The executable is the resource the credential permission binds to;
	// it is a registration fact, so the descriptor stays coarse here and
	// the destination pin (dest_ids rules) carries the precision.
	return ResourceDescriptor{Kind: "process.executable", Identifier: "pinned"}
}

// ValidateProcessArg enforces one argv element: printable, no control
// bytes, no NUL (which exec would reject anyway), bounded. Empty values
// are refused: an empty argv element is never what the agent meant, and
// refusing keeps the audit trail unambiguous.
func ValidateProcessArg(raw string) error {
	if raw == "" {
		return errors.New("invalid arg: empty")
	}
	if len(raw) > processArgMax {
		return errors.New("invalid arg: too long")
	}
	if !utf8.ValidString(raw) {
		return errors.New("invalid arg: not valid UTF-8")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return errors.New("invalid arg: control character")
		}
	}
	return nil
}

func (p *processRun) Validate(in UseInput) error {
	for i := 0; i < processMaxArgs; i++ {
		k := fmt.Sprintf("arg%d", i)
		if v, ok := in.Params[k]; ok {
			if err := ValidateProcessArg(v); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	}
	if in.Dest != nil {
		return ValidateProcessPinned(in.Dest)
	}
	return nil
}

// ValidateProcessPinned is the full registration-time grammar for a
// process-pinned destination. It fails closed on anything that is not a
// strictly pinned, broker-owned executable.
func ValidateProcessPinned(d *types.Destination) error {
	if d == nil || d.Type != DestTypeProcessPinned {
		return fmt.Errorf("destination type must be %s", DestTypeProcessPinned)
	}
	if d.AuthMethod != "" && d.AuthMethod != "stdin" {
		return errors.New("process-pinned supports only stdin credential placement")
	}
	path, err := pinnedExecutable(d.Endpoint)
	if err != nil {
		return err
	}
	return checkPinnedExecutable(path)
}

// pinnedExecutable enforces the absolute, fully-resolved path grammar.
func pinnedExecutable(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 {
		return "", errors.New("invalid executable path")
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("executable path must be absolute")
	}
	if strings.Contains(raw, "\x00") {
		return "", errors.New("invalid executable path")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", errors.New("executable path not resolvable")
	}
	if resolved != raw {
		return "", errors.New("executable path must not contain symlink components")
	}
	return resolved, nil
}

// checkPinnedExecutable enforces the file facts: regular file, executable,
// not group/world writable, owned by root or the broker's own identity,
// and every ancestor directory not group/world writable.
func checkPinnedExecutable(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return errors.New("executable not accessible")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("executable must be a regular file")
	}
	if fi.Mode().Perm()&0111 == 0 {
		return errors.New("executable is not executable")
	}
	if fi.Mode().Perm()&0022 != 0 {
		return errors.New("executable must not be group/world writable")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return errors.New("executable must be owned by root or the broker identity")
	}
	// Ancestor directories: a group/world-writable ancestor would let
	// another local identity replace the pinned binary or plant a path
	// component, so the pin is only as strong as the weakest directory.
	// The canonical exception is the root-owned sticky /tmp: the kernel's
	// sticky-bit rename protection keeps self-owned entries safe from
	// every other local identity there. Other group/world-writable
	// ancestors are refused.
	dir := filepath.Dir(path)
	for {
		di, err := os.Stat(dir)
		if err != nil {
			return errors.New("executable ancestor not accessible")
		}
		if !di.IsDir() {
			return errors.New("executable ancestor is not a directory")
		}
		if di.Mode().Perm()&0022 != 0 {
			if dir == "/tmp" && di.Mode()&os.ModeSticky != 0 && uidOf(di) == 0 {
				// Canonical shared sticky root: safe for self-owned
				// entries, which the owner check already enforces.
				return nil
			}
			return fmt.Errorf("executable ancestor %s must not be group/world writable", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// uidOf returns the owner UID of a file info, or a value that fails the
// root check when the platform type is unavailable.
func uidOf(di os.FileInfo) uint32 {
	if st, ok := di.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return ^uint32(0)
}

// processArgv assembles the pinned argv from the typed slots, preserving
// positional order and failing closed on any invalid value.
func processArgv(params map[string]string) ([]string, error) {
	argv := make([]string, 0, processMaxArgs)
	for i := 0; i < processMaxArgs; i++ {
		k := fmt.Sprintf("arg%d", i)
		v, ok := params[k]
		if !ok || v == "" {
			continue
		}
		if err := ValidateProcessArg(v); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		argv = append(argv, v)
	}
	return argv, nil
}

// processEnv is the fixed child environment. Nothing is inherited: the
// broker's environment (and anything an attacker hid in it) cannot leak
// into the child, and the child cannot inherit a path that would smuggle
// credential material.
func processEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"LANG=C.UTF-8",
	}
}

func (p *processRun) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
	if in.Dest == nil {
		return SafeResult{}, errors.New("pinned destination missing")
	}
	if in.Dest.Type != DestTypeProcessPinned {
		return SafeResult{}, fmt.Errorf("destination type %q is not %s", in.Dest.Type, DestTypeProcessPinned)
	}
	if err := ValidateProcessPinned(in.Dest); err != nil {
		return SafeResult{}, err
	}
	argv, err := processArgv(in.Params)
	if err != nil {
		return SafeResult{}, err
	}
	if len(cred.Components) > 0 {
		// There is no honest wire format for components on stdin, so a
		// multi-component credential is refused rather than silently
		// flattened.
		return SafeResult{}, errors.New("multi-component credentials unsupported for process.run")
	}

	ctx, cancel := context.WithTimeout(ctx, processTimeout)
	defer cancel()
	child := exec.CommandContext(ctx, in.Dest.Endpoint, argv...)
	child.Env = processEnv()
	// Own process group: the timeout kill takes the whole tree, not just
	// the direct child.
	child.SysProcAttr = pinnedProcAttr() // Private per-execution working directory: the child never sees the
	// broker's cwd and cannot collide with concurrent executions.
	workDir, err := os.MkdirTemp("", "seqpass-exec-")
	if err != nil {
		return SafeResult{}, errors.New("working directory unavailable")
	}
	if err := os.Chmod(workDir, 0700); err != nil {
		_ = os.RemoveAll(workDir)
		return SafeResult{}, errors.New("working directory unavailable")
	}
	defer os.RemoveAll(workDir)
	child.Dir = workDir
	stdin, err := child.StdinPipe()
	if err != nil {
		return SafeResult{}, errors.New("process setup failed")
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		return SafeResult{}, errors.New("process setup failed")
	}
	stderr, err := child.StderrPipe()
	if err != nil {
		return SafeResult{}, errors.New("process setup failed")
	}
	if err := child.Start(); err != nil {
		// Do not surface path diagnostics; the destination was validated,
		// so a start failure is transient or an environment change and the
		// audit trail already records the operation identity.
		return SafeResult{}, errors.New("pinned executable could not be started")
	}
	applyPinnedLimits(child.Process.Pid)
	// Write the credential and close stdin so the child sees EOF. The
	// primary value is the only credential material this profile carries.
	writeErr := make(chan error, 1)
	go func() {
		_, werr := io.WriteString(stdin, cred.Value)
		_ = stdin.Close()
		writeErr <- werr
	}()
	// Drain stderr so a chatty child cannot deadlock on a full pipe; it is
	// never interpreted or returned.
	go func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(stderr, processStderrDrain))
	}()
	var stdoutBytes []byte
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		b, _ := io.ReadAll(io.LimitReader(stdout, processJSONMax+1))
		stdoutBytes = b
	}()
	waitErr := child.Wait()
	werr := <-writeErr
	<-stdoutDone
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(child.Process)
		return SafeResult{}, errors.New("pinned command exceeded its time budget")
	}
	// The exit status is authoritative once the child has been reaped. A
	// child that exits without reading its stdin (a pinned wrapper that
	// ignores the credential slot) races the credential write and can
	// surface EPIPE here; that must not mask the real exit status, or a
	// plain failure reads as a credential-handoff incident.
	if waitErr != nil {
		// Exit code only — argv, env and stderr are never echoed back.
		if ee, ok := waitErr.(*exec.ExitError); ok {
			return SafeResult{}, fmt.Errorf("pinned command exited with code %d", ee.ExitCode())
		}
		return SafeResult{}, errors.New("pinned command did not run to completion")
	}
	if werr != nil {
		// Zero exit but the credential write failed: the child may have
		// acted on a partial value, so the operation must not read as a
		// clean success.
		return SafeResult{}, errors.New("credential handoff to the pinned executable failed")
	}
	if len(stdoutBytes) == 0 {
		return SafeResult{
			Summary: "pinned command completed (exit 0, no output)",
			Data:    map[string]interface{}{"exit_code": 0.0},
		}, nil
	}
	if len(stdoutBytes) > processJSONMax {
		return SafeResult{}, errors.New("pinned command output too large")
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(stdoutBytes, &doc); err != nil {
		// Output is never returned raw: free-form output is discarded, not
		// redacted (objective §7 — prefer projection over redaction).
		return SafeResult{
			Summary: "pinned command completed (exit 0, non-JSON output discarded)",
			Data:    map[string]interface{}{"exit_code": 0.0},
		}, nil
	}
	data := projectFlat(doc, cred.Value)
	if len(data) < httpMaxFields {
		data["exit_code"] = 0.0
	}
	return SafeResult{
		Summary: "pinned command completed (exit 0, JSON projection)",
		Data:    data,
	}, nil
}

// processVerifier is the independent postcondition check for process.run.
// It cannot re-run the command (verifiers must never repeat the side
// effect) and has no independently authorized observation path, so it
// reports inconclusive with the durable receipt as evidence — exactly the
// "accepted is not applied" discipline the lifecycle contract requires.
// Its presence also makes the driver activatable at all: an
// ExternalPostcondition driver without a verifier is a configuration
// error and the broker refuses to start.
type processVerifier struct{}

func (processVerifier) Verify(_ context.Context, input UseInput, result SafeResult) (Outcome, error) {
	detail := "pinned command completed; external effect not independently observed"
	if code, ok := result.Data["exit_code"].(float64); ok {
		detail = fmt.Sprintf("pinned command exited %.0f; external effect not independently observed", code)
	}
	if err := ValidateOutcomeDetail(detail); err != nil {
		return Outcome{}, err
	}
	return Outcome{
		State:        OutcomeInconclusive,
		Detail:       detail,
		EvidenceRef:  input.OpID,
		EvidenceKind: "receipt",
		ObservedAt:   time.Now(),
	}, nil
}
