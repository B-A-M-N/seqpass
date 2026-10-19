package secureops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

func init() {
	Register(&gitFetch{})
}

// Pinned git remote profiles (objective §7): the trusted destination
// registration pins the remote URL; the broker runs a pinned git binary
// with a fixed argument template. This is not an arbitrary clone/push
// operation, and it must not become one:
//
//   - the remote URL is a registration fact (strict grammar below) — the
//     agent has no parameter that names a remote, so "fetch from anywhere"
//     is unrepresentable;
//   - the git executable is a broker-host pinned absolute path subject to
//     the same file-facts discipline as process-pinned executables
//     (absolute, resolved, regular, owner-checked, private ancestors);
//   - the agent supplies only a strictly validated branch name. There is
//     no shell and no argument template the agent can extend: the branch
//     never reaches argv as an option (it is always prefixed into a
//     broker-composed refs/heads/<branch> refspec, and the grammar has no
//     option characters), and `--` closes the option parser;
//   - the credential NEVER appears in argv, the environment, a URL, a
//     file, or git's output. It is composed into a git credential-fill
//     protocol response and delivered on an inherited file descriptor to
//     the pinned credential helper `!cat <&3` — the helper's text in argv
//     is a static constant, not credential material. URL-embedded
//     passwords and askpass programs are structurally impossible here;
//   - the child environment is fixed and additionally neutralizes global,
//     system and prompt-driven configuration (a hostile global gitconfig
//     could otherwise rewrite the pinned URL via insteadOf or install its
//     own credential helpers);
//   - git's stdout and stderr are drained and discarded — error text may
//     echo the remote URL and is never returned raw. The model-visible
//     contract is a small closed DTO (fetched/remote/branch/head);
//   - the child runs under bounded resource limits and a hard timeout,
//     in its own process group that is killed on timeout.
//
// Completion is ResponseValidated: a fetch is read-only on the remote and
// on every broker-visible surface (the scratch mirror is broker-owned and
// discarded), so correct authorization + a successful fetch IS completion.
const (
	DestTypeGitPinned = "git-pinned"

	gitRemoteMax   = 2048
	gitRefMax      = 200
	gitTimeout     = 30 * time.Second
	gitHeadFileMax = 4096

	// gitHelperSnippet is the entire credential helper, as a constant.
	// It instructs git to read the pre-composed credential-fill response
	// from inherited file descriptor 3 and print it on stdout, which is
	// exactly the credential-fill protocol. Credential bytes never appear
	// in the snippet, so its presence in argv is not exposure. Git runs
	// "!"-helpers through its shell layer as `sh -c '<helper> "$@"'
	// <helper> <operation>` — it appends the operation name ("get") as a
	// shell argument — so the redirection must live inside a quoted
	// `sh -c` command whose positional parameters are never consumed;
	// `cat <&3` directly would see "get" as a file operand and fail.
	gitHelperSnippet = "! sh -c 'cat <&3'"
)

// gitExecutable is the pinned git binary. Production pins /usr/bin/git;
// tests substitute a wrapper script that dumps argv/env and then execs
// the real binary, exactly like the process-pinned tests do.
var gitExecutable = "/usr/bin/git"

// ParseGitRemote is the registration-time grammar for a pinned git
// remote: https://host[:port]/path, file:///abs/path, or — for
// qualification only, mirroring the pinned-HTTP loopback exception —
// http://127.0.0.1:port/path or http://localhost:port/path. Everything
// else is refused: no userinfo (a URL-embedded credential would land in
// argv), no other schemes (ssh://, git://, ext:: carry no broker-injected
// credential at all), no query, fragment, or control characters.
func ParseGitRemote(raw string) (string, error) {
	if raw == "" || len(raw) > gitRemoteMax {
		return "", errors.New("invalid remote: empty or too long")
	}
	if !utf8.ValidString(raw) {
		return "", errors.New("invalid remote: not valid UTF-8")
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f {
			return "", errors.New("invalid remote: control or whitespace character")
		}
	}
	switch {
	case strings.HasPrefix(raw, "https://"):
		return validateGitHostURL(raw, "https://")
	case strings.HasPrefix(raw, "http://127.0.0.1:"), strings.HasPrefix(raw, "http://localhost:"):
		return validateGitHostURL(raw, "http://")
	case strings.HasPrefix(raw, "file://"):
		p := raw[len("file://"):]
		if !strings.HasPrefix(p, "/") || p == "/" {
			return "", errors.New("invalid remote: file:// requires an absolute repository path")
		}
		if strings.ContainsAny(p, "?#@") {
			return "", errors.New("invalid remote: query, fragment or userinfo in file remote")
		}
		return raw, nil
	default:
		return "", errors.New("invalid remote: want https://host[:port]/path, file:///abs/path, or loopback http (qualification)")
	}
}

// validateGitHostURL enforces the host[:port] grammar of the pinned HTTP
// origins, with a required path component.
func validateGitHostURL(raw, scheme string) (string, error) {
	rest := raw[len(scheme):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return "", errors.New("invalid remote: path missing")
	}
	hostport, path := rest[:slash], rest[slash:]
	if hostport == "" {
		return "", errors.New("invalid remote: host missing")
	}
	if strings.Contains(hostport, "@") {
		return "", errors.New("invalid remote: userinfo refused")
	}
	host, port := hostport, ""
	hasPort := false
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		host, port = hostport[:i], hostport[i+1:]
		hasPort = true
	}
	if hasPort {
		if port == "" || len(port) > 5 {
			return "", errors.New("invalid remote: port out of range")
		}
		n := 0
		for _, r := range port {
			if r < '0' || r > '9' {
				return "", errors.New("invalid remote: port must be numeric")
			}
			n = n*10 + int(r-'0')
		}
		if n < 1 || n > 65535 {
			return "", errors.New("invalid remote: port out of range")
		}
	} else if scheme == "http://" {
		return "", errors.New("invalid remote: loopback http requires an explicit port")
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "[]:") ||
		host[0] == '-' || host[0] == '.' || strings.Contains(host, "..") {
		return "", errors.New("invalid remote: malformed hostname")
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return "", errors.New("invalid remote: malformed hostname")
		}
	}
	if strings.ContainsAny(path, "?#@") {
		return "", errors.New("invalid remote: query, fragment or userinfo in path")
	}
	return raw, nil
}

// ValidateGitRef is the only agent-supplied degree of freedom: a branch
// name. The grammar admits exactly [A-Za-z0-9][A-Za-z0-9._/-]* with no
// doubled or dangling components, no "..", and no ".lock" suffix — so no
// option prefix (leading dash impossible), no refspec colon, no glob, no
// whitespace, and the value is safe to echo in summaries and audit
// records. The broker composes the full refspec itself; the agent never
// writes one.
func ValidateGitRef(raw string) error {
	if raw == "" || len(raw) > gitRefMax {
		return errors.New("invalid ref: empty or too long")
	}
	if !utf8.ValidString(raw) {
		return errors.New("invalid ref: not valid UTF-8")
	}
	if raw[0] == '-' {
		return errors.New("invalid ref: leading dash")
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_', r == '/':
		default:
			return errors.New("invalid ref: unsupported character")
		}
	}
	if strings.Contains(raw, "..") || strings.Contains(raw, "//") {
		return errors.New("invalid ref: empty or doubled component")
	}
	if strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, ".") || strings.HasSuffix(raw, ".lock") {
		return errors.New("invalid ref: malformed ref component")
	}
	return nil
}

type gitFetch struct{}

func (g *gitFetch) Name() string               { return "git.fetch" }
func (g *gitFetch) Completion() CompletionMode { return ResponseValidated }
func (g *gitFetch) RequiresDestination() bool  { return true }
func (g *gitFetch) Describe() DriverInfo {
	return DriverInfo{
		Description: "Authenticated fetch of one branch from the operator-pinned git remote into a broker-owned scratch mirror: credential delivered out-of-band via git's credential protocol on a controlled file descriptor, projected result only (never git output)",
		Params: []ParamInfo{
			{Name: "ref", Description: "Branch name on the pinned remote (plain branch name; the refspec is composed by the broker)"},
		},
		ResourceKind: "git.remote",
		Completion:   ResponseValidated,
		Destination:  true,
	}
}
func (g *gitFetch) AllowedParams() []string { return []string{"ref"} }

func (g *gitFetch) Resource(params map[string]string) ResourceDescriptor {
	if err := ValidateGitRef(params["ref"]); err != nil {
		return ResourceDescriptor{Kind: "git.remote", Identifier: "invalid"}
	}
	return ResourceDescriptor{Kind: "git.remote", Identifier: params["ref"]}
}

func (g *gitFetch) Validate(in UseInput) error {
	if err := ValidateGitRef(in.Params["ref"]); err != nil {
		return err
	}
	// Remote validation needs the destination record; at submission time
	// it is absent, and Execute re-checks everything with it present.
	if in.Dest != nil {
		_, err := ParseGitRemote(in.Dest.Endpoint)
		return err
	}
	return nil
}

// gitChildEnv is the fixed child environment. Nothing is inherited, and
// the git-specific entries neutralize every configuration source that
// could steer the pinned URL or add credential paths: global config
// (GIT_CONFIG_GLOBAL, HOME), system config (GIT_CONFIG_NOSYSTEM,
// GIT_CONFIG_SYSTEM) and interactive prompting (GIT_TERMINAL_PROMPT=0 —
// a profile that would need to prompt must fail closed instead).
func gitChildEnv(home string) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"LANG=C.UTF-8",
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func (g *gitFetch) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
	if in.Dest == nil {
		return SafeResult{}, errors.New("pinned destination missing")
	}
	if in.Dest.Type != DestTypeGitPinned {
		return SafeResult{}, fmt.Errorf("destination type %q is not %s", in.Dest.Type, DestTypeGitPinned)
	}
	remote, err := ParseGitRemote(in.Dest.Endpoint)
	if err != nil {
		return SafeResult{}, err
	}
	ref := in.Params["ref"]
	if err := ValidateGitRef(ref); err != nil {
		return SafeResult{}, err
	}
	if err := checkPinnedExecutable(gitExecutable); err != nil {
		return SafeResult{}, errors.New("pinned git executable not available")
	}
	if cred.Value == "" && cred.Components["password"] == "" {
		return SafeResult{}, errors.New("no credential")
	}
	// Credential placement: the primary value is the password; an optional
	// "username" component names the account; an optional "password"
	// component overrides the primary value. Any other component is
	// refused rather than silently ignored — a credential half-consumed by
	// an undocumented placement is a handoff incident, not a projection
	// detail.
	token := cred.Value
	user := "git"
	for name, value := range cred.Components {
		switch name {
		case "username":
			if value != "" {
				user = value
			}
		case "password":
			if value != "" {
				token = value
			}
		default:
			return SafeResult{}, fmt.Errorf("unsupported credential component %q for git.fetch", name)
		}
	}
	if token == "" {
		return SafeResult{}, errors.New("no credential")
	}
	if strings.ContainsAny(token, "\x00\n\r") {
		// Newlines would corrupt the credential-fill response; such a
		// credential is unusable for this profile and must fail closed,
		// not truncate silently.
		return SafeResult{}, errors.New("credential bytes unusable for the git credential protocol")
	}
	// The credential-fill response is composed in memory, written to the
	// controlled file descriptor, and zeroed when execution ends. It never
	// touches argv, the environment, a file, or any returned result.
	fill := []byte("username=" + user + "\npassword=" + token + "\n\n")
	defer clear(fill)

	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	// Private per-execution working directory: the scratch mirror never
	// collides across executions and is discarded afterwards.
	workDir, err := os.MkdirTemp("", "seqpass-git-")
	if err != nil {
		return SafeResult{}, errors.New("working directory unavailable")
	}
	if err := os.Chmod(workDir, 0700); err != nil {
		_ = os.RemoveAll(workDir)
		return SafeResult{}, errors.New("working directory unavailable")
	}
	defer os.RemoveAll(workDir)
	mirror := filepath.Join(workDir, "mirror")

	// Step 1: broker-owned scratch repository, fixed arguments, no
	// credential involvement.
	initCmd := exec.CommandContext(ctx, gitExecutable, "init", "--bare", "--quiet", mirror)
	initCmd.Env = gitChildEnv(workDir)
	initCmd.Dir = workDir
	if err := initCmd.Run(); err != nil {
		return SafeResult{}, errors.New("git initialization failed")
	}

	// Step 2: authenticated fetch. The argv is entirely broker-composed:
	// pinned helper reset + our helper (static text), the pinned remote,
	// and the broker-composed refspec. `--` closes the option parser, so
	// even a hypothetically malformed ref cannot become an option.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return SafeResult{}, errors.New("credential handoff setup failed")
	}
	defer func() {
		_ = pipeR.Close()
	}()
	child := exec.CommandContext(ctx, gitExecutable,
		"-c", "credential.helper=",
		"-c", "credential.helper="+gitHelperSnippet,
		"fetch", "--", remote, "refs/heads/"+ref)
	child.Env = gitChildEnv(workDir)
	child.ExtraFiles = []*os.File{pipeR} // fd 3: the credential-fill response
	child.SysProcAttr = pinnedProcAttr()
	// Run inside the scratch mirror: the fetch writes its objects there.
	child.Dir = mirror
	stdout, err := child.StdoutPipe()
	if err != nil {
		return SafeResult{}, errors.New("git setup failed")
	}
	stderr, err := child.StderrPipe()
	if err != nil {
		return SafeResult{}, errors.New("git setup failed")
	}
	if err := child.Start(); err != nil {
		// No path or exec diagnostics: the destination and executable were
		// validated, so a start failure is transient and the audit trail
		// already records the operation identity.
		return SafeResult{}, errors.New("pinned git executable could not be started")
	}
	applyGitLimits(child.Process.Pid)
	writeErr := make(chan error, 1)
	go func() {
		_, werr := pipeW.Write(fill)
		_ = pipeW.Close()
		writeErr <- werr
	}()
	// Drain both pipes so a chatty child cannot deadlock on a full pipe;
	// git output is never interpreted or returned.
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	go func() { _, _ = io.Copy(io.Discard, stdout) }()

	waitErr := child.Wait()
	// The helper is only invoked when the transport needs authentication
	// (never for file:// remotes), so a failed or unread write is not an
	// incident: the fetch exit status is authoritative, and any transport
	// that needed the credential without receiving it fails closed below.
	_ = <-writeErr
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(child.Process)
		return SafeResult{}, errors.New("git fetch exceeded its time budget")
	}
	if waitErr != nil {
		// Fixed error only: git diagnostics may echo the remote URL and
		// transport details, and are never surfaced.
		return SafeResult{}, errors.New("git fetch failed")
	}

	// Project: read FETCH_HEAD (broker-owned file), take the leading
	// object name of the first line. Everything else git printed is
	// discarded, not redacted.
	head := ""
	if raw, rerr := os.ReadFile(filepath.Join(mirror, "FETCH_HEAD")); rerr == nil {
		if len(raw) > gitHeadFileMax {
			raw = raw[:gitHeadFileMax]
		}
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			raw = raw[:i]
		}
		if field, _, ok := bytes.Cut(raw, []byte{'\t'}); ok {
			if oid := string(bytes.TrimSpace(field)); isGitOID(oid) {
				head = oid
			}
		}
	}

	data := map[string]interface{}{"fetched": true}
	if !strings.Contains(ref, token) {
		data["branch"] = ref
	}
	if !strings.Contains(remote, token) {
		data["remote"] = remote
	}
	if head != "" && !strings.Contains(head, token) {
		data["head"] = head
	}
	summary := "git fetch completed"
	if !strings.Contains(ref, token) {
		summary = fmt.Sprintf("git fetch completed (branch %s)", ref)
	}
	return SafeResult{Summary: summary, Data: data}, nil
}

// isGitOID reports whether s is a lowercase hexadecimal object name
// (SHA-1 or SHA-256), the only commit-ish shape this DTO projects.
func isGitOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
