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
)

func init() {
	Register(&gitPush{})
}

// git.push is the state-changing counterpart of git.fetch (objective §7):
// an authenticated push of an operator-pinned source repository's branch to
// the operator-pinned remote. The trust argument is identical to git.fetch,
// with one addition — the CONTENT pushed is also a registration fact, not an
// agent parameter:
//
//   - the remote is a registration fact (ParseGitRemote grammar — no
//     userinfo, no exotic schemes);
//   - the source repository path is a registration fact (PinnedPath
//     discipline: absolute, resolved, regular, owner-checked, private
//     ancestors) re-verified at execution time like any pinned executable;
//   - the agent supplies only the branch name. There is no shell, no
//     argument template the agent can extend: the branch is always prefixed
//     into a broker-composed refs/heads/<branch> refspec, and `--` closes
//     the option parser;
//   - the credential NEVER appears in argv, the environment, a URL, a file,
//     or the projected result. It reaches git only through the credential
//     helper on a controlled file descriptor;
//   - the result is a fixed DTO. Git's own output (which can echo remote
//     URLs and transport details) is drained and discarded, never surfaced.
//
// Push semantics are deliberately non-forcing: no --force flag exists in the
// composed argv, so a non-fast-forward push fails with git's own refusal.
// Deleting remote branches is unrepresentable (no :delete refspecs).
type gitPush struct{}

func (g *gitPush) Name() string               { return "git.push" }
func (g *gitPush) Completion() CompletionMode { return ResponseValidated }
func (g *gitPush) RequiresDestination() bool  { return true }
func (g *gitPush) Describe() DriverInfo {
	return DriverInfo{
		Description: "Authenticated push of one branch from the operator-pinned source repository to the operator-pinned git remote: credential delivered out-of-band via git's credential protocol on a controlled file descriptor, projected result only (never git output)",
		Params: []ParamInfo{
			{Name: "ref", Description: "Branch name to push (plain branch name; both the source repository and the remote are operator-pinned)"},
		},
		ResourceKind: "git.remote",
		Completion:   ResponseValidated,
		Destination:  true,
	}
}
func (g *gitPush) AllowedParams() []string { return []string{"ref"} }

func (g *gitPush) Resource(params map[string]string) ResourceDescriptor {
	if err := ValidateGitRef(params["ref"]); err != nil {
		return ResourceDescriptor{Kind: "git.remote", Identifier: "invalid"}
	}
	return ResourceDescriptor{Kind: "git.remote", Identifier: params["ref"]}
}

func (g *gitPush) Validate(in UseInput) error {
	if err := ValidateGitRef(in.Params["ref"]); err != nil {
		return err
	}
	// Remote and source-repo validation need the destination record; at
	// submission time it is absent, and Execute re-checks everything with
	// it present.
	if in.Dest != nil {
		if _, err := ParseGitRemote(in.Dest.Endpoint); err != nil {
			return err
		}
		if _, err := ParseGitSourceRepo(in.Dest.SourceRepo); err != nil {
			return err
		}
	}
	return nil
}

func (g *gitPush) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
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
	source, err := ParseGitSourceRepo(in.Dest.SourceRepo)
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
	token, user, err := gitCredentialPlacement(cred)
	if err != nil {
		return SafeResult{}, err
	}

	// The source repository must still look like the repository the
	// operator pinned: the same owner/ancestor checks a pinned executable
	// gets, plus a gitdir sanity check, re-verified now (drift between
	// registration and execution must fail closed).
	if err := checkPinnedPath(source); err != nil {
		return SafeResult{}, errors.New("pinned source repository failed verification")
	}
	if _, err := os.Stat(filepath.Join(source, "HEAD")); err != nil {
		if _, err2 := os.Stat(filepath.Join(source, ".git")); err2 != nil {
			return SafeResult{}, errors.New("pinned source repository is not a git repository")
		}
	}

	// The credential-fill response is composed in memory, written to the
	// controlled file descriptor, and zeroed when execution ends. It never
	// touches argv, the environment, a file, or any returned result.
	fill := []byte("username=" + user + "\npassword=" + token + "\n\n")
	defer clear(fill)

	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	// Authenticated push. The argv is entirely broker-composed: pinned
	// helper reset + our helper (static text), the pinned remote, and the
	// broker-composed refspec. `--` closes the option parser; no --force
	// exists, so a non-fast-forward push fails with git's own refusal.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return SafeResult{}, errors.New("credential handoff setup failed")
	}
	defer func() { _ = pipeR.Close() }()
	child := exec.CommandContext(ctx, gitExecutable,
		"-c", "credential.helper=",
		"-c", "credential.helper="+gitHelperSnippet,
		"push", "--", remote, "refs/heads/"+ref)
	child.Env = gitChildEnv(source)
	child.ExtraFiles = []*os.File{pipeR} // fd 3: the credential-fill response
	child.SysProcAttr = pinnedProcAttr()
	// Run inside the pinned source repository: the push reads its objects
	// from there and updates the remote.
	child.Dir = source
	stdout, err := child.StdoutPipe()
	if err != nil {
		return SafeResult{}, errors.New("git setup failed")
	}
	stderr, err := child.StderrPipe()
	if err != nil {
		return SafeResult{}, errors.New("git setup failed")
	}
	if err := child.Start(); err != nil {
		// No path or exec diagnostics: the destination, source, and
		// executable were validated, so a start failure is transient and
		// the audit trail already records the operation identity.
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
	// incident: the push exit status is authoritative, and any transport
	// that needed the credential without receiving it fails closed below.
	_ = <-writeErr
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(child.Process)
		return SafeResult{}, errors.New("git push exceeded its time budget")
	}
	if waitErr != nil {
		// Fixed error only: git diagnostics may echo the remote URL and
		// transport details, and are never surfaced.
		return SafeResult{}, errors.New("git push failed")
	}

	// Project: the post-push tip of the pushed branch, read from the
	// pinned source repository (broker-owned read of the local ref). A
	// non-fast-forward refusal already failed Wait above; nothing is
	// projected unless git reported success.
	head := gitBranchHead(source, ref)

	data := map[string]interface{}{"pushed": true}
	if !strings.Contains(ref, token) {
		data["branch"] = ref
	}
	if !strings.Contains(remote, token) {
		data["remote"] = remote
	}
	if head != "" && !strings.Contains(head, token) {
		data["head"] = head
	}
	summary := "git push completed"
	if !strings.Contains(ref, token) {
		summary = fmt.Sprintf("git push completed (branch %s)", ref)
	}
	return SafeResult{Summary: summary, Data: data}, nil
}

// gitBranchHead reads the tip of a branch from the repository at dir
// without executing git in the push path's error-prone direction: the ref
// file itself (loose) is authoritative for a freshly pushed branch, and a
// packed fallback resolves via packed-refs. Missing/ambiguous refs project
// nothing.
func gitBranchHead(dir, ref string) string {
	b, err := os.ReadFile(filepath.Join(dir, ".git", "refs", "heads", ref))
	if err != nil {
		b, err = os.ReadFile(filepath.Join(dir, "refs", "heads", ref))
		if err != nil {
			return ""
		}
	}
	oid := string(bytes.TrimSpace(b))
	if !isGitOID(oid) {
		return ""
	}
	return oid
}
