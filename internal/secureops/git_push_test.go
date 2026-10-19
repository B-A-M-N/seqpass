package secureops

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

// gitPushFixture builds the pinned topology for git.push: a worktree
// source repository on branch "probe" with one commit, and a bare remote
// cloned from it (so the remote already has the branch at the same tip).
// secondCommit advances the source branch and returns the new tip.
func gitPushFixture(t *testing.T, realGit string) (source, remote, tip1 string) {
	t.Helper()
	source, tip1 = localRepoFixture(t, realGit, "probe")
	// The source repository is a pinned path, so it must satisfy the
	// pinned-path facts itself: git init honors the ambient umask, which
	// may leave the directory group-writable. A real operator pins a
	// private working copy the same way.
	if err := os.Chmod(source, 0700); err != nil {
		t.Fatal(err)
	}
	remoteDir := filepath.Join(filepath.Dir(source), "remote.git")
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	run := func(args ...string) {
		cmd := exec.Command(realGit, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture %v: %v: %s", args, err, out)
		}
	}
	run("clone", "--quiet", "--bare", "file://"+source, remoteDir)
	return source, remoteDir, tip1
}

func secondCommit(t *testing.T, realGit, source string) string {
	t.Helper()
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	cmd := exec.Command(realGit, "-C", source, "commit", "--allow-empty", "-m", "two")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second commit: %v: %s", err, out)
	}
	cmd = exec.Command(realGit, "-C", source, "rev-parse", "probe")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func gitPushDest(remote, source string) *types.Destination {
	d := gitPinnedDest("file://" + remote)
	d.SourceRepo = source
	return d
}

// assertNoMarker walks every regular file under root and fails if the
// synthetic credential appears anywhere — the push must leave no
// credential trace in the source repository, the remote, or git metadata.
func assertNoMarker(t *testing.T, root, marker string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // unreadable (permissions) cannot contain the marker
		}
		if strings.Contains(string(body), marker) {
			t.Errorf("credential marker found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGitPushLocalHappyPath(t *testing.T) {
	realGit := hasGit(t)
	source, remote, _ := gitPushFixture(t, realGit)
	tip2 := secondCommit(t, realGit, source)

	d, err := Lookup("git.push")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.push", Target: "dg", Dest: gitPushDest(remote, source),
			Params: map[string]string{"ref": "probe"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Data["pushed"] != true {
		t.Fatalf("pushed flag missing: %v", res.Data)
	}
	if res.Data["branch"] != "probe" {
		t.Fatalf("branch lost: %v", res.Data)
	}
	if res.Data["remote"] != "file://"+remote {
		t.Fatalf("remote lost: %v", res.Data)
	}
	if res.Data["head"] != tip2 {
		t.Fatalf("head = %v, want %s", res.Data["head"], tip2)
	}
	for k := range res.Data {
		switch k {
		case "pushed", "branch", "remote", "head":
		default:
			t.Fatalf("unexpected key %q in model output", k)
		}
	}
	if err := ValidateSafeResult(res); err != nil {
		t.Fatalf("result violates the shared DTO contract: %v", err)
	}
	if err := ValidateCredentialNonDisclosure(res, Credential{Value: gitMarker}); err != nil {
		t.Fatalf("credential disclosure gate rejected an honest result: %v", err)
	}

	// Independent effect verification: the bare remote's ref now points at
	// the pushed tip (read directly from the remote's ref file).
	remoteRef, err := os.ReadFile(filepath.Join(remote, "refs", "heads", "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(remoteRef)); got != tip2 {
		t.Fatalf("remote ref = %s, want %s", got, tip2)
	}
	// No credential trace anywhere in either repository tree.
	assertNoMarker(t, remote, gitMarker)
	assertNoMarker(t, source, gitMarker)
}

// The core contract, mirroring git.fetch: the credential reaches git ONLY
// through the credential-fill response on the controlled file descriptor.
func TestGitPushCredentialPlacement(t *testing.T) {
	realGit := hasGit(t)
	source, remote, _ := gitPushFixture(t, realGit)
	argvDump, envDump := installGitWrapper(t, realGit)

	d, _ := Lookup("git.push")
	if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.push", Target: "dg", Dest: gitPushDest(remote, source),
			Params: map[string]string{"ref": "probe"}}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	argvBody, err := os.ReadFile(argvDump)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(argvBody)
	if !strings.Contains(argv, "[push]") || !strings.Contains(argv, "[--]") {
		t.Fatalf("fixed template missing: %q", argv)
	}
	if !strings.Contains(argv, "[refs/heads/probe]") {
		t.Fatalf("broker-composed refspec missing from argv: %q", argv)
	}
	if strings.Contains(argv, "--force") {
		t.Fatal("force flag must never appear in the composed argv")
	}
	if !strings.Contains(argv, "[credential.helper="+gitHelperSnippet+"]") {
		t.Fatalf("pinned credential helper missing from argv: %q", argv)
	}
	if strings.Contains(argv, gitMarker) {
		t.Fatal("credential leaked into argv")
	}

	envBody, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatal(err)
	}
	env := string(envBody)
	if strings.Contains(env, gitMarker) {
		t.Fatal("credential leaked into the child environment")
	}
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "SEQ_PASS_") {
			t.Fatalf("inherited environment entry: %q", line)
		}
		if strings.HasPrefix(line, "PATH=") && line != "PATH=/usr/bin:/bin" {
			t.Fatalf("unexpected PATH: %q", line)
		}
	}
	if !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(env, "GIT_CONFIG_GLOBAL=/dev/null") {
		t.Fatal("child git config neutralization missing")
	}
}

// No --force exists in the composed argv, so a non-fast-forward push fails
// with git's own refusal and the remote is untouched.
func TestGitPushNonFastForwardRefused(t *testing.T) {
	realGit := hasGit(t)
	source, remote, _ := gitPushFixture(t, realGit)
	tip2 := secondCommit(t, realGit, source)

	// Diverge the remote: commit on a clone of the bare remote and push
	// there directly, so the remote branch is no longer an ancestor of
	// the source branch.
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	cloneDir := filepath.Join(filepath.Dir(source), "diverge")
	run := func(args ...string) {
		cmd := exec.Command(realGit, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture %v: %v: %s", args, err, out)
		}
	}
	run("clone", "--quiet", "file://"+remote, cloneDir)
	run("-C", cloneDir, "commit", "--allow-empty", "-m", "divergent")
	run("-C", cloneDir, "push", "--quiet", "origin", "probe")

	d, _ := Lookup("git.push")
	if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.push", Target: "dg", Dest: gitPushDest(remote, source),
			Params: map[string]string{"ref": "probe"}}); err == nil {
		t.Fatal("non-fast-forward push must be refused")
	} else if err.Error() != "git push failed" {
		t.Fatalf("refusal must be the fixed error, got %q", err.Error())
	}

	// The remote ref was not changed by the refused push.
	remoteRef, err := os.ReadFile(filepath.Join(remote, "refs", "heads", "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(remoteRef)); got == tip2 {
		t.Fatal("refused push nonetheless updated the remote")
	}
	assertNoMarker(t, remote, gitMarker)
}

func TestGitPushRefusals(t *testing.T) {
	realGit := hasGit(t)
	source, remote, _ := gitPushFixture(t, realGit)
	d, _ := Lookup("git.push")

	execErr := func(dest *types.Destination, params map[string]string, cred Credential) error {
		_, err := d.Execute(context.Background(), cred,
			UseInput{Operation: "git.push", Target: "dg", Dest: dest, Params: params})
		return err
	}

	// Destination contract.
	if err := execErr(nil, map[string]string{"ref": "probe"}, Credential{Value: gitMarker}); err == nil {
		t.Fatal("nil destination refused")
	}
	if err := execErr(gitPinnedDest("http://127.0.0.1:39999/r.git"), map[string]string{"ref": "probe"}, Credential{Value: gitMarker}); err == nil {
		t.Fatal("wrong destination type refused")
	}

	// No credential.
	if err := execErr(gitPushDest(remote, source), map[string]string{"ref": "probe"}, Credential{}); err == nil {
		t.Fatal("empty credential refused")
	}

	// Injection refs.
	for _, bad := range []string{"", "-oEvil", "a..b", "x/", ".lock", "has space"} {
		if err := execErr(gitPushDest(remote, source), map[string]string{"ref": bad}, Credential{Value: gitMarker}); err == nil {
			t.Fatalf("ref %q must be refused", bad)
		}
	}

	// Unknown credential components are refused, not ignored.
	if err := execErr(gitPushDest(remote, source), map[string]string{"ref": "probe"},
		Credential{Value: gitMarker, Components: map[string]string{"host": "evil"}}); err == nil {
		t.Fatal("unknown credential component refused")
	}

	// A fetch-only destination (no pinned source) can never push: the
	// source repository is a registration fact, never an agent parameter.
	if err := execErr(gitPinnedDest(remote), map[string]string{"ref": "probe"}, Credential{Value: gitMarker}); err == nil {
		t.Fatal("destination without a pinned source repository refused")
	}

	// Not a git repository.
	notRepo := t.TempDir()
	if err := execErr(gitPushDest(remote, notRepo), map[string]string{"ref": "probe"}, Credential{Value: gitMarker}); err == nil {
		t.Fatal("non-repository source refused")
	}

	// Drift between registration and execution fails closed: a source
	// repository that has become group-writable is refused before any
	// credential material is composed. (Discriminating control for the
	// exec-time checkPinnedPath re-verification: removing the check lets
	// this push proceed.)
	drifted := filepath.Join(filepath.Dir(source), "drifted")
	if err := exec.Command(realGit, "clone", "--quiet", "file://"+source, drifted).Run(); err != nil {
		t.Fatalf("drift fixture clone: %v", err)
	}
	if err := os.Chmod(drifted, 0775); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(drifted, 0700) })
	if err := execErr(gitPushDest(remote, drifted), map[string]string{"ref": "probe"}, Credential{Value: gitMarker}); err == nil {
		t.Fatal("group-writable source repository must be refused")
	}
}

// ParseGitSourceRepo is the registration grammar for the pinned push
// source: absolute, no control characters, no virtual filesystems.
func TestParseGitSourceRepoGrammar(t *testing.T) {
	good := []string{"/srv/work/repo", "/home/op/project", "/tmp/scratch/repo"}
	for _, p := range good {
		if _, err := ParseGitSourceRepo(p); err != nil {
			t.Errorf("ParseGitSourceRepo(%q) refused: %v", p, err)
		}
	}
	bad := []string{
		"",                         // empty
		"relative/path",            // relative
		"/dev/null",                // virtual filesystem
		"/proc/self",               // virtual filesystem
		"/sys/fs/cgroup",           // virtual filesystem
		"/tmp/has space",           // whitespace
		"/tmp/ctrl\x01char",        // control character
		strings.Repeat("/a", 2049), // too long
	}
	for _, p := range bad {
		if _, err := ParseGitSourceRepo(p); err == nil {
			t.Errorf("ParseGitSourceRepo(%q) accepted", p)
		}
	}
}

func TestGitPushDiscoveryContract(t *testing.T) {
	d, err := Lookup("git.push")
	if err != nil {
		t.Fatal(err)
	}
	if !d.RequiresDestination() {
		t.Fatal("git.push must require a destination")
	}
	if got := strings.Join(d.AllowedParams(), ","); got != "ref" {
		t.Fatalf("AllowedParams = %q, want only ref", got)
	}
	if d.Completion() != ResponseValidated {
		t.Fatal("git.push must be ResponseValidated")
	}
	// Submission-time validation refuses injection refs and, with a
	// destination attached, credential-bearing remotes and unusable
	// source pins.
	if err := d.Validate(UseInput{Params: map[string]string{"ref": "ok-branch"}}); err != nil {
		t.Fatalf("valid ref refused: %v", err)
	}
	if err := d.Validate(UseInput{Params: map[string]string{"ref": "-oEvil"}}); err == nil {
		t.Fatal("submission-time validation accepted an injection ref")
	}
	if err := d.Validate(UseInput{Params: map[string]string{"ref": "main"},
		Dest: gitPinnedDest("https://u:p@h/r")}); err == nil {
		t.Fatal("submission-time validation accepted a credential-bearing remote")
	}
	if err := d.Validate(UseInput{Params: map[string]string{"ref": "main"},
		Dest: gitPinnedDest("https://git.example.com/o/r.git")}); err == nil {
		t.Fatal("submission-time validation accepted a destination without a source pin")
	}
}
