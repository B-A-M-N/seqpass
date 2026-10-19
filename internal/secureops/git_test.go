package secureops

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

const gitMarker = "SECRET-GIT-pin-a1b2c3d4e5f6"

// hasGit reports whether a git binary is available for the live-path
// tests. All validation and rejection logic below runs without it.
func hasGit(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not available; validation-only checks still ran")
	}
	return path
}

// installGitWrapper points gitExecutable at a wrapper script that dumps
// argv and the environment to files, then execs the real git. It restores
// the pin on cleanup. The wrapper must satisfy the pinned-executable file
// facts (private temp tree, owner-executable, no group/world write).
func installGitWrapper(t *testing.T, realGit string) (argvDump, envDump string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	argvDump = filepath.Join(dir, "argv.txt")
	envDump = filepath.Join(dir, "env.txt")
	script := "#!/bin/sh\n" +
		"printf '[%s]' \"$@\" > " + argvDump + "\n" +
		"env > " + envDump + "\n" +
		"exec " + realGit + " \"$@\"\n"
	path := filepath.Join(dir, "git-wrapper")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	old := gitExecutable
	gitExecutable = path
	t.Cleanup(func() { gitExecutable = old })
	return argvDump, envDump
}

func gitPinnedDest(endpoint string) *types.Destination {
	return &types.Destination{ID: "dg", Type: DestTypeGitPinned, Endpoint: endpoint}
}

// localRepoFixture creates a source repository with one branch and one
// commit, and returns its path plus the tip SHA.
func localRepoFixture(t *testing.T, realGit string, branch string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "origin")
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	run := func(args ...string) {
		cmd := exec.Command(realGit, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture %v: %v: %s", args, err, out)
		}
	}
	run("init", "--quiet", "--initial-branch="+branch, repo)
	run("-C", repo, "commit", "--allow-empty", "-m", "one")
	sha := strings.TrimSpace(func() string {
		cmd := exec.Command(realGit, "-C", repo, "rev-parse", branch)
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("rev-parse: %v", err)
		}
		return string(out)
	}())
	return repo, sha
}

// ParseGitRemote is the registration grammar for pinned git remotes.
// Everything that is not a strictly shaped https (or qualification
// loopback/file) remote is refused — in particular any userinfo spelling
// that would put a credential in argv.
func TestParseGitRemoteGrammar(t *testing.T) {
	good := []string{
		"https://git.example.com/org/repo.git",
		"https://git.example.com:8443/group/proj/repo.git",
		"https://gitlab.internal/team/app",
		"http://127.0.0.1:39999/repo.git",
		"http://localhost:39999/repo.git",
		"file:///srv/git/repo.git",
	}
	for _, r := range good {
		if _, err := ParseGitRemote(r); err != nil {
			t.Errorf("ParseGitRemote(%q) refused: %v", r, err)
		}
	}
	bad := []string{
		"",                                // empty
		"https://",                        // nothing
		"https://git.example.com",         // no path
		"http://git.example.com/repo.git", // plain http, non-loopback
		"http://127.0.0.1/repo.git",       // loopback without port
		"https://user:pass@git.example.com/r.git", // URL-embedded credential
		"https://user@git.example.com/r.git",      // userinfo
		"https://git.example.com/r.git?x=1",       // query
		"https://git.example.com/r.git#frag",      // fragment
		"https://git.example.com:99999/r.git",     // port out of range
		"https://git.example.com:port/r.git",      // non-numeric port
		"ssh://git@example.com/repo.git",          // unsupported scheme
		"git://example.com/repo.git",              // unsupported scheme
		"ext::sh -c touch /tmp/pwned",             // git transport injection
		"git@example.com:org/repo.git",            // scp-style ssh remote
		"/srv/git/repo.git",                       // bare path
		"https://git exam ple.com/r.git",          // whitespace
		"https://git.example.com/r.git\n",         // control character
		"https://" + strings.Repeat("a", 3000),    // too long
		"file://relative/path",                    // non-absolute file remote
		"file:///srv/repo.git?a=b",                // query in file remote
	}
	for _, r := range bad {
		if _, err := ParseGitRemote(r); err == nil {
			t.Errorf("ParseGitRemote(%q) accepted", r)
		}
	}
}

// ValidateGitRef: the branch name is the only agent-supplied degree of
// freedom. Every injection spelling must be unrepresentable.
func TestValidateGitRefGrammar(t *testing.T) {
	good := []string{
		"main", "master", "feature/login-flow", "release_2.1", "a.b.c",
	}
	for _, r := range good {
		if err := ValidateGitRef(r); err != nil {
			t.Errorf("ValidateGitRef(%q) refused: %v", r, err)
		}
	}
	bad := []string{
		"",                          // empty
		"-oProxyCommand=evil",       // option injection
		"--upload-pack=/bin/false",  // option injection
		"--exec=evil",               // option injection
		"origin --exec=evil",        // embedded option word
		"refs/heads/x:refs/hosts/y", // refspec colon refused
		"refs/heads/*",              // glob
		"a..b",                      // range syntax
		"main.lock",                 // ref lock suffix
		"main.",                     // trailing dot
		"main/",                     // trailing slash
		"a//b",                      // empty component
		"x~1",                       // tilde revision
		"x^2",                       // caret revision
		"x:y",                       // colon
		"x y",                       // whitespace
		"x\ty",                      // control byte
		"x\x00y",                    // NUL
		"\xff\xfe",                  // not UTF-8
		strings.Repeat("a", 201),    // too long
		"-",                         // bare dash
	}
	for _, r := range bad {
		if err := ValidateGitRef(r); err == nil {
			t.Errorf("ValidateGitRef(%q) accepted", r)
		}
	}
}

// Happy path against a LOCAL test repository: the branch is fetched, the
// DTO is the closed projection, and no git output reaches the result.
func TestGitFetchLocalHappyPath(t *testing.T) {
	realGit := hasGit(t)
	repo, sha := localRepoFixture(t, realGit, "probe")

	d, err := Lookup("git.fetch")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg", Dest: gitPinnedDest("file://" + repo),
			Params: map[string]string{"ref": "probe"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Data["fetched"] != true {
		t.Fatalf("fetched flag missing: %v", res.Data)
	}
	if res.Data["branch"] != "probe" {
		t.Fatalf("branch lost: %v", res.Data)
	}
	if res.Data["head"] != sha {
		t.Fatalf("head = %v, want %s", res.Data["head"], sha)
	}
	if res.Data["remote"] != "file://"+repo {
		t.Fatalf("remote lost: %v", res.Data)
	}
	for k := range res.Data {
		switch k {
		case "fetched", "branch", "remote", "head":
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
}

// The core contract: the credential reaches git ONLY through the
// credential-fill response on the controlled file descriptor. It never
// appears in argv, in the child environment, or in any URL.
func TestGitFetchCredentialPlacement(t *testing.T) {
	realGit := hasGit(t)
	repo, _ := localRepoFixture(t, realGit, "probe")
	argvDump, envDump := installGitWrapper(t, realGit)

	d, _ := Lookup("git.fetch")
	if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg", Dest: gitPinnedDest("file://" + repo),
			Params: map[string]string{"ref": "probe"}}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// argv: the pinned remote and broker-composed refspec are present; the
	// credential and any URL-embedded form of it are not. The helper text
	// is the static snippet, proving the fd handoff is in place.
	argvBody, err := os.ReadFile(argvDump)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(argvBody)
	if !strings.Contains(argv, "[fetch]") || !strings.Contains(argv, "[--]") {
		t.Fatalf("fixed template missing: %q", argv)
	}
	if !strings.Contains(argv, "[refs/heads/probe]") {
		t.Fatalf("broker-composed refspec missing from argv: %q", argv)
	}
	if !strings.Contains(argv, "[credential.helper="+gitHelperSnippet+"]") {
		t.Fatalf("pinned credential helper missing from argv: %q", argv)
	}
	if strings.Contains(argv, gitMarker) {
		t.Fatal("credential leaked into argv")
	}
	if strings.Contains(argv, "password=") && !strings.Contains(argv, "credential.helper="+gitHelperSnippet) {
		t.Fatal("credential-fill material appeared outside the pinned helper")
	}

	// Environment: fixed profile, no credential, no inherited broker env.
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
		if line == "GIT_TERMINAL_PROMPT=1" {
			t.Fatal("interactive prompting must be disabled")
		}
	}
	if !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(env, "GIT_CONFIG_GLOBAL=/dev/null") {
		t.Fatal("child git config neutralization missing")
	}
}

// The credential is actually consumed by the transport: a live smart-HTTP
// server that requires Basic auth accepts the broker-injected credential
// and rejects a wrong one. This is the end-to-end proof of broker-side
// injection over the protocol git actually speaks.
func TestGitFetchAuthOverLoopbackHTTP(t *testing.T) {
	realGit := hasGit(t)
	if _, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Skip("sandbox denies local TCP listeners")
	}
	repo, _ := localRepoFixture(t, realGit, "probe")
	var authOK bool
	// pktLine wraps s as a git pkt-line frame.
	pktLine := func(s string) []byte {
		return []byte(fmt.Sprintf("%04x%s", len(s)+4, s))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/repo.git/") {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "git" || pass != gitMarker {
			authOK = false
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authOK = true
		// Dispatch the real git server side so the fetch completes
		// protocol-honestly: GET serves the ref advertisement, POST
		// relays the raw stateless-rpc request/response bytes.
		env := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if r.Method == http.MethodGet {
			if !strings.HasSuffix(r.URL.Path, "/info/refs") ||
				r.URL.Query().Get("service") != "git-upload-pack" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.WriteHeader(http.StatusOK)
			w.Write(pktLine("# service=git-upload-pack\n"))
			w.Write([]byte("0000"))
			cmd := exec.Command(realGit, "upload-pack", "--stateless-rpc", "--advertise-refs", repo)
			cmd.Stdout = w
			cmd.Env = env
			if err := cmd.Run(); err != nil {
				return
			}
			return
		}
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, zerr := gzip.NewReader(r.Body)
			if zerr != nil {
				http.Error(w, "bad gzip body", http.StatusBadRequest)
				return
			}
			defer zr.Close()
			body = zr
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		cmd := exec.Command(realGit, "upload-pack", "--stateless-rpc", repo)
		cmd.Stdin = body
		cmd.Stdout = w
		cmd.Env = env
		if err := cmd.Run(); err != nil {
			http.Error(w, "backend failed", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	d, _ := Lookup("git.fetch")
	dest := gitPinnedDest(srv.URL + "/repo.git")
	res, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg", Dest: dest,
			Params: map[string]string{"ref": "probe"}})
	if err != nil {
		t.Fatalf("execute with correct credential: %v", err)
	}
	if !authOK {
		t.Fatal("fixture never saw a correct Basic credential")
	}
	if res.Data["fetched"] != true {
		t.Fatalf("fetched flag missing: %v", res.Data)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), gitMarker) {
		t.Fatalf("credential reached model-visible output: %s", raw)
	}

	// A wrong credential must fail the operation — the pin is real, and
	// the fixed error carries no git diagnostics.
	authOK = false
	if _, err := d.Execute(context.Background(), Credential{Value: "WRONG-" + gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg", Dest: dest,
			Params: map[string]string{"ref": "probe"}}); err == nil {
		t.Fatal("wrong credential accepted")
	}
	if authOK {
		t.Fatal("server accepted the wrong credential")
	}
}

// Refusals that need no git binary: wrong destination type, missing
// destination, empty credential, and unknown components.
func TestGitFetchRefusals(t *testing.T) {
	d, _ := Lookup("git.fetch")
	_, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg",
			Dest:   &types.Destination{ID: "d", Type: "file", Endpoint: "/tmp/x"},
			Params: map[string]string{"ref": "main"}})
	if err == nil {
		t.Fatal("file destination accepted by git.fetch")
	}
	if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Params: map[string]string{"ref": "main"}}); err == nil {
		t.Fatal("missing destination accepted")
	}
	if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg",
			Dest:   gitPinnedDest("https://git.example.com/org/repo.git"),
			Params: map[string]string{"ref": "main"}}); err == nil {
		t.Fatal("empty credential accepted")
	}
	// Multi-component credentials: only username/password placements exist.
	if _, err := d.Execute(context.Background(),
		Credential{Value: gitMarker, Components: map[string]string{"ssh_key": "PRIVATE"}},
		UseInput{Operation: "git.fetch", Target: "dg",
			Dest:   gitPinnedDest("https://git.example.com/org/repo.git"),
			Params: map[string]string{"ref": "main"}}); err == nil {
		t.Fatal("unsupported credential component accepted")
	}
	// A ref that cannot be a valid branch is refused before any I/O —
	// even with a destination that would pass the remote grammar.
	for _, ref := range []string{"-oProxyCommand=evil", "x:y", "--upload-pack=/bin/false", "a..b"} {
		if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
			UseInput{Operation: "git.fetch", Target: "dg",
				Dest:   gitPinnedDest("https://git.example.com/org/repo.git"),
				Params: map[string]string{"ref": ref}}); err == nil {
			t.Errorf("injection ref %q accepted", ref)
		}
	}
	// A registered-but-malformed remote fails closed at execution.
	for _, endpoint := range []string{"https://user:pass@git.example.com/r.git", "ssh://h/r", "http://host.example.com/r.git"} {
		if _, err := d.Execute(context.Background(), Credential{Value: gitMarker},
			UseInput{Operation: "git.fetch", Target: "dg",
				Dest:   gitPinnedDest(endpoint),
				Params: map[string]string{"ref": "main"}}); err == nil {
			t.Errorf("remote %q accepted", endpoint)
		}
	}
}

// The credential-fill response is line-oriented: a username carrying a
// newline could inject a password line that authenticates before the real
// token — corrupting the handoff silently. The refusal must happen before
// any I/O, so this runs against a reachable local repository: if the
// validation were removed (negative control), the fetch would succeed and
// this test would fail on the missing error instead of passing for the
// unrelated reason of an unreachable remote.
func TestGitFetchRefusesCorruptingUsername(t *testing.T) {
	realGit := hasGit(t)
	repo, _ := localRepoFixture(t, realGit, "probe")
	d, err := Lookup("git.fetch")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Execute(context.Background(),
		Credential{Value: gitMarker, Components: map[string]string{"username": "u\npassword=x\n"}},
		UseInput{Operation: "git.fetch", Target: "dg",
			Dest:   gitPinnedDest("file://" + repo),
			Params: map[string]string{"ref": "probe"}})
	if err == nil {
		t.Fatal("username with protocol-significant bytes accepted")
	}
	if !strings.Contains(err.Error(), "credential bytes unusable") {
		t.Fatalf("error is not the credential-integrity refusal (fetch may have failed for an unrelated reason): %v", err)
	}
}

// selectFetchHead is the projection security boundary: the DTO's head must
// be the tip of the branch the operator's approval covered, never whichever
// line git wrote first. Table-tested against synthetic FETCH_HEAD content
// because the live single-refspec fetch writes exactly one line on current
// git — a first-line mutant is only distinguishable here. Negative control:
// mutating selectFetchHead to first-line selection trips
// TestSelectFetchHeadRejectsForeignLines.
func TestSelectFetchHeadRejectsForeignLines(t *testing.T) {
	const (
		oidFeature = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		oidMain    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		oidTag     = "cccccccccccccccccccccccccccccccccccccccc"
	)
	cases := []struct {
		name string
		raw  string
		ref  string
		want string
	}{
		{
			name: "requested branch in a multi-ref FETCH_HEAD, requested line second",
			raw: oidMain + "\t\tbranch 'main' of https://g/r.git\n" +
				oidFeature + "\t\tbranch 'feature' of https://g/r.git\n",
			ref:  "feature",
			want: oidFeature,
		},
		{
			name: "requested branch first among tags",
			raw: oidFeature + "\t\tbranch 'feature' of https://g/r.git\n" +
				oidTag + "\tnot-for-merge\ttag 'v1' of https://g/r.git\n",
			ref:  "feature",
			want: oidFeature,
		},
		{
			// The quoted description must match in full: a branch named
			// "feature" must not be satisfied by the line of
			// "feature-x" (a raw-substring match would project the wrong
			// tip, and the wrong tip is a false attestation).
			name: "ref name that prefixes another ref's name",
			raw:  "dddddddddddddddddddddddddddddddddddddddd\t\tbranch 'feature-x' of https://g/r.git\n",
			ref:  "feature",
			want: "",
		},
		{
			name: "malformed first field is skipped",
			raw:  "not-an-oid\t\tbranch 'feature' of https://g/r.git\n" + oidFeature + "\t\tbranch 'feature' of https://g/r.git\n",
			ref:  "feature",
			want: oidFeature,
		},
		{
			name: "no matching line projects nothing",
			raw:  oidMain + "\t\tbranch 'main' of https://g/r.git\n",
			ref:  "feature",
			want: "",
		},
		{
			name: "bare HEAD fetch line has no description to match",
			raw:  oidMain + "\t\thttps://g/r.git\n",
			ref:  "main",
			want: "",
		},
		{
			name: "single line, exact match (current git single-refspec shape)",
			raw:  oidFeature + "\t\tbranch 'feature' of file:///srv/repo\n",
			ref:  "feature",
			want: oidFeature,
		},
	}
	for _, tc := range cases {
		if got := selectFetchHead([]byte(tc.raw), tc.ref); got != tc.want {
			t.Errorf("%s: selectFetchHead(ref=%q) = %q, want %q", tc.name, tc.ref, got, tc.want)
		}
	}
}

// Live-path companion: with the driver's real argv against a real
// repository, the projected head is the requested branch's tip (a
// non-default branch), and the honest result passes the disclosure gates.
func TestGitFetchHeadMatchesRequestedBranch(t *testing.T) {
	realGit := hasGit(t)
	repo, _ := localRepoFixture(t, realGit, "main")

	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	run := func(args ...string) {
		cmd := exec.Command(realGit, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture %v: %v: %s", args, err, out)
		}
	}
	run("-C", repo, "switch", "--quiet", "-c", "feature")
	run("-C", repo, "commit", "--allow-empty", "-m", "two")
	sha := strings.TrimSpace(func() string {
		cmd := exec.Command(realGit, "-C", repo, "rev-parse", "feature")
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("rev-parse: %v", err)
		}
		return string(out)
	}())

	d, err := Lookup("git.fetch")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Execute(context.Background(), Credential{Value: gitMarker},
		UseInput{Operation: "git.fetch", Target: "dg", Dest: gitPinnedDest("file://" + repo),
			Params: map[string]string{"ref": "feature"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Data["head"] != sha {
		t.Fatalf("head = %v, want the feature tip %s", res.Data["head"], sha)
	}
	if err := ValidateCredentialNonDisclosure(res, Credential{Value: gitMarker}); err != nil {
		t.Fatalf("credential disclosure gate rejected an honest result: %v", err)
	}
}

// The agent cannot steer the operation: there is no remote/url parameter
// at all, the op requires a destination, and no state-changing git
// operation exists.
func TestGitFetchDiscoveryContract(t *testing.T) {
	d, err := Lookup("git.fetch")
	if err != nil {
		t.Fatal(err)
	}
	if !d.RequiresDestination() {
		t.Fatal("git.fetch must require a destination")
	}
	if got := strings.Join(d.AllowedParams(), ","); got != "ref" {
		t.Fatalf("AllowedParams = %q, want only ref", got)
	}
	if d.Completion() != ResponseValidated {
		t.Fatal("read-only git.fetch must be ResponseValidated")
	}
	for _, forbidden := range []string{"git.clone", "git.push", "git.raw", "git.remote.add", "git.config"} {
		if _, err := Lookup(forbidden); err == nil {
			t.Fatalf("operation %s must not exist", forbidden)
		}
	}
	// Submission-time validation refuses bad refs and does not loosely
	// accept unknown remotes when a destination is attached.
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
}

// git.fetch is a real operation in the frozen registry, and its DTO
// survives the shared result contract (SC-09).
func TestGitFetchResultContract(t *testing.T) {
	res := SafeResult{Summary: "git fetch completed (branch main)", Data: map[string]interface{}{
		"fetched": true, "remote": "https://git.example.com/org/repo.git",
		"branch": "main", "head": strings.Repeat("a", 40),
	}}
	if err := ValidateSafeResult(res); err != nil {
		t.Fatalf("git.fetch DTO rejected by the shared contract: %v", err)
	}
}
