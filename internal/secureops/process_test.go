package secureops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

const processMarker = "SECRET-PROCESS-pin-2b3c4d5e6f70"

// writePinnedScript installs an executable pinned profile in a private
// temp tree that satisfies the registration grammar (absolute resolved
// path, regular file, owner-executable, no group/world write bits,
// private ancestors).
func writePinnedScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pinned-tool")
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func pinnedDest(path string) *types.Destination {
	return &types.Destination{ID: "dp", Type: DestTypeProcessPinned, Endpoint: path, AuthMethod: "stdin"}
}

// The core contract: the pinned executable receives the credential on
// stdin only. The child dumps stdin, argv and environment to separate
// files to prove the credential is only in the first.
func TestProcessRunCredentialOnStdinOnly(t *testing.T) {
	tmp := t.TempDir()
	stdinDump := filepath.Join(tmp, "stdin.txt")
	argvDump := filepath.Join(tmp, "argv.txt")
	envDump := filepath.Join(tmp, "env.txt")
	script := writePinnedScript(t, "#!/bin/sh\n"+
		"cat > "+stdinDump+"\n"+
		"printf '[%s]' \"$@\" > "+argvDump+"\n"+
		"env > "+envDump+"\n"+
		"echo '{\"applied\":true}'\n")
	d, _ := Lookup("process.run")
	res, err := d.Execute(context.Background(), Credential{Value: processMarker},
		UseInput{Operation: "process.run", Target: "dp", Dest: pinnedDest(script),
			Params: map[string]string{"arg0": "positional-a", "arg1": "positional-b"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// stdin: the credential arrived, as the only stdin content.
	stdinBody, err := os.ReadFile(stdinDump)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdinBody) != processMarker {
		t.Fatalf("stdin = %q, want exactly the credential", stdinBody)
	}
	// argv: exactly the typed slots, never the credential.
	argvBody, err := os.ReadFile(argvDump)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(argvBody), "[positional-a][positional-b]") {
		t.Fatalf("typed args missing from argv: %q", argvBody)
	}
	if strings.Contains(string(argvBody), processMarker) {
		t.Fatal("credential leaked into argv")
	}
	// Environment is fixed, so it can neither carry the credential nor
	// leak the broker's own environment.
	envBody, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatal(err)
	}
	env := string(envBody)
	if strings.Contains(env, processMarker) {
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
	// Projected JSON output only.
	if res.Data["applied"] != true {
		t.Fatalf("JSON projection lost the field: %v", res.Data)
	}
	if res.Data["exit_code"] != 0.0 {
		t.Fatalf("exit code missing: %v", res.Data)
	}
}

// A non-zero exit is a failed operation whose message carries the code
// only — never argv, environment or stderr content.
func TestProcessRunNonZeroExitRefused(t *testing.T) {
	script := writePinnedScript(t, "#!/bin/sh\necho 'BOOM ' \"$1\" >&2\nexit 3\n")
	d, _ := Lookup("process.run")
	_, err := d.Execute(context.Background(), Credential{Value: processMarker},
		UseInput{Operation: "process.run", Target: "dp", Dest: pinnedDest(script),
			Params: map[string]string{"arg0": "SECRET-ARG-shout-9911"}})
	if err == nil {
		t.Fatal("non-zero exit accepted as success")
	}
	if strings.Contains(err.Error(), "SECRET-ARG") || strings.Contains(err.Error(), "BOOM") {
		t.Fatalf("error message carries child output: %v", err)
	}
	if !strings.Contains(err.Error(), "3") {
		t.Fatalf("error message should carry the exit code: %v", err)
	}
}

// Free-form output is discarded, never redacted or passed through.
func TestProcessRunNonJSONOutputDiscarded(t *testing.T) {
	script := writePinnedScript(t, "#!/bin/sh\ncat > /dev/null\necho 'plain text output'\n")
	d, _ := Lookup("process.run")
	res, err := d.Execute(context.Background(), Credential{Value: processMarker},
		UseInput{Operation: "process.run", Target: "dp", Dest: pinnedDest(script)})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "plain text") {
		t.Fatal("free-form output reached the model-visible result")
	}
	if res.Data["exit_code"] != 0.0 {
		t.Fatalf("exit code missing: %v", res.Data)
	}
}

// A pinned executable that echoes the credential in its JSON output is
// blocked by the projection (field dropped) before the service gate.
func TestProcessRunCredentialEchoDropped(t *testing.T) {
	// The pinned script echoes a string equal to the credential marker as
	// a JSON field — the hostile-or-buggy profile case.
	script := writePinnedScript(t, "#!/bin/sh\ncat > /dev/null\nprintf '{\"leak\":\""+processMarker+"\",\"ok\":1}'\n")
	d, _ := Lookup("process.run")
	res, err := d.Execute(context.Background(), Credential{Value: processMarker},
		UseInput{Operation: "process.run", Target: "dp", Dest: pinnedDest(script)})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), processMarker) {
		t.Fatalf("reflected credential reached the model-visible result: %s", raw)
	}
	if res.Data["ok"] != 1.0 {
		t.Fatalf("harmless field lost when the leaking one was dropped: %v", res.Data)
	}
}

// Registration grammar: only a strictly pinned, broker-owned executable
// passes. Every deviation is refused with a named reason.
func TestValidateProcessPinnedGrammar(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"relative path", "tool/bin/x", true},
		{"empty", "", true},
		{"missing file", "/nonexistent/seqpass-tool", true},
		{"symlink", "", true}, // filled in below
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real-tool")
	if err := os.WriteFile(real, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link-tool")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cases[3].endpoint = link

	d, _ := Lookup("process.run")
	if !d.RequiresDestination() {
		t.Fatal("process.run must require a destination")
	}
	for _, tc := range cases {
		err := ValidateProcessPinned(&types.Destination{ID: "d", Type: DestTypeProcessPinned, Endpoint: tc.endpoint})
		if tc.wantErr && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}

	// The real pinned tool validates.
	if err := ValidateProcessPinned(pinnedDest(real)); err != nil {
		t.Fatalf("valid pinned executable refused: %v", err)
	}
	// Wrong type fails closed.
	if err := ValidateProcessPinned(&types.Destination{ID: "d", Type: "file", Endpoint: real}); err == nil {
		t.Fatal("file destination accepted by process.run validation")
	}
	// Any credential placement other than stdin is refused: a profile that
	// would need the credential in argv or the environment is
	// structurally impossible.
	if err := ValidateProcessPinned(&types.Destination{ID: "d", Type: DestTypeProcessPinned, Endpoint: real, AuthMethod: "argv"}); err == nil {
		t.Fatal("argv credential placement accepted")
	}
	if err := ValidateProcessPinned(&types.Destination{ID: "d", Type: DestTypeProcessPinned, Endpoint: real, AuthMethod: "env"}); err == nil {
		t.Fatal("env credential placement accepted")
	}

	// Group/world writable executable or ancestor breaks the pin.
	if err := os.Chmod(real, 0711); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProcessPinned(pinnedDest(real)); err != nil {
		// 0711 is not writable, so it must still pass.
		t.Fatalf("0711 executable refused: %v", err)
	}
	if err := os.Chmod(real, 0770); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProcessPinned(pinnedDest(real)); err == nil {
		t.Fatal("group-writable executable accepted")
	}
	if err := os.Chmod(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProcessPinned(pinnedDest(real)); err == nil {
		t.Fatal("world-writable ancestor accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
}

// Typed argument slots: order preserved, control bytes and empty values
// refused, unknown keys handled by the shared admission gate.
func TestProcessRunArgGrammar(t *testing.T) {
	if err := ValidateProcessArg(""); err == nil {
		t.Fatal("empty arg accepted")
	}
	if err := ValidateProcessArg(strings.Repeat("a", 2000)); err == nil {
		t.Fatal("oversized arg accepted")
	}
	for _, a := range []string{"ok", "with-dash --flag=value", "utf8 ✓"} {
		if err := ValidateProcessArg(a); err != nil {
			t.Errorf("valid arg %q refused: %v", a, err)
		}
	}
	for _, a := range []string{"bad\x00nul", "bad\nnewline", "bad\ttab", "bad\x7fdel", "\xff\xfe"} {
		if err := ValidateProcessArg(a); err == nil {
			t.Errorf("invalid arg %q accepted", a)
		}
	}
	argv, err := processArgv(map[string]string{"arg0": "a", "arg2": "c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, "|") != "a|c" {
		t.Fatalf("argv = %v, want positional order with gaps closed by omission", argv)
	}
}

// The verifier must exist (activation contract), must never claim
// satisfaction, and must point at the durable receipt.
func TestProcessRunVerifierInconclusive(t *testing.T) {
	v, ok := LookupVerifier("process.run")
	if !ok {
		t.Fatal("process.run has no registered verifier; broker would refuse to start")
	}
	out, err := v.Verify(context.Background(), UseInput{OpID: "op-1"},
		SafeResult{Data: map[string]interface{}{"exit_code": 0.0}})
	if err != nil {
		t.Fatal(err)
	}
	if out.State != OutcomeInconclusive {
		t.Fatalf("verifier claimed %s; a generic adapter must never claim independent observation", out.State)
	}
	if out.EvidenceKind != "receipt" || out.EvidenceRef != "op-1" {
		t.Fatalf("evidence = %s/%s, want receipt/op-1", out.EvidenceKind, out.EvidenceRef)
	}
}

// Multi-component credentials have no honest stdin encoding: refused.
func TestProcessRunMultiComponentRefused(t *testing.T) {
	script := writePinnedScript(t, "#!/bin/sh\ncat > /dev/null\n")
	d, _ := Lookup("process.run")
	if _, err := d.Execute(context.Background(),
		Credential{Value: "v", Components: map[string]string{"user": "u"}},
		UseInput{Operation: "process.run", Target: "dp", Dest: pinnedDest(script)}); err == nil {
		t.Fatal("multi-component credential accepted for process.run")
	}
}
