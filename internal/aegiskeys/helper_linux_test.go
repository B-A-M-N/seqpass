//go:build linux

package aegiskeys

import (
	"context"
	"strings"
	"testing"
)

// TestHelperCommandMinimalEnv pins the helper's environment contract: the
// child inherits ONLY allowlisted Go runtime knobs, never the broker's
// application environment. A synthetic secret-shaped variable in the parent
// environment must not reach the helper — the parent environment is not
// assumed credential-free; it is filtered.
func TestHelperCommandMinimalEnv(t *testing.T) {
	t.Setenv("SEQPASS_TEST_ENV_CANARY", "synthetic-secret-value")
	t.Setenv("SEQPASS_AEGISKEYS_TOKEN", "synthetic-secret-value-2")
	t.Setenv("GOMAXPROCS", "2")
	// systemd's LoadCredentialEncrypted exposes the stable-key seed through
	// CREDENTIALS_DIRECTORY: a credential the broker may hold but the
	// helper must never see.
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/seqpass-broker")

	server, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close() //nolint:errcheck
	defer child.Close()  //nolint:errcheck

	prev := TestingHelperCommand
	TestingHelperCommand = nil
	t.Cleanup(func() { TestingHelperCommand = prev })

	cmd := helperCommand(context.Background(), "/usr/local/bin/seqpass", "/run/aegiskeys.sock", child)
	if cmd.Env == nil {
		t.Fatal("helper env is nil: the child would inherit the parent environment")
	}
	for _, kv := range cmd.Env {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if !helperEnvAllowlist[key] {
			t.Fatalf("helper inherits non-allowlisted env %q (value %q)", key, kv)
		}
	}
	for _, kv := range cmd.Env {
		if strings.Contains(kv, "synthetic-secret") {
			t.Fatalf("helper env contains synthetic secret: %q", kv)
		}
	}
	found := false
	for _, kv := range cmd.Env {
		if kv == "GOMAXPROCS=2" {
			found = true
		}
	}
	if !found {
		t.Fatal("allowlisted GOMAXPROCS was not forwarded")
	}
}
