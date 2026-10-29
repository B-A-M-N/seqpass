package apptarget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestCodexAuthUsesRecipientCLIAndReconcilesRotation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "recipient")
	codexHome := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexHome, 0700); err != nil {
		t.Fatal(err)
	}
	argvPath := filepath.Join(home, "argv")
	envPath := filepath.Join(home, "env")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argvPath + "\n" +
		"env > " + envPath + "\n" +
		"IFS= read -r key || exit 11\n" +
		"mkdir -p \"$CODEX_HOME\"\n" +
		`printf '{"auth_mode":"apikey","OPENAI_API_KEY":"%s","tokens":{}}\n' "$key" > "$CODEX_HOME/auth.json"` + "\n" +
		"chmod 600 \"$CODEX_HOME/auth.json\"\n"
	command := filepath.Join(home, "codex")
	if err := os.WriteFile(command, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	target := types.AppCredentialTarget{
		ID: "codex:openai:api_key", App: "codex", Account: "openai", Slot: "api_key",
		UpdateMethod: CodexAuthFileV1, SourceRef: "provider/openai", SourceRevision: 1,
	}
	adapter := CodexAuthFile{CommandPath: command, HomeDir: home, CodexHome: codexHome}
	first := []byte("synthetic-codex-key-one")
	result, err := adapter.Apply(context.Background(), target, "op-1", first)
	if err != nil || !result.Applied {
		t.Fatalf("apply: %#v %v", result, err)
	}
	state, err := os.ReadFile(filepath.Join(codexHome, "auth.json"))
	if err != nil || !strings.Contains(string(state), string(first)) {
		t.Fatalf("Codex auth file did not receive the key: %v", err)
	}
	argv, err := os.ReadFile(argvPath)
	if err != nil || strings.Contains(string(argv), string(first)) {
		t.Fatal("credential was passed in Codex argv")
	}
	env, err := os.ReadFile(envPath)
	if err != nil || strings.Contains(string(env), string(first)) {
		t.Fatal("credential was passed through the Codex environment")
	}
	check, err := adapter.Reconcile(context.Background(), target, "op-1", first)
	if err != nil || !check.Applied || check.Digest != result.Digest {
		t.Fatalf("reconcile after apply: %#v %v", check, err)
	}
	second := []byte("synthetic-codex-key-two")
	rotated, err := adapter.Apply(context.Background(), target, "op-2", second)
	if err != nil || !rotated.Applied {
		t.Fatalf("rotation: %#v %v", rotated, err)
	}
	old, err := adapter.Reconcile(context.Background(), target, "op-1", first)
	if err != nil || old.Applied {
		t.Fatalf("old key still reconciled after rotation: %#v %v", old, err)
	}
	newKey, err := adapter.Reconcile(context.Background(), target, "op-2", second)
	if err != nil || !newKey.Applied {
		t.Fatalf("new key did not reconcile: %#v %v", newKey, err)
	}
}

func TestCodexTargetRejectsCredentialAsIdentity(t *testing.T) {
	target := types.AppCredentialTarget{
		ID: "codex:openai:api_key", App: "codex", Account: "openai", Slot: "api_key",
		UpdateMethod: CodexAuthFileV1, SourceRef: "provider/openai", SourceRevision: 1,
	}
	target.ID = "codex:synthetic-secret:api_key"
	if err := validateCodexTarget(target); err == nil {
		t.Fatal("accepted substituted target identity")
	}
}
