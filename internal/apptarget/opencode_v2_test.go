package apptarget

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestOpenCodeV2AdapterRequiresRecipientPinnedExecutable(t *testing.T) {
	target := types.AppCredentialTarget{
		ID: "opencode:openrouter:api_key", App: "opencode", Account: "openrouter",
		Slot: "api_key", UpdateMethod: OpenCodeAuthImportV2,
		SourceRef: "ref-1", SourceRevision: 1,
	}
	if _, err := NewOpenCodeAdapter(target, t.TempDir(), ""); err == nil {
		t.Fatal("selected a PATH-resolved OpenCode command without a recipient pin")
	}

	home := filepath.Join(t.TempDir(), "recipient-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	got, err := NewOpenCodeAdapter(target, home, command)
	if err != nil {
		t.Fatal(err)
	}
	adapter, ok := got.(OpenCodeV2Auth)
	if !ok || adapter.CommandPath != command || adapter.HomeDir != home {
		t.Fatalf("factory did not preserve the pinned executable and recipient home: %#v", got)
	}
}

func TestOpenCodeV2ChildEnvironmentPinsHomeAndOmitsSecrets(t *testing.T) {
	env := openCodeV2Environment([]string{
		"HOME=/agent/home", "OPENROUTER_API_KEY=agent-secret",
		"XDG_DATA_HOME=/recipient/data", "PATH=/trusted/bin",
	}, "/recipient/home")
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "HOME=/recipient/home") || strings.Contains(joined, "/agent/home") {
		t.Fatalf("OpenCode child home was not pinned to the recipient: %q", joined)
	}
	if strings.Contains(joined, "OPENROUTER_API_KEY") {
		t.Fatal("OpenCode credential-management subprocess inherited an ambient API key")
	}
	if !strings.Contains(joined, "XDG_DATA_HOME=/recipient/data") || !strings.Contains(joined, "PATH=/trusted/bin") {
		t.Fatalf("recipient app paths or command environment were not preserved: %q", joined)
	}
}
