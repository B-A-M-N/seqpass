package qual

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secretbridge/secretbridge/internal/apptarget"
	"github.com/secretbridge/secretbridge/internal/types"
)

// TestQualOpenCodeHandoff exercises the installed OpenCode v2 binary against
// the credential stored by the recipient adapter. It uses an isolated HOME
// and a synthetic key, and is opt-in because it requires a real app install.
func TestQualOpenCodeHandoff(t *testing.T) {
	if os.Getenv("SEQPASS_QUAL_OPENCODE") != "1" {
		t.Skip("set SEQPASS_QUAL_OPENCODE=1 to qualify the installed OpenCode app")
	}
	bin, err := exec.LookPath("opencode")
	if err != nil {
		t.Skip("OpenCode is not installed")
	}

	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))

	const synthetic = "seqpass-qualification-synthetic-only"
	const rotatedSynthetic = "seqpass-qualification-rotated-only"
	target := types.AppCredentialTarget{
		ID: "opencode:openrouter:api_key", App: "opencode",
		Account: "openrouter", Slot: "api_key",
		UpdateMethod: apptarget.OpenCodeAuthImportV2,
		SourceRef:    "qualification/synthetic", SourceRevision: 1,
	}
	versionCmd := exec.Command(bin, "--version")
	versionCmd.Env = isolatedOpenCodeEnv(os.Environ(), home)
	versionOutput, err := versionCmd.Output()
	if err != nil {
		t.Fatalf("OpenCode version command failed: %v", err)
	}
	version := strings.TrimSpace(string(versionOutput))
	if version == "" {
		t.Fatal("OpenCode did not report its version")
	}
	if !strings.HasPrefix(strings.ToLower(version), "opencode v2.") {
		t.Skip("this qualification requires OpenCode v2 credential storage")
	}

	adapter := apptarget.OpenCodeV2Auth{CommandPath: bin, HomeDir: home}
	result, err := adapter.Apply(context.Background(), target, "qualification-op", []byte(synthetic))
	if err != nil || !result.Applied {
		t.Fatalf("recipient adapter did not install the synthetic credential: applied=%t err=%v", result.Applied, err)
	}

	var receivedAuth atomic.Bool
	var expectedAuth atomic.Value
	expectedAuth.Store(synthetic)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+expectedAuth.Load().(string) {
			message := "qualification request had no authorization header"
			if auth != "" {
				message = "qualification request used an unexpected authorization header"
			}
			http.Error(w, message, http.StatusUnauthorized)
			return
		}
		receivedAuth.Store(true)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"qual-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"seqpass-qual\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"seqpass-qualified\"},\"finish_reason\":null}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"qual-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"seqpass-qual\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	configDir := filepath.Join(home, "config", "opencode")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	appConfig := map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"model":   "openrouter/seqpass-qual",
		"providers": map[string]any{
			"openrouter": map[string]any{
				"settings": map[string]any{"baseURL": server.URL + "/api/v1"},
				"models":   map[string]any{"seqpass-qual": map[string]any{"name": "SeqPass Qualification", "modelID": "seqpass-qual"}},
			},
		},
	}
	configBytes, err := json.Marshal(appConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "opencode.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}

	projectDir := filepath.Join(home, "project")
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		runCmd := exec.Command(bin, "run", "--standalone", "--model", "openrouter/seqpass-qual", "respond with the qualification phrase")
		runCmd.Dir = projectDir
		runCmd.Env = isolatedOpenCodeEnv(os.Environ(), home)
		runOutput, err := runCmd.CombinedOutput()
		if err != nil {
			// Never print app output directly: integrations may echo credentials.
			safeOutput := strings.ReplaceAll(string(runOutput), synthetic, "[REDACTED]")
			safeOutput = strings.ReplaceAll(safeOutput, rotatedSynthetic, "[REDACTED]")
			t.Fatalf("OpenCode %s did not complete a mock-provider request: %v; output=%q", version, err, safeOutput)
		}
		if !receivedAuth.Swap(false) {
			t.Fatal("mock provider did not receive the adapter-installed credential")
		}
		if !strings.Contains(string(runOutput), "seqpass-qualified") {
			t.Fatalf("OpenCode %s did not return the mock completion", version)
		}
	}
	run()

	expectedAuth.Store(rotatedSynthetic)
	result, err = adapter.Apply(context.Background(), target, "qualification-op-rotated", []byte(rotatedSynthetic))
	if err != nil || !result.Applied {
		t.Fatalf("recipient adapter did not rotate the synthetic credential: applied=%t err=%v", result.Applied, err)
	}
	run()
}

func isolatedOpenCodeEnv(parent []string, home string) []string {
	path := ""
	for _, entry := range parent {
		key, _, ok := strings.Cut(entry, "=")
		if ok && key == "PATH" {
			path = entry
			break
		}
	}
	env := make([]string, 0, 5)
	if path != "" {
		env = append(env, path)
	}
	return append(env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, "config"),
		"XDG_DATA_HOME="+filepath.Join(home, "data"),
		"XDG_STATE_HOME="+filepath.Join(home, "state"),
	)
}
