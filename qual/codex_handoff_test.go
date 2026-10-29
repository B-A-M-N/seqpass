package qual

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestQualCodexHandoff drives the installed Codex CLI with a credential
// installed by the recipient adapter and a local synthetic Responses API.
func TestQualCodexHandoff(t *testing.T) {
	if os.Getenv("SEQPASS_QUAL_CODEX") != "1" {
		t.Skip("set SEQPASS_QUAL_CODEX=1 to qualify the installed Codex app")
	}
	bin, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("Codex is not installed")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	codexHome := filepath.Join(home, ".codex")
	if err := os.Mkdir(codexHome, 0700); err != nil {
		t.Fatal(err)
	}
	const synthetic = "seqpass-qualification-codex-synthetic"
	const rotatedSynthetic = "seqpass-qualification-codex-rotated"
	target := types.AppCredentialTarget{
		ID: "codex:openai:api_key", App: "codex", Account: "openai", Slot: "api_key",
		UpdateMethod: apptarget.CodexAuthFileV1, SourceRef: "qualification/synthetic", SourceRevision: 1,
	}
	adapter := apptarget.CodexAuthFile{CommandPath: bin, HomeDir: home, CodexHome: codexHome}
	result, err := adapter.Apply(context.Background(), target, "qualification-codex-op", []byte(synthetic))
	if err != nil || !result.Applied {
		t.Fatalf("recipient adapter did not install the synthetic Codex credential: applied=%t err=%v", result.Applied, err)
	}
	var received atomic.Bool
	var expectedAuth atomic.Value
	expectedAuth.Store(synthetic)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/responses") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+expectedAuth.Load().(string) {
			http.Error(w, "mock provider rejected missing or unexpected authorization", http.StatusUnauthorized)
			return
		}
		received.Store(true)
		w.Header().Set("Content-Type", "text/event-stream")
		response := map[string]any{
			"type": "response.completed",
			"response": map[string]any{
				"id": "resp_seqpass_qual", "object": "response", "created_at": 1,
				"status": "completed", "model": "gpt-5-codex",
				"output": []any{map[string]any{
					"id": "msg_seqpass_qual", "type": "message", "status": "completed", "role": "assistant",
					"content": []any{map[string]any{"type": "output_text", "text": "codex-qualified", "annotations": []any{}}},
				}},
				"usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
			},
		}
		body, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "mock response encoding failed", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, "event: response.completed\ndata: %s\n\n", body)
	}))
	defer server.Close()
	config := fmt.Sprintf("model = %q\nmodel_provider = %q\nopenai_base_url = %q\napproval_policy = %q\nsandbox_mode = %q\ncli_auth_credentials_store = %q\n", "gpt-5-codex", "openai", server.URL+"/v1", "never", "read-only", "file")
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	runCodex := func() ([]byte, error) {
		cmd := exec.Command(bin, "exec", "--ephemeral", "--sandbox", "read-only", "--cd", project, "return the exact phrase codex-qualified")
		cmd.Dir = project
		cmd.Env = []string{"HOME=" + home, "CODEX_HOME=" + codexHome, "PATH=" + os.Getenv("PATH")}
		return cmd.CombinedOutput()
	}
	output, err := runCodex()
	if err != nil {
		safeOutput := strings.ReplaceAll(string(output), synthetic, "[REDACTED]")
		t.Fatalf("Codex did not complete a mock-provider request: %v; output=%q", err, safeOutput)
	}
	if !received.Swap(false) {
		t.Fatal("mock provider did not receive Codex's request with the adapter-installed key")
	}
	if !strings.Contains(string(output), "codex-qualified") {
		t.Fatalf("Codex did not return the synthetic completion: %q", string(output))
	}
	expectedAuth.Store(rotatedSynthetic)
	rotated, err := adapter.Apply(context.Background(), target, "qualification-codex-op-rotated", []byte(rotatedSynthetic))
	if err != nil || !rotated.Applied {
		t.Fatalf("recipient adapter did not rotate the Codex credential: applied=%t err=%v", rotated.Applied, err)
	}
	output, err = runCodex()
	if err != nil {
		safeOutput := strings.ReplaceAll(string(output), rotatedSynthetic, "[REDACTED]")
		t.Fatalf("Codex did not use the rotated credential: %v; output=%q", err, safeOutput)
	}
	if !received.Swap(false) || !strings.Contains(string(output), "codex-qualified") {
		t.Fatal("the next Codex request did not use the rotated synthetic credential")
	}
}
