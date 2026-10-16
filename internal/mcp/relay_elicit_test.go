package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// fakeHarness is a hostile-capability control: it offers an elicitation
// channel with a secret value, and tests verify that the agent adapter
// never invokes it.
type fakeHarness struct {
	action  mcp.ElicitationResponseAction
	content map[string]interface{}
	calls   int
}

func (f *fakeHarness) SessionID() string { return "test-session" }
func (f *fakeHarness) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return make(chan mcp.JSONRPCNotification, 1)
}
func (f *fakeHarness) Initialize()       {}
func (f *fakeHarness) Initialized() bool { return true }
func (f *fakeHarness) RequestElicitation(ctx context.Context, req mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	f.calls++
	if req.Params.RequestedSchema == nil {
		return &mcp.ElicitationResult{ElicitationResponse: mcp.ElicitationResponse{Action: mcp.ElicitationResponseActionCancel}}, nil
	}
	return &mcp.ElicitationResult{ElicitationResponse: mcp.ElicitationResponse{
		Action:  f.action,
		Content: f.content,
	}}, nil
}

func elicitFixture(t *testing.T) (*Server, string) {
	t.Helper()
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	if fi, err := os.Lstat("/home"); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 && fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(dir, "mcp-relay.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	uid := uint32(os.Geteuid())
	if err := svc.AddDestination(&types.Destination{
		ID: "rd1", Name: "r", Type: "recipient-socket",
		Endpoint: "/tmp/seqpass-mcp-relay-test.sock", ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	euid := uint32(os.Geteuid())
	auth := &ipc.UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{euid: true},
		AgentUIDs:  map[uint32]bool{euid: true},
		IntakeUIDs: map[uint32]bool{euid: true},
	}
	agentSock := filepath.Join(dir, "a.sock")
	intakeSock := filepath.Join(dir, "i.sock")
	srv := ipc.NewServer(svc, agentSock, "", nil, auth)
	srv.IntakeSocket = intakeSock
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return NewServer(agentSock), agentSock
}

func relayCall(t *testing.T, s *Server, ctx context.Context, args map[string]interface{}) string {
	t.Helper()
	res, err := s.handleRelayRequest(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: args},
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || len(res.Content) == 0 {
		t.Fatal("empty tool result")
	}
	tc, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("result is %T, want text", res.Content[0])
	}
	return tc.Text
}

// Even a harness that offers native elicitation is never asked for a
// credential by the untrusted MCP adapter. The trusted operator must use
// the separate terminal intake path.
func TestRelayRequestDoesNotElicitSecret(t *testing.T) {
	s, _ := elicitFixture(t)
	const secret = "elicited-TEST-value-7741"
	harness := &fakeHarness{
		action:  mcp.ElicitationResponseActionAccept,
		content: map[string]interface{}{"secret_value": secret},
	}
	ctx := s.mcp.WithContext(context.Background(), harness)
	out := relayCall(t, s, ctx, map[string]interface{}{
		"destination_id": "rd1", "data_kind": "password", "purpose": "test login",
	})
	for _, want := range []string{"request_id", "awaiting_user", "seqpass relay fulfill"} {
		if !strings.Contains(out, want) {
			t.Fatalf("result missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, secret) {
		t.Fatal("elicited value leaked into the tool result")
	}
	if harness.calls != 0 {
		t.Fatalf("untrusted adapter invoked MCP elicitation %d times", harness.calls)
	}
}

// A declined or absent harness form has no effect on request creation and
// cannot authorize delivery.
func TestRelayRequestDoesNotDependOnElicitationCapability(t *testing.T) {
	s, _ := elicitFixture(t)
	harness := &fakeHarness{
		action: mcp.ElicitationResponseActionDecline,
	}
	ctx := s.mcp.WithContext(context.Background(), harness)
	out := relayCall(t, s, ctx, map[string]interface{}{
		"destination_id": "rd1", "data_kind": "password",
	})
	if !strings.Contains(out, "awaiting_user") {
		t.Fatalf("decline lost the request: %s", out)
	}
	if harness.calls != 0 {
		t.Fatalf("untrusted adapter invoked MCP elicitation %d times", harness.calls)
	}
}

// Plain clients receive the same trusted-intake instruction.
func TestRelayNoElicitationFallback(t *testing.T) {
	s, _ := elicitFixture(t)
	out := relayCall(t, s, context.Background(), map[string]interface{}{
		"destination_id": "rd1", "data_kind": "one_time_code",
	})
	if !strings.Contains(out, "awaiting_user") {
		t.Fatalf("no fallback: %s", out)
	}
	if !strings.Contains(out, "request_id") {
		t.Fatalf("no request ID: %s", out)
	}
	if !strings.Contains(out, "seqpass relay fulfill") {
		t.Fatalf("missing trusted intake instruction: %s", out)
	}
}

// The tool schema itself offers no secret field: even a compromised or
// confused agent cannot stuff a value into tool arguments.
func TestRelayToolHasNoSecretParam(t *testing.T) {
	s, _ := elicitFixture(t)
	for _, name := range []string{"relay_request", "relay_status"} {
		st := s.mcp.GetTool(name)
		if st == nil {
			t.Fatalf("tool %s missing", name)
		}
		for _, p := range []string{"secret_value", "password", "token", "payload", "secret"} {
			if _, ok := st.Tool.InputSchema.Properties[p]; ok {
				t.Fatalf("tool %s exposes secret-adjacent param %q", name, p)
			}
		}
	}
}

// HI-06: even with synthetic credentials in play, the adapter response is
// a public control-plane envelope. There is no placeholder, secret field,
// token, or fulfillment instruction that can accidentally serialize a
// value into model context.
func TestRelayResultHasNoSecretBearingContext(t *testing.T) {
	s, _ := elicitFixture(t)
	out := relayCall(t, s, context.Background(), map[string]interface{}{
		"destination_id": "rd1", "data_kind": "api_key",
	})
	if !strings.Contains(out, `"next_action":"protected_input"`) {
		t.Fatalf("non-universal next action: %s", out)
	}
	for _, forbidden := range []string{"secret_value", "password", "payload", "session_token", "fulfill"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("agent result contains secret-bearing control field %q: %s", forbidden, out)
		}
	}
}
