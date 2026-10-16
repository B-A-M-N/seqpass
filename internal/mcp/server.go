package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

// Server is the untrusted agent-facing MCP adapter. It holds no vault and no
// database; every tool forwards to the broker over IPC. The broker derives
// the principal from peer credentials, so tools take no actor argument.
type Server struct {
	socket string
	mcp    *server.MCPServer
	dial   func() (*ipc.Client, error)
}

func NewServer(socket string) *Server {
	mcpSrv := server.NewMCPServer(
		"seqpass",
		"1.0.0",
		server.WithToolCapabilities(false),
	)
	s := &Server{
		socket: socket,
		mcp:    mcpSrv,
	}
	s.dial = func() (*ipc.Client, error) { return ipc.Dial(socket) }
	s.registerTools()
	return s
}

func (s *Server) registerTools() {
	catalogTool := mcp.NewTool("secret_catalog",
		mcp.WithDescription("Discover your secret references with permitted operations, required arguments, and access (ready is directly usable, needs_destination still needs a registered destination, scoped needs an exact target/resource)"),
	)
	s.mcp.AddTool(catalogTool, s.handleCatalog)

	useTool := mcp.NewTool("secret_use",
		mcp.WithDescription("Submit an allowlisted credentialed operation from secret_catalog; returns an opaque operation ID, never a secret"),
		mcp.WithString("secret_ref", mcp.Required(), mcp.Description("Secret reference ID from secret_catalog")),
		mcp.WithString("operation", mcp.Required(), mcp.Description("Allowlisted operation, e.g. github.get_repo")),
		mcp.WithString("target", mcp.Description("Registered destination or target ID")),
		mcp.WithObject("params", mcp.Description("Typed operation arguments (never secret values)")),
	)
	s.mcp.AddTool(useTool, s.handleUse)

	transferTool := mcp.NewTool("secret_transfer",
		mcp.WithDescription("Request a direct broker-to-recipient transfer; returns an opaque operation ID"),
		mcp.WithString("secret_ref", mcp.Required(), mcp.Description("Secret reference ID")),
		mcp.WithString("destination_id", mcp.Required(), mcp.Description("Registered destination ID")),
		mcp.WithString("payload_ref", mcp.Description("Optional component selector: \"component:<name>\" (AegisKeys v2 logical key; legacy v1 fallback uses its response-map key); empty transfers the default value")),
	)
	s.mcp.AddTool(transferTool, s.handleTransfer)

	statusTool := mcp.NewTool("secret_status",
		mcp.WithDescription("Check your own operation status and safe receipt metadata (also shows pending approvals)"),
		mcp.WithString("op_type", mcp.Required(), mcp.Description("Operation type: use or transfer")),
		mcp.WithString("op_id", mcp.Required(), mcp.Description("Operation ID")),
	)
	s.mcp.AddTool(statusTool, s.handleStatus)

	relayReqTool := mcp.NewTool("relay_request",
		mcp.WithDescription("Request protected user input for a registered recipient. Returns an opaque request ID only; a qualified native host or trusted out-of-band operator surface handles protected entry. This untrusted MCP adapter never collects or handles the value."),
		mcp.WithString("destination_id", mcp.Required(), mcp.Description("Registered recipient ID (must already exist; arbitrary endpoints are refused)")),
		mcp.WithString("data_kind", mcp.Required(), mcp.Description("What is needed: password | one_time_code | api_key | token | pin | text")),
		mcp.WithString("purpose", mcp.Description("Short human-readable reason shown to the user")),
		mcp.WithNumber("ttl_seconds", mcp.Description("How long the request stays fulfillable (default 300, min 30, max 86400)")),
	)
	s.mcp.AddTool(relayReqTool, s.handleRelayRequest)

	relayStatusTool := mcp.NewTool("relay_status",
		mcp.WithDescription("Check your own relay request: awaiting_user, authorized, delivered, uncertain, rejected, expired, cancelled, unavailable, or failed. Never contains the secret."),
		mcp.WithString("request_id", mcp.Required(), mcp.Description("Relay request ID from relay_request")),
	)
	s.mcp.AddTool(relayStatusTool, s.handleRelayStatus)
}

func (s *Server) call(ctx context.Context, method string, params map[string]interface{}) (interface{}, error) {
	cli, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	return cli.CallCtx(ctx, method, params)
}

func (s *Server) handleCatalog(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := s.call(ctx, ipc.MethodCatalog, nil)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	raw, _ := json.Marshal(data)
	return mcp.NewToolResultText(string(raw)), nil
}

// toolArgs decodes the untyped arguments envelope (v1.x types Arguments
// as any). Non-object envelopes yield no arguments — never a panic.
func toolArgs(req mcp.CallToolRequest) map[string]interface{} {
	m, _ := req.Params.Arguments.(map[string]interface{})
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

func argStr(req mcp.CallToolRequest, key string) string {
	s, _ := toolArgs(req)[key].(string)
	return s
}

func (s *Server) handleUse(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := map[string]interface{}{
		"secret_ref": argStr(req, "secret_ref"),
		"operation":  argStr(req, "operation"),
		"target":     argStr(req, "target"),
	}
	if pm, ok := toolArgs(req)["params"].(map[string]interface{}); ok {
		params["params"] = pm
	}
	data, err := s.call(ctx, ipc.MethodUseSubmit, params)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	raw, _ := json.Marshal(data)
	return mcp.NewToolResultText(string(raw)), nil
}

func (s *Server) handleTransfer(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := map[string]interface{}{
		"secret_ref":     argStr(req, "secret_ref"),
		"destination_id": argStr(req, "destination_id"),
		"payload_ref":    argStr(req, "payload_ref"),
	}
	data, err := s.call(ctx, ipc.MethodTransferSubmit, params)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	raw, _ := json.Marshal(data)
	return mcp.NewToolResultText(string(raw)), nil
}

func (s *Server) handleStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	opID := argStr(req, "op_id")
	data, err := s.call(ctx, ipc.MethodStatus, map[string]interface{}{
		"op_type": argStr(req, "op_type"),
		"op_id":   opID,
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	raw, _ := json.Marshal(data)
	return mcp.NewToolResultText(fmt.Sprintf(`%s`, string(raw))), nil
}

func (s *Server) GetMCPServer() *server.MCPServer {
	return s.mcp
}

func (s *Server) handleRelayStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := s.call(ctx, ipc.MethodRelayStatus, map[string]interface{}{
		"request_id": argStr(req, "request_id"),
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	raw, _ := json.Marshal(data)
	return mcp.NewToolResultText(string(raw)), nil
}

// handleRelayRequest creates a handoff request and returns its opaque ID.
// Plaintext intake happens only through the separately authenticated
// trusted-terminal path; this process is agent-side and must never receive
// the value, even through MCP elicitation.
func (s *Server) handleRelayRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := toolArgs(req)
	params := map[string]interface{}{
		"destination_id": argStr(req, "destination_id"),
		"data_kind":      argStr(req, "data_kind"),
		"purpose":        argStr(req, "purpose"),
	}
	if n, ok := args["ttl_seconds"].(float64); ok && n > 0 {
		params["ttl_seconds"] = n
	}
	data, err := s.call(ctx, ipc.MethodRelayRequest, params)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	m, _ := data.(map[string]interface{})
	reqID, _ := m["request_id"].(string)
	if reqID == "" {
		return mcp.NewToolResultError("broker did not return a request ID"), nil
	}
	// HI-06: the agent context receives only the public control-plane
	// status. No secret field, hint, placeholder, or host input session
	// token is included. Native host presentation is separate.
	raw, _ := json.Marshal(map[string]interface{}{
		"request_id":     reqID,
		"status":         "awaiting_user",
		"input_required": true,
		"input_kind":     args["data_kind"],
		"next_action":    "protected_input",
	})
	return mcp.NewToolResultText(string(raw)), nil
}
