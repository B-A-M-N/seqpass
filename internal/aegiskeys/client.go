package aegiskeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ProtocolVersion is the AegisKeys broker IPC version this client speaks.
const ProtocolVersion = "v1"

const (
	maxComponents     = 32
	maxComponentBytes = 64 * 1024
	maxValueBytes     = 1 << 20
)

var (
	ErrVaultLocked          = errors.New("vault_locked")
	ErrBindingUnavailable   = errors.New("binding_unavailable")
	ErrAccessDenied         = errors.New("access_denied")
	ErrTransportUnavailable = errors.New("transport_unavailable")
	ErrProtocolMismatch     = errors.New("protocol_mismatch")
	ErrRequestInvalid       = errors.New("request_invalid")
)

// ResolveResponse mirrors the AegisKeys ResolvedCredential wire format.
// Strict unknown-field rejection is preserved; known fields must all decode.
type ResolveResponse struct {
	Binding    string            `json:"binding"`
	Kind       string            `json:"kind,omitempty"`
	EnvVar     string            `json:"env_var,omitempty"`
	Value      string            `json:"value,omitempty"`
	Components map[string]string `json:"components,omitempty"`
}

// ResolveResponseV2 preserves logical component keys and optional launch
// environment hints. The v1 response remains supported as a fallback.
type ResolveResponseV2 struct {
	Protocol         string                     `json:"protocol"`
	Binding          string                     `json:"binding"`
	Kind             string                     `json:"kind,omitempty"`
	EnvVar           string                     `json:"env_var,omitempty"`
	Value            string                     `json:"value,omitempty"`
	ComponentEntries []ResolveComponentResponse `json:"component_entries,omitempty"`
}

type ResolveComponentResponse struct {
	Key    string `json:"key"`
	EnvVar string `json:"env_var,omitempty"`
	Value  string `json:"value"`
}

// CredentialMaterial is plaintext resolved inside the trusted executor only.
// This type must never cross into MCP or agent IPC response paths.
type CredentialMaterial struct {
	Binding    string
	Kind       string
	Value      string
	Components map[string]string
}

// BrokerStatus is the structured /v1/status response.
type BrokerStatus struct {
	Protocol string
	Locked   bool
}

// Client resolves credentials from an AegisKeys broker over HTTP-over-Unix.
// Resolve speaks the v2 wire contract by default; legacy brokers that only
// implement v1 resolve semantics require the explicit legacy opt-in
// (SetLegacyProtocol). There is never an automatic version downgrade: a
// missing binding must not be misread as proof that v2 is unsupported.
type Client struct {
	http   *http.Client
	legacy bool
}

// SetLegacyProtocol opts this client into the v1 resolve endpoint and its
// legacy response-key semantics. It exists for explicitly configured legacy
// installations only; new installations use v2 (stable logical component
// keys) and must not silently downgrade.
func (c *Client) SetLegacyProtocol(legacy bool) {
	if c == nil {
		return
	}
	c.legacy = legacy
}

func socketPath(configDir string) string {
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".config", "aegiskeys")
	}
	return filepath.Join(configDir, "run", "broker.sock")
}

// ConnectSocket dials an explicit unix socket path (HTTP-over-Unix, never TCP).
func ConnectSocket(socket string) (*Client, error) {
	if socket == "" {
		return nil, fmt.Errorf("%w: empty socket path", ErrTransportUnavailable)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 10 * time.Second}}, nil
}

func Connect(configDir string) (*Client, error) {
	return ConnectSocket(socketPath(configDir))
}

// Status decodes the structured broker status including lock state.
func (c *Client) Status(ctx context.Context) (BrokerStatus, error) {
	if c == nil || c.http == nil {
		return BrokerStatus{}, ErrTransportUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://aegiskeys.local/v1/status", nil)
	if err != nil {
		return BrokerStatus{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return BrokerStatus{}, fmt.Errorf("%w: %v", ErrTransportUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return BrokerStatus{}, fmt.Errorf("%w: %s", ErrProtocolMismatch, resp.Status)
	}
	var st struct {
		Protocol string `json:"protocol"`
		Locked   bool   `json:"locked"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return BrokerStatus{}, fmt.Errorf("%w: decode", ErrProtocolMismatch)
	}
	if st.Protocol != ProtocolVersion {
		return BrokerStatus{}, fmt.Errorf("%w: protocol %q", ErrProtocolMismatch, st.Protocol)
	}
	return BrokerStatus{Protocol: st.Protocol, Locked: st.Locked}, nil
}

// ResolveRequest is the operation-aware resolve body. Operation names the
// logical driver operation the credential is consumed by (git.fetch,
// git.push, http.request, process.run, transfer); operation-scoped
// bindings reject any other operation. OperationID is an opaque correlation
// token carried into the broker audit log only — it never widens
// authorization.
type ResolveRequest struct {
	Binding     string `json:"binding"`
	Operation   string `json:"operation,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
}

// validOperationName mirrors the broker grammar ([a-z0-9._-], 1..64 chars)
// so malformed operations fail locally instead of producing a confusing
// remote denial.
func validOperationName(op string) bool {
	if len(op) == 0 || len(op) > 64 {
		return false
	}
	for _, r := range op {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// validOperationID mirrors the broker correlation-token grammar
// ([A-Za-z0-9._-], 1..128 chars).
func validOperationID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// Resolve fetches one explicitly approved binding under a specific logical
// operation. Trusted executor only. Response bodies are never logged;
// strict size limits + unknown-field rejection.
//
// Version semantics (SC-13): both contracts resolve the CURRENT authorized
// value of a stable binding (latest_authorized). The approval binds the
// binding identity — not a credential version — so rotation between approval
// and execution changes the resolved material by design. Exact_version
// (pinned-payload) semantics are NOT supported by this contract: do not
// claim a transfer carries the reviewed byte value, only the reviewed
// binding. V2 component selectors use stable logical keys; legacy v1
// response-key semantics require SetLegacyProtocol(true) — there is no
// automatic downgrade, because a 404 on an unknown binding is not proof
// that v2 is unsupported.
// AegisKeys Lock() prevents subsequent resolutions; it cannot retract
// plaintext already resolved.
func (c *Client) Resolve(ctx context.Context, binding, operation, operationID string) (CredentialMaterial, error) {
	if c == nil || c.http == nil {
		return CredentialMaterial{}, ErrTransportUnavailable
	}
	if binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	if !validOperationName(operation) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation", ErrRequestInvalid)
	}
	if operationID != "" && !validOperationID(operationID) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation_id", ErrRequestInvalid)
	}
	req := ResolveRequest{Binding: binding, Operation: operation, OperationID: operationID}
	if c.legacy {
		return c.resolveV1(ctx, req)
	}
	material, err := c.resolveV2(ctx, req)
	if errors.Is(err, errResolveV2Unsupported) {
		// Fail closed with an actionable error: the operator must either
		// fix the broker or explicitly configure legacy v1 mode. Falling
		// back here would mask missing bindings and scoped-authorization
		// refusals as version problems.
		return CredentialMaterial{}, fmt.Errorf("%w: %v (broker lacks /v2/resolve; configure legacy mode explicitly if required)", ErrProtocolMismatch, err)
	}
	return material, err
}

var errResolveV2Unsupported = errors.New("resolve v2 unsupported")

func (c *Client) resolveV2(ctx context.Context, req ResolveRequest) (CredentialMaterial, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CredentialMaterial{}, err
	}
	reqURL := "http://aegiskeys.local/v2/resolve"
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return CredentialMaterial{}, err
	}
	req2.Header.Set("Content-Type", "application/json")
	if req.OperationID != "" {
		// Diagnostics/correlation header; the operation_id body field is
		// what the broker writes to its audit log.
		req2.Header.Set("X-Seqpass-Op", req.OperationID)
	}
	resp, err := c.http.Do(req2)
	if err != nil {
		return CredentialMaterial{}, fmt.Errorf("%w: %v", ErrTransportUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, errResolveV2Unsupported
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, ErrAccessDenied
	case http.StatusLocked, http.StatusUnauthorized:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, ErrVaultLocked
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, fmt.Errorf("%w: %s", ErrProtocolMismatch, resp.Status)
	}
	var raw ResolveResponseV2
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return CredentialMaterial{}, fmt.Errorf("%w: decode", ErrProtocolMismatch)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CredentialMaterial{}, fmt.Errorf("%w: trailing data", ErrProtocolMismatch)
	}
	if raw.Protocol != "v2" || raw.Binding != req.Binding {
		return CredentialMaterial{}, fmt.Errorf("%w: version or binding mismatch", ErrProtocolMismatch)
	}
	if raw.Kind != "" && !validKind(raw.Kind) {
		return CredentialMaterial{}, fmt.Errorf("%w: kind", ErrProtocolMismatch)
	}
	if len(raw.Value) > maxValueBytes || len(raw.ComponentEntries) > maxComponents {
		return CredentialMaterial{}, fmt.Errorf("%w: credential bounds", ErrProtocolMismatch)
	}
	components := make(map[string]string, len(raw.ComponentEntries))
	for _, component := range raw.ComponentEntries {
		if component.Key == "" || component.Key == "primary" || len(component.Key) > 128 || len(component.EnvVar) > 256 || len(component.Value) > maxComponentBytes {
			return CredentialMaterial{}, fmt.Errorf("%w: component bounds", ErrProtocolMismatch)
		}
		if _, exists := components[component.Key]; exists {
			return CredentialMaterial{}, fmt.Errorf("%w: duplicate component key", ErrProtocolMismatch)
		}
		components[component.Key] = component.Value
	}
	if raw.Value == "" && len(components) == 0 {
		return CredentialMaterial{}, fmt.Errorf("%w: empty credential", ErrProtocolMismatch)
	}
	return CredentialMaterial{Binding: raw.Binding, Kind: raw.Kind, Value: raw.Value, Components: components}, nil
}

// resolveV1 preserves the legacy response-key semantics: component selectors
// match the keys of the v1 Components map (historically environment names).
// Reachable only through SetLegacyProtocol(true).
func (c *Client) resolveV1(ctx context.Context, req ResolveRequest) (CredentialMaterial, error) {
	if c == nil || c.http == nil {
		return CredentialMaterial{}, ErrTransportUnavailable
	}
	if req.Binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	body, err := json.Marshal(req)
	if err != nil {
		return CredentialMaterial{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://aegiskeys.local/v1/resolve", bytes.NewReader(body))
	if err != nil {
		return CredentialMaterial{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	if req.OperationID != "" {
		// Diagnostics only; must not influence authorization (server ignores it).
		r.Header.Set("X-Seqpass-Op", req.OperationID)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return CredentialMaterial{}, fmt.Errorf("%w: %v", ErrTransportUnavailable, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, ErrAccessDenied
	case http.StatusLocked, http.StatusUnauthorized:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, ErrVaultLocked
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, ErrBindingUnavailable
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CredentialMaterial{}, fmt.Errorf("%w: %s", ErrProtocolMismatch, resp.Status)
	}
	var raw ResolveResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return CredentialMaterial{}, fmt.Errorf("%w: decode", ErrProtocolMismatch)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CredentialMaterial{}, fmt.Errorf("%w: trailing data", ErrProtocolMismatch)
	}
	// Binding must equal the request, not merely be nonempty.
	if raw.Binding != req.Binding {
		return CredentialMaterial{}, fmt.Errorf("%w: binding mismatch", ErrProtocolMismatch)
	}
	if raw.Kind != "" && !validKind(raw.Kind) {
		return CredentialMaterial{}, fmt.Errorf("%w: kind", ErrProtocolMismatch)
	}
	if len(raw.Value) > maxValueBytes {
		return CredentialMaterial{}, fmt.Errorf("%w: oversize", ErrProtocolMismatch)
	}
	if len(raw.Components) > maxComponents {
		return CredentialMaterial{}, fmt.Errorf("%w: too many components", ErrProtocolMismatch)
	}
	for name, val := range raw.Components {
		if name == "" || len(name) > 128 || len(val) > maxComponentBytes {
			return CredentialMaterial{}, fmt.Errorf("%w: component bounds", ErrProtocolMismatch)
		}
	}
	if raw.Value == "" && len(raw.Components) == 0 {
		return CredentialMaterial{}, fmt.Errorf("%w: empty credential", ErrProtocolMismatch)
	}
	return CredentialMaterial{Binding: raw.Binding, Kind: raw.Kind, Value: raw.Value, Components: raw.Components}, nil
}

func validKind(k string) bool {
	k = strings.ToLower(k)
	switch k {
	case "password", "token", "api-key", "apikey", "ssh", "ssh-key", "certificate", "cert", "generic", "oauth", "kubeconfig":
		return true
	default:
		// Allow other nonempty kinds only if plausibly identifier-shaped.
		if k == "" || len(k) > 64 {
			return false
		}
		for _, r := range k {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
		return true
	}
}
