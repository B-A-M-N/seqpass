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

type Client struct {
	http *http.Client
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

// Resolve fetches one explicitly approved binding. Trusted executor only.
// Response bodies are never logged; strict size limits + unknown-field rejection.
//
// Version semantics (SC-13): both contracts resolve the CURRENT authorized
// value of a stable binding (latest_authorized). The approval binds the
// binding identity — not a credential version — so rotation between approval
// and execution changes the resolved material by design. Exact_version
// (pinned-payload) semantics are NOT supported by this contract: do not
// claim a transfer carries the reviewed byte value, only the reviewed
// binding. V2 component selectors use stable logical keys; the compatibility
// v1 fallback uses response-map keys, historically environment-variable names.
// AegisKeys Lock() prevents subsequent resolutions; it cannot retract
// plaintext already resolved.
func (c *Client) Resolve(ctx context.Context, binding, correlationID string) (CredentialMaterial, error) {
	if c == nil || c.http == nil {
		return CredentialMaterial{}, ErrTransportUnavailable
	}
	if binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	material, err := c.resolveV2(ctx, binding, correlationID)
	if errors.Is(err, errResolveV2Unsupported) {
		return c.resolveV1(ctx, binding, correlationID)
	}
	return material, err
}

var errResolveV2Unsupported = errors.New("resolve v2 unsupported")

func (c *Client) resolveV2(ctx context.Context, binding, correlationID string) (CredentialMaterial, error) {
	body, err := json.Marshal(map[string]string{"binding": binding})
	if err != nil {
		return CredentialMaterial{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://aegiskeys.local/v2/resolve", bytes.NewReader(body))
	if err != nil {
		return CredentialMaterial{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if correlationID != "" {
		req.Header.Set("X-Seqpass-Op", correlationID)
	}
	resp, err := c.http.Do(req)
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
	if raw.Protocol != "v2" || raw.Binding != binding {
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
func (c *Client) resolveV1(ctx context.Context, binding, correlationID string) (CredentialMaterial, error) {
	if c == nil || c.http == nil {
		return CredentialMaterial{}, ErrTransportUnavailable
	}
	if binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	body, err := json.Marshal(map[string]string{"binding": binding})
	if err != nil {
		return CredentialMaterial{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://aegiskeys.local/v1/resolve", bytes.NewReader(body))
	if err != nil {
		return CredentialMaterial{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if correlationID != "" {
		// Diagnostics only; must not influence authorization (server ignores it).
		req.Header.Set("X-Seqpass-Op", correlationID)
	}
	resp, err := c.http.Do(req)
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
	if raw.Binding != binding {
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
