package harness

import (
	"fmt"
	"time"
)

// HostSessionKind identifies a broker-qualified native-host integration.
// This is trusted configuration metadata, never a request-supplied
// identity assertion.
type HostSessionKind string

const (
	HostKindGeneric  HostSessionKind = "generic"
	HostKindHermes   HostSessionKind = "hermes"
	HostKindCodex    HostSessionKind = "codex"
	HostKindClaude   HostSessionKind = "claude-code"
	HostKindOpenCode HostSessionKind = "opencode"
	HostKindPi       HostSessionKind = "pi"
	HostKindJCode    HostSessionKind = "jcode"
	HostKindQwen     HostSessionKind = "qwen-code"
	HostKindAgy      HostSessionKind = "agy"
)

// HostSession is the broker-issued binding between a real harness
// instance, its workflow/thread, the authenticated agent identity, and
// the authorized human operator. The token is broker minted and must be
// retained only by the trusted host adapter — never placed in agent
// environment, shell, config, or model-visible context.
type HostSession struct {
	ID             string          `json:"id"`
	HostKind       HostSessionKind `json:"host_kind"`
	AgentPrincipal string          `json:"agent_principal"`
	HumanPrincipal string          `json:"human_principal"`
	ThreadID       string          `json:"thread_id"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Revision       uint64          `json:"revision"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// HostCapabilities carries broker-verifiable adapter facts separately from
// the host's security classification. Presentation describes UI capability;
// only an independently accepted AdapterQualification can raise the input
// mode above external_tty/model_blind.
type HostCapabilities struct {
	Presentation            string `json:"presentation"`
	InputTransport          string `json:"input_transport"`
	CredentialFormViaMCP    bool   `json:"credential_form_via_mcp"`
	SupportsResume          bool   `json:"supports_resume"`
	SupportsCancelPrompt    bool   `json:"supports_cancel_prompt"`
	SupportsMultiplePending bool   `json:"supports_multiple_pending"`
}

// HostSessionToken is returned once at registration. It is bearer
// evidence for the trusted host session and must never be logged or
// serialized through an agent control path.
type HostSessionToken struct {
	SessionID   string           `json:"session_id"`
	Token       string           `json:"token"`
	ExpiresAt   time.Time        `json:"expires_at"`
	Credentials HostCapabilities `json:"credentials"`
}

// HostRegistration is supplied by a trusted native-host adapter over the
// protected IPC domain. AgentPrincipal and HumanPrincipal are assigned
// from authenticated peer identity — the caller cannot name principals.
type HostRegistration struct {
	HostKind       HostSessionKind   `json:"host_kind"`
	ThreadID       string            `json:"thread_id"`
	HostVersion    string            `json:"host_version"`
	AdapterVersion string            `json:"adapter_version"`
	Topology       string            `json:"execution_topology,omitempty"`
	SecurityConfig map[string]string `json:"security_config,omitempty"`
	Credentials    HostCapabilities  `json:"credentials"`
	TTLOfSession   time.Duration     `json:"-"`
	HumanPrincipal string            `json:"-"`
}

// ProtectedInputTransaction is the shared trusted-adapter contract for
// one broker-backed credential handoff (CORE-02). It is intentionally
// separate from the agent-facing relay API: adapters implement it using
// the protected intake trust boundary, and agents never receive a
// reference to it.
//
// Fulfill and Reject compare RequestRev against the broker's current
// revision so a changed recipient or concurrent decision fails closed.
// DismissPrompt is display-only and must not fabricate relay cancellation.
type ProtectedInputTransaction interface {
	GetRequest(requestID string) (ProtectedInputNotice, error)
	Fulfill(requestID string, expectedRev uint64, payload []byte) error
	Reject(requestID string, expectedRev uint64) error
	DismissPrompt(requestID string) error
	GetStatus(requestID string) (RelayStatus, error)
}

// RelayStatus is the sanitized completion view available to the trusted
// adapter. It deliberately omits credential bytes and recipient wire data.
type RelayStatus struct {
	RequestID           string                `json:"request_id"`
	State               string                `json:"state"`
	RecipientID         string                `json:"recipient_id"`
	Consumption         string                `json:"consumption"`
	ExpiresAt           time.Time             `json:"expires_at"`
	OperationID         string                `json:"operation_id,omitempty"`
	RemainingDeliveries *int64                `json:"remaining_deliveries,omitempty"`
	Deliveries          []RelayDeliveryStatus `json:"deliveries,omitempty"`
}

// RelayDeliveryStatus is one sanitized per-delivery outcome for reusable or
// bounded grants. It exposes only broker-observed state and the operation
// locator — never credential bytes or recipient wire data.
type RelayDeliveryStatus struct {
	OperationID string     `json:"operation_id"`
	State       string     `json:"state"`
	Outcome     string     `json:"outcome,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// NegotiatedCapabilities returns the broker's explicit capability record for
// a host registration. It does not infer security from UI claims.
func NegotiatedCapabilities(caps HostCapabilities) HostCapabilities {
	if caps.Presentation == "" {
		caps.Presentation = "request_status"
	}
	if caps.InputTransport == "" {
		caps.InputTransport = "external_tty"
	}
	caps.CredentialFormViaMCP = false
	return caps
}

// TrustedHostClient is the concrete shared adapter client (CORE-02). It
// owns only a broker-authenticated host session and the trusted intake
// connection. It is not agent-reachable and does not return credential
// bytes to the caller. A higher-level package supplies the connection
// clients to avoid the harness<->ipc import cycle.
type TrustedHostClient struct {
	Intake  any
	Host    any
	Session HostSessionToken
}

// BrokerSecurityConfig derives the deployment security configuration from
// trusted broker topology facts (SP-06). This is set by the broker, not by
// the adapter. The adapter may report host version/capabilities, but its
// self-reported security configuration cannot establish isolation.
func BrokerSecurityConfig(assuranceMode string, hasIntakeGroup bool) map[string]string {
	cfg := map[string]string{
		"assurance_mode":    assuranceMode,
		"intake_group":      fmt.Sprintf("%t", hasIntakeGroup),
		"separate_uid":      fmt.Sprintf("%t", assuranceMode == "isolated"),
		"host_socket_owner": "broker_euid",
	}
	return cfg
}
