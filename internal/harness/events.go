package harness

import "time"

// HostEventType is the payload-free presentation event vocabulary
// (HI-03). Events are refresh hints, never authorization or delivery
// mechanisms.
type HostEventType string

const (
	// HostRelayPending tells a connected host adapter to refresh one
	// pending request from broker state.
	HostRelayPending HostEventType = "relay.pending"
	// HostRelayChanged signals revision/state movement on an already
	// registered request.
	HostRelayChanged HostEventType = "relay.changed"
	// HostRelayResolved signals that the request reached a terminal
	// broker state.
	HostRelayResolved HostEventType = "relay.resolved"
)

// HostEvent contains only broker-verified public presentation metadata.
// It never contains secret bytes or agent-controlled security claims.
type HostEvent struct {
	Type       HostEventType `json:"type"`
	RequestID  string        `json:"request_id"`
	SessionID  string        `json:"session_id,omitempty"`
	Sequence   uint64        `json:"sequence"`
	State      string        `json:"state"`
	Revision   uint64        `json:"revision"`
	OccurredAt time.Time     `json:"occurred_at"`
}

// TrustedReviewDTO is the host-rendered verified envelope. Every security
// field comes from the relay row and live destination snapshot; Purpose
// remains explicitly untrusted annotation.
type TrustedReviewDTO struct {
	RequestID           string          `json:"request_id"`
	RequestRevision     uint64          `json:"request_revision"`
	DestinationDigest   string          `json:"destination_digest"`
	DestinationRevision int             `json:"destination_revision"`
	DataKind            string          `json:"data_kind"`
	DestinationID       string          `json:"destination_id"`
	DestinationName     string          `json:"destination_name"`
	Endpoint            string          `json:"endpoint"`
	Action              string          `json:"action"`
	ExpiresAt           time.Time       `json:"expires_at"`
	Consumption         string          `json:"consumption"`
	MaxDeliveries       uint32          `json:"max_deliveries"`
	Mode                SecureInputMode `json:"input_mode"`
	Assurance           string          `json:"input_assurance"`
	AgentPrincipal      string          `json:"agent_principal"`
	HumanPrincipal      string          `json:"human_principal"`
	SessionID           string          `json:"session_id,omitempty"`
	ThreadID            string          `json:"thread_id,omitempty"`
	Purpose             string          `json:"purpose,omitempty"`
	PurposeUntrusted    bool            `json:"purpose_untrusted"`
	TrustedHostRender   bool            `json:"trusted_host_render"`
}
