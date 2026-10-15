// Package harness is the plaintext-free presentation contract (SP-02)
// that any coding agent harness can implement to surface a pending
// SeqPass request through its existing notification surface. It carries
// only broker-verified metadata — never secret bytes, never agent-
// supplied security claims.
package harness

import "time"

// SecureInputMode is the verified class of the trusted input surface
// (SP-01/SP-03). The agent must never claim a mode — this value comes
// from the broker's independently qualified deployment topology.
type SecureInputMode string

const (
	// InputExternalTTY is a separately trusted SeqPass terminal process
	// receiving the bytes; the harness only shows request status.
	InputExternalTTY SecureInputMode = "external_tty"
	// InputHostNative is a host-owned secure-input extension qualified
	// by the operator. Only broker config — never the agent — can
	// set this mode.
	InputHostNative SecureInputMode = "host_native_verified"
	// InputURL is a URL-mode elicitation surface (MCP July 2026 spec),
	// which keeps the submitted value outside the MCP client.
	InputURL SecureInputMode = "url"
	// InputUnavailable means no verified protected input path exists.
	InputUnavailable SecureInputMode = "unavailable"
)

// RequestNotice is the payload-free notification structure that a
// harness adapter displays to the human. It contains no plaintext and
// no agent-controllable security claims — all fields are broker-derived.
type RequestNotice struct {
	RequestID string          `json:"request_id"`
	DataKind  string          `json:"data_kind"`
	DestID    string          `json:"destination_id"`
	ExpiresAt time.Time       `json:"expires_at"`
	Mode      SecureInputMode `json:"input_mode"`
	// Purpose is agent-supplied and must be sanitized before display.
	// The harness should render it as untrusted annotation.
	Purpose string `json:"purpose,omitempty"`
}
