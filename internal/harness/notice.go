// Package harness is the plaintext-free presentation contract (SP-02)
// that any coding agent harness can implement to surface a pending
// SeqPass request through its existing notification surface. It carries
// only broker-verified metadata — never secret bytes, never agent-
// supplied security claims.
package harness

import (
	"fmt"
	"time"
)

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

// ProtectedInputNoticeSchemaVersion is the current version of the shared
// host-presentation wire schema (CORE-01). Every adapter must parse this
// exact version; unknown versions fail closed rather than being guessed.
const ProtectedInputNoticeSchemaVersion uint32 = 1

// ProtectedInputNotice is the versioned, payload-free review envelope for
// native host adapters. It contains only immutable, broker-derived fields
// needed to render one pending request. Secret bytes never enter this
// structure, and HostSessionID comes from authenticated host registration,
// not agent-supplied context.
type ProtectedInputNotice struct {
	Version        uint32          `json:"version"`
	RequestID      string          `json:"request_id"`
	RequestRev     uint64          `json:"request_revision"`
	HostSessionID  string          `json:"host_session_id"`
	DataKind       string          `json:"data_kind"`
	RecipientID    string          `json:"recipient_id"`
	RecipientLabel string          `json:"recipient_label"`
	Consumption    string          `json:"consumption"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Mode           SecureInputMode `json:"input_mode"`
	Assurance      string          `json:"input_assurance"`

	// Purpose remains separately identified as untrusted annotation. It is
	// never allowed to overwrite RecipientLabel, consumption policy, or a
	// trusted security indicator.
	UntrustedPurpose string `json:"untrusted_purpose,omitempty"`
}

// Validate fails closed when a notice is structurally unusable or appears
// to have been constructed outside the broker contract.
func (n ProtectedInputNotice) Validate() error {
	if n.Version != ProtectedInputNoticeSchemaVersion {
		return fmt.Errorf("unsupported protected-input notice version %d", n.Version)
	}
	if n.RequestID == "" || n.HostSessionID == "" || n.DataKind == "" ||
		n.RecipientID == "" || n.RecipientLabel == "" || n.Consumption == "" {
		return fmt.Errorf("protected-input notice missing required fields")
	}
	if n.RequestRev == 0 || n.ExpiresAt.IsZero() {
		return fmt.Errorf("protected-input notice missing review revision or expiry")
	}
	if n.Mode != InputExternalTTY && n.Mode != InputHostNative && n.Mode != InputURL {
		return fmt.Errorf("protected-input notice has no verified input mode")
	}
	if n.Assurance == "" {
		return fmt.Errorf("protected-input notice missing assurance classification")
	}
	return nil
}
