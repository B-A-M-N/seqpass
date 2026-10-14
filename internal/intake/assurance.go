// Package intake classifies secure-input assurance from verified broker
// topology, never from user-visible claims or harness marketing.
package intake

import "time"

// InputMode names the verified class of a secure-input surface. A mode is
// earned by actual process/topology configuration, never by a boolean flag
// or a reassuring label.
type InputMode string

const (
	// InputHostNative means a separately audited host adapter carries the
	// credential directly to the broker without model or MCP form data.
	InputHostNative InputMode = "host_native_verified"
	// InputExternalTTY means a separate trusted SeqPass terminal process
	// receives the bytes; the harness only displays request status.
	InputExternalTTY InputMode = "external_tty"
	// InputURLSecure means a detected URL-mode elicitation surface with
	// its own authenticated secure-input page. Must be feature-detected.
	InputURLSecure InputMode = "url_secure"
	// InputUnavailable means no verified protected input path exists.
	InputUnavailable InputMode = "unavailable"
)

// InputRequestNotice is the plaintext-free presentation contract for
// harness surfaces. It carries only broker-verified metadata.
type InputRequestNotice struct {
	RequestID     string    `json:"request_id"`
	DataKind      string    `json:"data_kind"`
	DestinationID string    `json:"destination_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	Mode          InputMode `json:"input_mode"`
}

// Assurance is the truthful classification shown before the user types.
type Assurance struct {
	Mode           InputMode `json:"mode"`
	Protected      bool      `json:"protected"`
	Reason         string    `json:"reason"`
	SameUID        bool      `json:"same_uid"`
	TerminalShared bool      `json:"terminal_shared"`
}

// Classify maps actual deployment topology to an honest assurance result.
// best-effort/same-UID topologies can never claim protected input.
func Classify(assuranceMode string, terminalShared bool) Assurance {
	if assuranceMode == "isolated" && !terminalShared {
		return Assurance{
			Mode:      InputExternalTTY,
			Protected: true,
			Reason:    "dedicated broker UID and separate trusted terminal verified",
		}
	}
	return Assurance{
		Mode:           InputUnavailable,
		Protected:      false,
		SameUID:        assuranceMode != "isolated",
		TerminalShared: terminalShared,
		Reason:         "isolation not verified: use a dedicated broker UID and a separate trusted terminal",
	}
}
