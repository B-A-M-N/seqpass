// Package intake classifies secure-input assurance from verified broker
// topology, never from user-visible claims or harness marketing.
package intake

import "time"

// InputMode names the verified class of a secure-input surface. A mode
// is earned by actual process/topology configuration, never by a
// boolean flag or a reassuring label.
type InputMode string

const (
	// InputExternalTTY means a separate trusted SeqPass terminal process
	// receives the bytes; the harness only displays request status.
	InputExternalTTY InputMode = "external_tty"
	// InputHostNative means a separately audited host adapter carries
	// the credential directly to the broker without model or MCP data.
	InputHostNative InputMode = "host_native_verified"
	// InputURL means a URL-mode elicitation surface (MCP July 2026
	// spec), which keeps the submitted value outside the MCP client.
	InputURL InputMode = "url"
	// InputUnavailable means no verified protected input path exists.
	InputUnavailable InputMode = "unavailable"
)

// InputAssurance is the closed set of honest classifications for the
// protected-input surface (SP-03). Verified requires independently
// qualified host topology — never just a masked field.
type InputAssurance string

const (
	// AssuranceVerified means the submitting process identity, intake
	// permissions, and agent isolation are all independently verified.
	AssuranceVerified InputAssurance = "verified"
	// AssuranceUnverified means the path exists but topology has not
	// been independently qualified (e.g. same-UID best-effort mode).
	AssuranceUnverified InputAssurance = "unverified"
	// AssuranceProhibited means the agent can observe the intake socket
	// or terminal — the path must not be used for credential entry.
	AssuranceProhibited InputAssurance = "prohibited"
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
	Mode             InputMode      `json:"mode"`
	Assurance        InputAssurance `json:"assurance"`
	Protected        bool           `json:"protected"`
	Reason           string         `json:"reason"`
	SameUID          bool           `json:"same_uid"`
	TerminalShared   bool           `json:"terminal_shared"`
	IntakeAccessible bool           `json:"intake_accessible"`
}

// Classify maps actual deployment topology to an honest assurance
// result. It evaluates: assurance mode, terminal sharing, intake
// socket reachability from the agent identity, and peer identity.
// best-effort/same-UID topologies can never claim verified protection.
func Classify(assuranceMode string, terminalShared bool, intakeAccessible bool) Assurance {
	// SP-03: if the agent can reach the intake socket, protection is
	// actively prohibited — not merely unverified.
	if intakeAccessible {
		return Assurance{
			Mode:             InputUnavailable,
			Assurance:        AssuranceProhibited,
			Protected:        false,
			SameUID:          assuranceMode != "isolated",
			TerminalShared:   terminalShared,
			IntakeAccessible: true,
			Reason:           "agent can access the intake socket: credential entry must not proceed",
		}
	}
	if assuranceMode == "isolated" && !terminalShared {
		return Assurance{
			Mode:             InputExternalTTY,
			Assurance:        AssuranceVerified,
			Protected:        true,
			SameUID:          false,
			TerminalShared:   false,
			IntakeAccessible: false,
			Reason:           "dedicated broker UID, separate intake domain and trusted terminal verified",
		}
	}
	return Assurance{
		Mode:             InputUnavailable,
		Assurance:        AssuranceUnverified,
		Protected:        false,
		SameUID:          assuranceMode != "isolated",
		TerminalShared:   terminalShared,
		IntakeAccessible: false,
		Reason:           "isolation not verified: use a dedicated broker UID and a separate trusted terminal",
	}
}
