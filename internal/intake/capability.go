package intake

// Capability names the independently verified observation boundary being
// classified. These are facts supplied by the trusted broker/deployment
// configuration — never by the agent.
type Capability string

const (
	// CapabilityTerminalObserve means the agent can observe the terminal
	// input or output stream (PTY recording, terminal APIs, shared TTY).
	CapabilityTerminalObserve Capability = "terminal_observe"
	// CapabilityProcessInspect means the agent can inspect trusted-process
	// memory or launch/trace processes with access to protected data.
	CapabilityProcessInspect Capability = "process_inspect"
	// CapabilityTranscriptRead means the agent can read transcripts, debug
	// records, or replay logs that could contain protected input.
	CapabilityTranscriptRead Capability = "transcript_read"
)

// VerifiedProperties is the closed set of properties required for full
// agent isolation. Unknown/unverified boundaries stay out of this set.
type VerifiedProperties struct {
	IntakeInaccessible bool `json:"intake_inaccessible"`
	TerminalIsolated   bool `json:"terminal_isolated"`
	ProcessIsolated    bool `json:"process_isolated"`
	TranscriptIsolated bool `json:"transcript_isolated"`
}

// Complete reports whether every boundary required by agent_isolated has
// been independently verified.
func (p VerifiedProperties) Complete() bool {
	return p.IntakeInaccessible && p.TerminalIsolated &&
		p.ProcessIsolated && p.TranscriptIsolated
}

// AssuredInputMode names the verified class of the trusted input surface.
// The distinction matters: model_blind means plaintext does not enter
// model messages or agent-visible results; agent_isolated additionally
// requires every disclosed process/tool/transcript boundary to be tested.
type AssuredInputMode string

const (
	// ModelBlindHostNative is a broker-qualified host-native input path
	// whose secret never enters model context, but whose process/tool
	// isolation has not all been proven.
	ModelBlindHostNative AssuredInputMode = "model_blind_host_native"
	// AgentIsolatedHostNative is model-blind AND the verified agent
	// process/tool/transcript boundaries are complete.
	AgentIsolatedHostNative AssuredInputMode = "agent_isolated_host_native"
)

// Classify maps verified boundary facts to the restricted assurance
// vocabulary from the host-integration review. intakeAccessible always
// wins: any reachable protected transport is prohibited.
func ClassifyBoundaries(props VerifiedProperties, intakeAccessible bool) Assurance {
	if intakeAccessible {
		return Assurance{
			Mode:       InputUnavailable,
			Assurance:  AssuranceProhibited,
			Protected:  false,
			Properties: VerifiedProperties{},
			Reason:     "agent can access the protected input transport: credential entry must not proceed",
		}
	}
	// Preserve legacy topology classification: dedicated broker UID plus
	// a separate trusted terminal is the external-TTY baseline.
	if props.IntakeInaccessible && !props.Complete() {
		return Assurance{
			Mode:       InputExternalTTY,
			Assurance:  AssuranceModelBlind,
			Protected:  true,
			Properties: props,
			Reason:     "protected transport is isolated; remaining agent process/tool/transcript boundaries are not all proven",
		}
	}
	if props.Complete() {
		return Assurance{
			Mode:       InputExternalTTY,
			Assurance:  AssuranceAgentIsolated,
			Protected:  true,
			Properties: props,
			Reason:     "protected transport, terminal, process and transcript boundaries verified",
		}
	}
	return Assurance{
		Mode:       InputUnavailable,
		Assurance:  AssuranceUnverified,
		Protected:  false,
		Properties: props,
		Reason:     "required isolation boundaries are not fully verified",
	}
}
