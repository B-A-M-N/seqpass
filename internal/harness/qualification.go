package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// QualificationStatus is the closed qualification vocabulary (HI-05).
// Fail-closed means an integration that has not passed all required
// boundaries is not qualified, even if it partially worked.
type QualificationStatus string

const (
	QualificationPassed      QualificationStatus = "passed"
	QualificationFailed      QualificationStatus = "failed"
	QualificationBlocked     QualificationStatus = "blocked"
	QualificationNotRun      QualificationStatus = "not_run"
	QualificationUnsupported QualificationStatus = "unsupported"
)

// HostInputMode names the tested presentation/data-plane pairing.
type HostInputMode string

const (
	QualifiedExternalTTY HostInputMode = "external_tty"
	QualifiedHostNative  HostInputMode = "host_native_verified"
	QualifiedNone        HostInputMode = "none"
)

// AdapterQualification is a durable, version-bound record. It is trusted
// configuration evidence, not an assertion supplied by the host or agent.
type AdapterQualification struct {
	ID                   string              `json:"id"`
	HostKind             HostSessionKind     `json:"host_kind"`
	HostVersion          string              `json:"host_version"`
	AdapterVersion       string              `json:"adapter_version"`
	InputMode            HostInputMode       `json:"input_mode"`
	Status               QualificationStatus `json:"status"`
	HostRevision         string              `json:"host_revision"`
	ExecutionTopology    string              `json:"execution_topology"`
	SecurityConfigDigest string              `json:"security_config_digest"`
	VerifiedProperties   map[string]bool     `json:"verified_properties"`
	TestedSurfaces       []string            `json:"tested_surfaces"`
	EvidenceReferences   []string            `json:"evidence_references"`
	QualifiedAt          time.Time           `json:"qualified_at"`
	ExpiresAt            time.Time           `json:"expires_at"`
}

// QualificationSnapshot is the current accepted record. The broker uses
// it as a whole; partial equality with a previous record does not carry
// qualification forward.
type QualificationSnapshot struct {
	HostKind       HostSessionKind
	HostVersion    string
	AdapterVersion string
	InputMode      HostInputMode
	Topology       string
	ConfigDigest   string
	Record         AdapterQualification
}

// SecurityConfigDigest hashes the deployment inputs that can invalidate
// a qualification. Version and topology are mandatory; security config
// may be empty only when the caller explicitly fingerprints "none".
func SecurityConfigDigest(hostKind HostSessionKind, hostVersion, adapterVersion, topology string, securityConfig map[string]string) (string, error) {
	if strings.TrimSpace(hostVersion) == "" || strings.TrimSpace(adapterVersion) == "" || strings.TrimSpace(topology) == "" {
		return "", fmt.Errorf("qualification requires host version, adapter version and topology")
	}
	if hostKind == "" {
		return "", fmt.Errorf("qualification requires host kind")
	}
	h := sha256.New()
	fmt.Fprintf(h, "seqpass-adapter-qualification\x00%s\x00%s\x00%s\x00%s\x00", hostKind, hostVersion, adapterVersion, topology)
	keys := make([]string, 0, len(securityConfig))
	for k := range securityConfig {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		if strings.Contains(k, "\x00") || strings.Contains(securityConfig[k], "\x00") {
			return "", fmt.Errorf("qualification config key contains NUL")
		}
		fmt.Fprintf(h, "%s=%s\x00", k, securityConfig[k])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidFor fails closed when any versioned/topological/config input does
// not exactly match the qualified snapshot or the record has expired.
func (q *AdapterQualification) ValidFor(hostKind HostSessionKind, hostVersion, adapterVersion string, inputMode HostInputMode, topology, configDigest string, now time.Time) error {
	if q.Status != QualificationPassed {
		return fmt.Errorf("host integration qualification is %q", q.Status)
	}
	if !now.Before(q.ExpiresAt) {
		return fmt.Errorf("host integration qualification expired")
	}
	if q.HostKind != hostKind || q.HostVersion != hostVersion || q.AdapterVersion != adapterVersion ||
		q.InputMode != inputMode || q.ExecutionTopology != topology || q.SecurityConfigDigest != configDigest {
		return fmt.Errorf("host integration changed since qualification")
	}
	return nil
}

// NativeModeDecision is the fail-closed result of matching a registration
// against the broker's accepted qualification snapshot.
//
// Presentation and isolation are deliberately separate claims (HI-01/4.3):
// Presentation says WHERE a value is typed (external trusted terminal vs an
// in-host native surface); IsolationAssurance says WHICH agent-observable
// boundaries have been independently verified. A native UI that keeps the
// value out of model messages is model-blind, not agent-isolated, and the
// two must never be conflated.
type NativeModeDecision struct {
	Mode       SecureInputMode
	Assurance  string
	Reason     string
	Qualified  bool
	RecordUsed bool

	// Presentation is the surface that would carry the value. It equals Mode.
	Presentation SecureInputMode
	// PresentationAssurance describes only model-visibility: "model_blind"
	// when the value never enters model messages or agent-visible results.
	PresentationAssurance string
	// IsolationAssurance is "agent_isolated" only when every required
	// boundary property is verified; otherwise "unverified".
	IsolationAssurance string
	// BoundariesVerified reports whether process, terminal, transcript and
	// intake boundaries were all verified for this decision.
	BoundariesVerified bool
	// MissingBoundaries lists the unverified boundary properties, empty when
	// BoundariesVerified is true.
	MissingBoundaries []string
}

// AgentIsolated reports whether the stronger, verified guarantee holds.
func (d NativeModeDecision) AgentIsolated() bool { return d.IsolationAssurance == "agent_isolated" }

// boundaryProperties are the independently verified boundaries required
// before any decision may advertise the agent-isolated guarantee.
var boundaryProperties = []string{
	"process_isolated", "terminal_isolated", "transcript_isolated", "intake_inaccessible",
}

// fallbackDecision is the safe external-TTY/model-blind result. It never
// claims isolation.
func fallbackDecision(reason string) NativeModeDecision {
	return NativeModeDecision{
		Mode:                  InputExternalTTY,
		Assurance:             "model_blind",
		Reason:                reason,
		Presentation:          InputExternalTTY,
		PresentationAssurance: "model_blind",
		IsolationAssurance:    "unverified",
	}
}

func missingBoundaries(props map[string]bool) []string {
	var missing []string
	for _, p := range boundaryProperties {
		if !props[p] {
			missing = append(missing, p)
		}
	}
	return missing
}

// SelectNativeMode matches the registration's exact host kind, version,
// adapter version, topology, and security configuration against the
// accepted snapshot. It never trusts the registration's Presentation or
// InputTransport flags as security evidence. A mismatch falls back to
// external_tty/model_blind, not to host-native.
func SelectNativeMode(snapshot *QualificationSnapshot, hostKind HostSessionKind, hostVersion, adapterVersion, topology string, securityConfig map[string]string, now time.Time) (NativeModeDecision, error) {
	if snapshot == nil {
		return fallbackDecision("no accepted qualification; using external trusted terminal"), nil
	}
	digest, err := SecurityConfigDigest(hostKind, hostVersion, adapterVersion, topology, securityConfig)
	if err != nil {
		return fallbackDecision("qualification inputs invalid; using external trusted terminal"), err
	}
	if err := snapshot.Record.ValidFor(snapshot.HostKind, snapshot.HostVersion, snapshot.AdapterVersion, snapshot.InputMode, snapshot.Topology, snapshot.ConfigDigest, now); err != nil {
		return fallbackDecision("qualification snapshot invalid; using external trusted terminal"), fmt.Errorf("qualification mismatch: %w", err)
	}
	if snapshot.HostKind != hostKind || snapshot.HostVersion != hostVersion ||
		snapshot.AdapterVersion != adapterVersion || snapshot.Topology != topology ||
		snapshot.ConfigDigest != digest {
		return fallbackDecision("qualification mismatch or expiry; using external trusted terminal"), fmt.Errorf("qualification mismatch: %w", err)
	}
	mode := InputExternalTTY
	assurance := "model_blind"
	if snapshot.InputMode == QualifiedHostNative {
		mode = InputHostNative
		assurance = "model_blind"
	}
	missing := missingBoundaries(snapshot.Record.VerifiedProperties)
	isolation := "unverified"
	if len(missing) == 0 {
		assurance = "agent_isolated"
		isolation = "agent_isolated"
	}
	return NativeModeDecision{
		Mode:                  mode,
		Assurance:             assurance,
		Reason:                "accepted qualification matched exact host/adapter/topology/config",
		Qualified:             true,
		RecordUsed:            true,
		Presentation:          mode,
		PresentationAssurance: "model_blind",
		IsolationAssurance:    isolation,
		BoundariesVerified:    len(missing) == 0,
		MissingBoundaries:     missing,
	}, nil
}

// SelectNativeModeRequiringIsolation is the fail-closed variant used when a
// deployment requires the verified boundary before offering inline native
// capture (objective 4.3). When the accepted record is host-native but not
// every required boundary property is verified, inline capture is WITHHELD
// and the decision falls back to the external trusted terminal. It never
// upgrades assurance; it can only decline to advertise it.
func SelectNativeModeRequiringIsolation(snapshot *QualificationSnapshot, hostKind HostSessionKind, hostVersion, adapterVersion, topology string, securityConfig map[string]string, now time.Time) (NativeModeDecision, error) {
	decision, err := SelectNativeMode(snapshot, hostKind, hostVersion, adapterVersion, topology, securityConfig, now)
	if err != nil {
		return decision, err
	}
	if decision.Mode != InputHostNative || decision.BoundariesVerified {
		return decision, nil
	}
	// Native capture withheld: fall back to the external trusted terminal
	// while reporting exactly which boundaries were unproven.
	decision.Mode = InputExternalTTY
	decision.Presentation = InputExternalTTY
	decision.Assurance = "model_blind"
	decision.IsolationAssurance = "unverified"
	decision.Reason = "native capture withheld: unverified boundaries " + joinStrings(decision.MissingBoundaries) + "; using external trusted terminal"
	return decision, nil
}

func joinStrings(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	if out == "" {
		return "none"
	}
	return out
}
