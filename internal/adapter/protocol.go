// Package adapter defines the transport-neutral contract every agent
// integration speaks to SeqPass: MCP tools, the `seqpass agent` CLI, and
// in-host display adapters all produce and consume the same request states,
// events and capability descriptions.
//
// The adapter is deliberately untrusted. It holds no vault, no database and
// no plaintext: it forwards requests to the broker and renders sanitized
// status. Every type in this package is designed so that an integration
// cannot accidentally widen what an agent can see.
package adapter

import (
	"fmt"
	"sort"
	"strings"
)

// RequestState is the closed, agent-facing vocabulary for a request. The
// broker has richer internal lifecycle names (relay "ready"/"reserved",
// operation "completed") but an agent must never receive an unqualified or
// unknown state, so every adapter surface reports one of these values only.
type RequestState string

const (
	// StateAwaitingUser: the broker is waiting for the human to authorize or
	// supply the protected value. No payload exists yet.
	StateAwaitingUser RequestState = "awaiting_user"
	// StateAuthorized: the human authorized the request; dispatch may begin.
	StateAuthorized RequestState = "authorized"
	// StateDispatching: the broker has committed to the external effect and
	// the outcome is not yet known.
	StateDispatching RequestState = "dispatching"
	// StateAccepted: the recipient durably accepted the delivery, but the
	// intended effect is not independently verified.
	StateAccepted RequestState = "accepted"
	// StateApplied: the consumer verified the intended effect. This is the
	// only success state that may be described as fully done.
	StateApplied RequestState = "applied"
	// StateUncertain: an external effect may have occurred but could not be
	// confirmed. Never auto-retried; reconciled against the original target.
	StateUncertain RequestState = "uncertain"
	// StateRejected: refused, denied, or withdrawn before any effect.
	StateRejected RequestState = "rejected"
	// StateExpired: the request deadline passed before fulfillment.
	StateExpired RequestState = "expired"
	// StateUnavailable: the broker or destination could not be reached, so
	// no decision was made either way.
	StateUnavailable RequestState = "unavailable"
)

// requestStates is the canonical ordered vocabulary.
var requestStates = []RequestState{
	StateAwaitingUser, StateAuthorized, StateDispatching, StateAccepted,
	StateApplied, StateUncertain, StateRejected, StateExpired, StateUnavailable,
}

// stateAliases maps broker-internal lifecycle names onto the closed
// vocabulary. Every alias is intentional and total: an unrecognized name is
// an error, never a guess.
var stateAliases = map[string]RequestState{
	"awaiting_user": StateAwaitingUser,
	"pending":       StateAwaitingUser,
	"requested":     StateAwaitingUser,
	"ready":         StateAuthorized,
	"reserved":      StateAuthorized,
	"authorized":    StateAuthorized,
	"authorised":    StateAuthorized,
	"dispatching":   StateDispatching,
	"executing":     StateDispatching,
	"claimed":       StateDispatching,
	"delivered":     StateAccepted,
	"accepted":      StateAccepted,
	"applied":       StateApplied,
	"completed":     StateApplied,
	"uncertain":     StateUncertain,
	"rejected":      StateRejected,
	"failed":        StateRejected,
	"denied":        StateRejected,
	"cancelled":     StateRejected,
	"canceled":      StateRejected,
	"expired":       StateExpired,
	"unavailable":   StateUnavailable,
}

// States returns the closed vocabulary in canonical order.
func States() []RequestState {
	out := make([]RequestState, len(requestStates))
	copy(out, requestStates)
	return out
}

// Valid reports whether s is in the closed vocabulary.
func (s RequestState) Valid() bool {
	for _, v := range requestStates {
		if s == v {
			return true
		}
	}
	return false
}

// Terminal reports whether no further transition is expected.
func (s RequestState) Terminal() bool {
	switch s {
	case StateApplied, StateUncertain, StateRejected, StateExpired, StateUnavailable:
		return true
	}
	return false
}

// Succeeded reports whether the request reached a verified success. Only
// StateApplied qualifies: StateAccepted means stored, not verified.
func (s RequestState) Succeeded() bool { return s == StateApplied }

// Settled reports whether the agent should stop polling: every terminal
// state plus StateApplied.
func (s RequestState) Settled() bool { return s.Terminal() }

// Normalize maps a broker-reported status string onto the closed vocabulary.
// Unknown, empty, or unqualified values are an error: an adapter must not
// invent a state to look responsive.
func Normalize(raw string) (RequestState, error) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return "", fmt.Errorf("empty request state")
	}
	if st, ok := stateAliases[key]; ok {
		return st, nil
	}
	return "", fmt.Errorf("unqualified request state %q", raw)
}

// Transport names the wire an integration uses to reach the broker.
type Transport string

const (
	TransportMCP  Transport = "mcp"
	TransportCLI  Transport = "cli"
	TransportHost Transport = "host"
)

// Operation is one discoverable credentialed operation the agent may invoke,
// exactly as the broker's policy-filtered catalog describes it. It never
// carries a value.
type Operation struct {
	SecretRef   string `json:"secret_ref"`
	Name        string `json:"name"`
	Access      string `json:"access"`
	Description string `json:"description,omitempty"`
}

// Capability describes what an agent integration may ask for. It is the
// discovery payload for both MCP and CLI, so an agent can plan without
// probing: which operations exist, which states to expect, and which
// surfaces the integration deliberately does not expose.
type Capability struct {
	Transport       Transport      `json:"transport"`
	Assurance       string         `json:"assurance"`
	DataKinds       []string       `json:"data_kinds"`
	Operations      []Operation    `json:"operations"`
	States          []RequestState `json:"states"`
	RequestPath     string         `json:"request_path"`
	StatusPath      string         `json:"status_path"`
	CancelPath      string         `json:"cancel_path"`
	InputMode       string         `json:"input_mode"`
	InputReason     string         `json:"input_reason"`
	NeverExposesKey bool           `json:"never_exposes_secret"`
	Constraints     []string       `json:"constraints"`
}

// DataKindsSupported is the closed set of data kinds a relay may request.
// It mirrors the broker's accepted kinds so discovery cannot drift.
var DataKindsSupported = []string{"password", "one_time_code", "api_key", "token", "pin", "text"}

// RequestPaths are the transport-specific invoke surfaces. They name the
// call to make; they never contain an argument value.
var RequestPaths = map[Transport]struct{ Request, Status, Cancel string }{
	TransportMCP:  {"relay_request", "relay_status", "relay_cancel"},
	TransportCLI:  {"seqpass agent request", "seqpass agent status", "seqpass agent cancel"},
	TransportHost: {"host:request", "host:status", "host:cancel"},
}

// NewCapability builds the discovery payload for a transport. assurance,
// inputMode and inputReason are broker-supplied facts, never agent claims.
func NewCapability(transport Transport, assurance, inputMode, inputReason string, operations []Operation) Capability {
	paths, ok := RequestPaths[transport]
	if !ok {
		paths = RequestPaths[TransportCLI]
	}
	sorted := make([]Operation, len(operations))
	copy(sorted, operations)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].SecretRef != sorted[j].SecretRef {
			return sorted[i].SecretRef < sorted[j].SecretRef
		}
		return sorted[i].Name < sorted[j].Name
	})
	return Capability{
		Transport:       transport,
		Assurance:       assurance,
		DataKinds:       append([]string{}, DataKindsSupported...),
		Operations:      sorted,
		States:          States(),
		RequestPath:     paths.Request,
		StatusPath:      paths.Status,
		CancelPath:      paths.Cancel,
		InputMode:       inputMode,
		InputReason:     inputReason,
		NeverExposesKey: true,
		Constraints: []string{
			"the credential value is never an argument, environment variable, log line, file written by the agent, or tool result",
			"the request only names a registered destination, an operation name, and a data kind",
			"status carries opaque identifiers and states only, never a hint, prefix, length or fingerprint of the value",
			"an unqualified or unknown broker state is refused rather than reported",
		},
	}
}

// OperationFromCatalog flattens a decoded broker catalog payload into the
// adapter's operation view. It accepts the wire shapes ipc returns
// ([]map[string]interface{}) and never reads a value field.
func OperationFromCatalog(payload interface{}) []Operation {
	rows := asRows(payload)
	var out []Operation
	for _, row := range rows {
		ref, _ := row["ref"].(map[string]interface{})
		id, _ := ref["id"].(string)
		ops, _ := row["operations"].([]interface{})
		for _, raw := range ops {
			op, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := op["name"].(string)
			if id == "" || name == "" {
				continue
			}
			access, _ := op["access"].(string)
			desc, _ := op["description"].(string)
			out = append(out, Operation{SecretRef: id, Name: name, Access: access, Description: desc})
		}
	}
	return out
}

func asRows(payload interface{}) []map[string]interface{} {
	switch typed := payload.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(typed))
		for _, e := range typed {
			if m, ok := e.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// sensitiveKeys are field names that must never appear on an agent-visible
// adapter surface. The list is intentionally broad: a false positive costs a
// rename, a false negative leaks a credential.
var sensitiveKeys = map[string]bool{
	"secret": true, "secret_value": true, "value": true, "payload": true,
	"password": true, "passwd": true, "token": true, "api_key": true,
	"apikey": true, "otp": true, "one_time_code": true, "pin": true,
	"credential": true, "plaintext": true, "private_key": true,
	"access_token": true, "refresh_token": true, "client_secret": true,
}

// SensitiveField returns the first agent-visible field name that would carry
// credential material, and false when the map is clean.
func SensitiveField(m map[string]interface{}) (string, bool) {
	for k := range m {
		if sensitiveKeys[strings.ToLower(k)] {
			return k, true
		}
	}
	return "", false
}

// Scrub returns a copy of m with every sensitive key's value replaced by a
// redaction marker. It is used when rendering broker payloads that the
// adapter cannot prove are clean.
func Scrub(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if sensitiveKeys[strings.ToLower(k)] {
			out[k] = "[redacted]"
			continue
		}
		if nested, ok := v.(map[string]interface{}); ok {
			out[k] = Scrub(nested)
			continue
		}
		out[k] = v
	}
	return out
}
