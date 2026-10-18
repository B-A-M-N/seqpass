package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// EventType is the closed set of adapter event kinds. A consumer that sees
// an unknown type must treat the stream as untrustworthy rather than
// ignoring the frame.
type EventType string

const (
	// EventStateChanged reports a request moving between RequestStates.
	EventStateChanged EventType = "state_changed"
	// EventReceipt reports sanitized delivery metadata for a completed
	// transfer (byte count, digest of the payload as the broker saw it,
	// recipient label). Never the value.
	EventReceipt EventType = "receipt"
	// EventError reports a refusal or transport failure.
	EventError EventType = "error"
	// EventCapabilities reports adapter discovery.
	EventCapabilities EventType = "capabilities"
)

var eventTypes = map[EventType]bool{
	EventStateChanged: true, EventReceipt: true, EventError: true, EventCapabilities: true,
}

// Event is the single sanitized frame every adapter emits. It has no field
// that can hold credential material: identifiers, states, counts and
// redacted metadata only.
type Event struct {
	Type        EventType    `json:"type"`
	RequestID   string       `json:"request_id,omitempty"`
	OperationID string       `json:"operation_id,omitempty"`
	State       RequestState `json:"state,omitempty"`
	Outcome     string       `json:"outcome,omitempty"`
	NextAction  string       `json:"next_action,omitempty"`
	Assurance   string       `json:"assurance,omitempty"`
	Code        string       `json:"code,omitempty"`
	Message     string       `json:"message,omitempty"`
	Bytes       int          `json:"bytes,omitempty"`
	At          time.Time    `json:"at"`
}

// Validate enforces the event contract: a known type, a qualified state when
// one is present, and no sensitive field reachable from the frame.
func (e Event) Validate() error {
	if !eventTypes[e.Type] {
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	if e.State != "" && !e.State.Valid() {
		return fmt.Errorf("unqualified event state %q", e.State)
	}
	if e.Type == EventStateChanged && e.State == "" {
		return fmt.Errorf("state_changed event without a state")
	}
	if _, bad := SensitiveField(map[string]interface{}{
		"outcome": e.Outcome, "message": e.Message, "code": e.Code,
	}); bad {
		return fmt.Errorf("event carries a sensitive field")
	}
	return nil
}

// Encode validates and marshals an event. A frame that fails validation is
// never emitted.
func Encode(e Event) ([]byte, error) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// Decode parses one event frame, rejecting unknown fields so a newer or
// hostile producer cannot smuggle extra data past the adapter.
func Decode(frame []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Event{}, err
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// StateChanged is the convenience constructor for a status transition.
func StateChanged(requestID string, state RequestState, outcome, nextAction string) Event {
	return Event{
		Type: EventStateChanged, RequestID: requestID, State: state,
		Outcome: outcome, NextAction: nextAction,
	}
}

// Receipt is the convenience constructor for a sanitized transfer receipt.
func Receipt(operationID string, state RequestState, recipient string, bytes int) Event {
	return Event{
		Type: EventReceipt, OperationID: operationID, State: state,
		Bytes: bytes, Outcome: "recipient=" + recipient,
	}
}

// ErrorEvent is the convenience constructor for a refusal.
func ErrorEvent(code, message string) Event {
	return Event{Type: EventError, Code: code, Message: message}
}

// RedactMessage removes anything that looks like a credential from free
// text before it reaches an agent surface. It is a defence in depth: the
// adapter should never have plaintext to begin with.
func RedactMessage(msg string) string {
	fields := strings.Fields(msg)
	for i, f := range fields {
		lower := strings.ToLower(f)
		for key := range sensitiveKeys {
			if strings.HasPrefix(lower, key+"=") || strings.HasPrefix(lower, key+":") {
				fields[i] = key + "=[redacted]"
			}
		}
	}
	return strings.Join(fields, " ")
}
