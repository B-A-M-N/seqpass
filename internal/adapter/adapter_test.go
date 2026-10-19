package adapter

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every broker-reported status either maps into the closed vocabulary or is
// refused; an adapter must never invent a state.
func TestNormalizeMapsBrokerStatesAndRejectsUnknown(t *testing.T) {
	cases := map[string]RequestState{
		"awaiting_user": StateAwaitingUser,
		"ready":         StateAuthorized,
		"reserved":      StateAuthorized,
		"dispatching":   StateDispatching,
		"delivered":     StateAccepted,
		"accepted":      StateAccepted,
		"applied":       StateApplied,
		"completed":     StateApplied,
		"uncertain":     StateUncertain,
		"cancelled":     StateRejected,
		"expired":       StateExpired,
		"unavailable":   StateUnavailable,
	}
	for raw, want := range cases {
		got, err := Normalize(raw)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("Normalize(%q) = %q, want %q", raw, got, want)
		}
	}
	for _, bad := range []string{"", "  ", "maybe", "READY-ish", "done"} {
		if _, err := Normalize(bad); err == nil {
			t.Fatalf("Normalize(%q) accepted an unqualified state", bad)
		}
	}
}

func TestStatePredicates(t *testing.T) {
	if !StateApplied.Succeeded() {
		t.Fatal("applied must count as success")
	}
	if StateAccepted.Succeeded() {
		t.Fatal("durable acceptance must not be reported as verified success")
	}
	if !StateUncertain.Terminal() || !StateRejected.Terminal() {
		t.Fatal("terminal states not recognised")
	}
	if StateDispatching.Terminal() {
		t.Fatal("dispatching must not be terminal")
	}
	for _, s := range States() {
		if !s.Valid() {
			t.Fatalf("advertised state %q is not valid", s)
		}
	}
}

func TestCapabilityIsBoundedAndDeclaresNoExposure(t *testing.T) {
	ops := []Operation{
		{SecretRef: "zeta", Name: "b"},
		{SecretRef: "alpha", Name: "a"},
	}
	cap := NewCapability(TransportMCP, "unverified", "external_tty", "reason", ops)
	if !cap.NeverExposesKey {
		t.Fatal("capability does not declare the no-exposure guarantee")
	}
	if cap.RequestPath != "relay_request" || cap.StatusPath != "relay_status" {
		t.Fatalf("mcp paths wrong: %+v", cap)
	}
	if cap.Operations[0].SecretRef != "alpha" || cap.Operations[1].SecretRef != "zeta" {
		t.Fatalf("operations not deterministically ordered: %+v", cap.Operations)
	}
	if len(cap.DataKinds) != len(DataKindsSupported) {
		t.Fatalf("data kinds not fully advertised: %v", cap.DataKinds)
	}
	raw, err := json.Marshal(cap)
	if err != nil {
		t.Fatal(err)
	}
	// The discovery payload itself must be free of sensitive field names.
	var round map[string]interface{}
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if k, bad := SensitiveField(round); bad {
		t.Fatalf("capability discovery exposes sensitive field %q", k)
	}
	if !strings.Contains(string(raw), "never_exposes_secret") {
		t.Fatalf("capability payload missing the exposure guarantee: %s", raw)
	}
}

func TestCapabilityCLIPaths(t *testing.T) {
	cap := NewCapability(TransportCLI, "unverified", "external_tty", "", nil)
	if cap.RequestPath != "seqpass agent request" || cap.CancelPath != "seqpass agent cancel" {
		t.Fatalf("cli paths wrong: %+v", cap)
	}
}

func TestOperationFromCatalogWireShape(t *testing.T) {
	payload := []map[string]interface{}{
		{
			"ref": map[string]interface{}{"id": "ref-1"},
			"operations": []interface{}{
				map[string]interface{}{"name": "github.get_repo", "access": "ready", "description": "read a repo"},
				map[string]interface{}{"name": "", "access": "ready"},
			},
		},
		{"ref": map[string]interface{}{"id": ""}},
	}
	ops := OperationFromCatalog(payload)
	if len(ops) != 1 {
		t.Fatalf("expected one usable operation, got %+v", ops)
	}
	if ops[0].SecretRef != "ref-1" || ops[0].Name != "github.get_repo" || ops[0].Access != "ready" {
		t.Fatalf("operation decoded wrong: %+v", ops[0])
	}
}

func TestScrubRemovesSensitiveFields(t *testing.T) {
	in := map[string]interface{}{
		"status": "applied",
		"secret": "synthetic-value",
		"nested": map[string]interface{}{"token": "synthetic-value", "id": "op-1"},
	}
	out := Scrub(in)
	if out["secret"] != "[redacted]" {
		t.Fatalf("secret not redacted: %v", out["secret"])
	}
	nested, _ := out["nested"].(map[string]interface{})
	if nested["token"] != "[redacted]" || nested["id"] != "op-1" {
		t.Fatalf("nested scrub wrong: %v", nested)
	}
	// No value from the original map may survive, at any depth.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "synthetic-value") {
		t.Fatalf("scrubbed payload still contains a credential: %s", raw)
	}
	// Non-sensitive keys are preserved so the frame stays useful.
	if out["status"] != "applied" {
		t.Fatalf("scrub dropped a benign field: %v", out)
	}
}

func TestEventRoundTrip(t *testing.T) {
	e := StateChanged("req-1", StateAwaitingUser, "", "protected_input")
	frame, err := Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req-1" || got.State != StateAwaitingUser || got.At.IsZero() {
		t.Fatalf("event round trip lost data: %+v", got)
	}
}

func TestEventRejectsUnqualifiedStateAndUnknownFields(t *testing.T) {
	if _, err := Encode(Event{Type: EventStateChanged, State: "definitely_done"}); err == nil {
		t.Fatal("unqualified state accepted")
	}
	if _, err := Encode(Event{Type: "made_up"}); err == nil {
		t.Fatal("unknown event type accepted")
	}
	if _, err := Encode(Event{Type: EventStateChanged}); err == nil {
		t.Fatal("state_changed without a state accepted")
	}
	// Unknown wire fields are refused so a producer cannot smuggle data.
	if _, err := Decode([]byte(`{"type":"error","code":"x","payload":"synthetic-value","at":"2026-01-01T00:00:00Z"}`)); err == nil {
		t.Fatal("unknown field smuggled past Decode")
	}
}

// A free-text field carrying a credential assignment is refused outright,
// and the explicit sanitizer removes it for text the adapter cannot vouch
// for.
func TestEventRefusesCredentialBearingText(t *testing.T) {
	dirty := Event{Type: EventError, Code: "bad_input", Message: "broker said token=synthetic-secret-abc"}
	if _, err := Encode(dirty); err == nil {
		t.Fatal("event with credential-bearing text was emitted")
	}
	clean := dirty.Sanitized()
	frame, err := Encode(clean)
	if err != nil {
		t.Fatalf("sanitized event rejected: %v", err)
	}
	if strings.Contains(string(frame), "synthetic-secret-abc") {
		t.Fatalf("sanitized event still leaks a credential: %s", frame)
	}
	if !strings.Contains(string(frame), "[redacted]") {
		t.Fatalf("sanitized event lost the redaction marker: %s", frame)
	}
}

func TestReceiptCarriesNoValue(t *testing.T) {
	frame, err := Encode(Receipt("op-1", StateAccepted, "Registered Recipient", 42))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(frame), "synthetic") {
		t.Fatalf("receipt leaked a value: %s", frame)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(frame, &round); err != nil {
		t.Fatal(err)
	}
	if _, bad := SensitiveField(round); bad {
		t.Fatal("receipt exposes a sensitive field")
	}
}

func TestRedactMessage(t *testing.T) {
	got := RedactMessage("failed to use token=abc123 for request")
	if strings.Contains(got, "abc123") {
		t.Fatalf("credential survived redaction: %q", got)
	}
	if !strings.Contains(got, "token=[redacted]") {
		t.Fatalf("redaction did not rewrite the field: %q", got)
	}
}

func TestCapabilityCarriesProtocolVersion(t *testing.T) {
	cap := NewCapability(TransportCLI, "isolated", "external_tty", "test", nil)
	if cap.ProtocolVersion != ProtocolVersion {
		t.Fatalf("capability protocol version %d, want %d", cap.ProtocolVersion, ProtocolVersion)
	}
	frame, err := json.Marshal(cap)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(frame, &round); err != nil {
		t.Fatal(err)
	}
	if v, ok := round["protocol_version"].(float64); !ok || int(v) != ProtocolVersion {
		t.Fatalf("capability wire frame missing protocol_version: %s", frame)
	}
}

func TestVersionedEnvelopeRoundTripAndRejection(t *testing.T) {
	env := Seal(Event{Type: EventError, Code: "x", Message: "y"})
	if env.ProtocolVersion != ProtocolVersion {
		t.Fatalf("seal produced version %d, want %d", env.ProtocolVersion, ProtocolVersion)
	}
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Versioned
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	frame, err := Unseal(back)
	if err != nil {
		t.Fatal(err)
	}
	evt, ok := frame.(map[string]interface{})
	if !ok || evt["type"] != string(EventError) {
		t.Fatalf("unsealed frame is not the original event: %#v", frame)
	}

	// A frame claiming a different protocol version must be refused, not
	// interpreted: a newer producer's shape may not pass this contract's
	// validation.
	bad := Versioned{ProtocolVersion: ProtocolVersion + 1, Frame: evt}
	if _, err := Unseal(bad); err == nil {
		t.Fatal("Unseal accepted a frame from an unsupported protocol version")
	}
}
