package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/adapter"
)

// The agent adapter must never pass a broker state through unqualified.
func TestNormalizeRelayStatusMapsAndRefuses(t *testing.T) {
	out, err := normalizeRelayStatus(map[string]interface{}{
		"status": "delivered", "request_id": "r1", "op_id": "op1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != string(adapter.StateAccepted) {
		t.Fatalf("status = %v, want accepted", out["status"])
	}
	if out["succeeded"] != false {
		t.Fatal("durable acceptance reported as verified success")
	}
	// Accepted is durable but not verified, so the agent should keep
	// polling for a verified applied outcome rather than treating it as
	// finished.
	if out["settled"] != false {
		t.Fatal("accepted state should not be settled")
	}

	applied, err := normalizeRelayStatus(map[string]interface{}{"status": "applied"})
	if err != nil {
		t.Fatal(err)
	}
	if applied["settled"] != true || applied["succeeded"] != true {
		t.Fatalf("applied state not settled/succeeded: %+v", applied)
	}

	if _, err := normalizeRelayStatus(map[string]interface{}{"status": "looks_fine"}); err == nil {
		t.Fatal("unqualified broker state was reported to the agent")
	}
	if _, err := normalizeRelayStatus(nil); err == nil {
		t.Fatal("unusable status payload was reported to the agent")
	}
}

// A status payload that smuggles a value field is scrubbed before it reaches
// the agent surface.
func TestNormalizeRelayStatusScrubsSensitiveFields(t *testing.T) {
	out, err := normalizeRelayStatus(map[string]interface{}{
		"status": "applied", "secret": "synthetic-value-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "synthetic-value-123") {
		t.Fatalf("status payload leaked a value: %s", raw)
	}
}

// Discovery advertises the closed vocabulary, the no-exposure guarantee, and
// the cancel surface the adapter actually implements.
func TestCapabilityDiscoveryIsComplete(t *testing.T) {
	cap := adapter.NewCapability(adapter.TransportMCP, "unverified", "external_tty", "reason", nil)
	if cap.CancelPath == "" || cap.RequestPath == "" || cap.StatusPath == "" {
		t.Fatalf("capability omits an invoke surface: %+v", cap)
	}
	if len(cap.States) != len(adapter.States()) {
		t.Fatalf("capability omits states: %v", cap.States)
	}
	if !cap.NeverExposesKey {
		t.Fatal("capability does not declare the no-exposure guarantee")
	}
}
