package hostnative

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
)

func TestProtectedInputNoticeWireContract(t *testing.T) {
	notice := harness.ProtectedInputNotice{
		Version:          harness.ProtectedInputNoticeSchemaVersion,
		RequestID:        "req-contract",
		RequestRev:       3,
		HostSessionID:    "host-session",
		DataKind:         "api_key",
		RecipientID:      "registered-service",
		RecipientLabel:   "Registered Recipient",
		Consumption:      "single_dispatch",
		ExpiresAt:        time.Now().Add(time.Minute).UTC(),
		Mode:             harness.InputExternalTTY,
		Assurance:        "model_blind",
		UntrustedPurpose: "configure integration",
	}
	raw, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	var decoded harness.ProtectedInputNotice
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("wire round-trip failed: %v", err)
	}
	if decoded.UntrustedPurpose != notice.UntrustedPurpose {
		t.Fatal("untrusted purpose was not preserved")
	}
	if decoded.RecipientLabel != notice.RecipientLabel || decoded.Consumption != notice.Consumption {
		t.Fatal("trusted review facts changed")
	}
}
