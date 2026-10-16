package harness

import (
	"testing"
	"time"
)

func TestProtectedInputNoticeValidation(t *testing.T) {
	valid := ProtectedInputNotice{
		Version:          ProtectedInputNoticeSchemaVersion,
		RequestID:        "req-1",
		RequestRev:       2,
		HostSessionID:    "host-1",
		DataKind:         "api_key",
		RecipientID:      "rd1",
		RecipientLabel:   "staging runner",
		Consumption:      "single_dispatch",
		ExpiresAt:        time.Now().Add(time.Minute),
		Mode:             InputExternalTTY,
		Assurance:        "model_blind",
		UntrustedPurpose: "configure integration",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid notice rejected: %v", err)
	}
	if valid.Version != 1 {
		t.Fatalf("schema version changed: %d", valid.Version)
	}
	if valid.UntrustedPurpose == "" {
		t.Fatal("untrusted purpose lost")
	}
}

func TestProtectedInputNoticeFailsClosed(t *testing.T) {
	base := ProtectedInputNotice{
		Version:        ProtectedInputNoticeSchemaVersion,
		RequestID:      "req-1",
		RequestRev:     2,
		HostSessionID:  "host-1",
		DataKind:       "api_key",
		RecipientID:    "rd1",
		RecipientLabel: "staging runner",
		Consumption:    "single_dispatch",
		ExpiresAt:      time.Now().Add(time.Minute),
		Mode:           InputExternalTTY,
		Assurance:      "model_blind",
	}
	cases := map[string]func(*ProtectedInputNotice){
		"version":     func(n *ProtectedInputNotice) { n.Version++ },
		"request":     func(n *ProtectedInputNotice) { n.RequestID = "" },
		"revision":    func(n *ProtectedInputNotice) { n.RequestRev = 0 },
		"session":     func(n *ProtectedInputNotice) { n.HostSessionID = "" },
		"data-kind":   func(n *ProtectedInputNotice) { n.DataKind = "" },
		"recipient":   func(n *ProtectedInputNotice) { n.RecipientID = "" },
		"label":       func(n *ProtectedInputNotice) { n.RecipientLabel = "" },
		"consumption": func(n *ProtectedInputNotice) { n.Consumption = "" },
		"expiry":      func(n *ProtectedInputNotice) { n.ExpiresAt = time.Time{} },
		"mode":        func(n *ProtectedInputNotice) { n.Mode = "" },
		"assurance":   func(n *ProtectedInputNotice) { n.Assurance = "" },
	}
	for name, mutate := range cases {
		n := base
		mutate(&n)
		if err := n.Validate(); err == nil {
			t.Fatalf("%s mutation accepted", name)
		}
	}
}
