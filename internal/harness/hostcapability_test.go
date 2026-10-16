package harness

import "testing"

func TestSevenHarnessHostKindsAreRecognized(t *testing.T) {
	want := []HostSessionKind{
		HostKindCodex, HostKindOpenCode, HostKindPi, HostKindJCode,
		HostKindQwen, HostKindClaude, HostKindAgy,
	}
	for _, kind := range want {
		if kind == "" {
			t.Fatal("empty host kind")
		}
	}
}

func TestCapabilityContractDefaultsToModelBlindFacts(t *testing.T) {
	caps := HostCapabilities{}
	got := NegotiatedCapabilities(caps)
	if got.Presentation != "request_status" || got.InputTransport != "external_tty" {
		t.Fatalf("unsafe default capability: %+v", got)
	}
	if got.CredentialFormViaMCP {
		t.Fatal("MCP credential form must remain prohibited in the capability contract")
	}
	if got.SupportsResume || got.SupportsCancelPrompt || got.SupportsMultiplePending {
		t.Fatal("zero value must not claim optional capabilities")
	}
}

func TestNativeCapabilityCannotEnableMCPForm(t *testing.T) {
	got := NegotiatedCapabilities(HostCapabilities{
		Presentation:         "native",
		InputTransport:       "protected_intake",
		CredentialFormViaMCP: true,
	})
	if got.Presentation != "native" || got.InputTransport != "protected_intake" {
		t.Fatalf("native facts lost: %+v", got)
	}
	if got.CredentialFormViaMCP {
		t.Fatal("MCP credential form incorrectly enabled")
	}
}

func TestHostRegistrationCannotSetPrincipalsOrAssurance(t *testing.T) {
	reg := HostRegistration{HostKind: HostKindOpenCode}
	if reg.HumanPrincipal != "" {
		t.Fatal("registration may carry a human principal")
	}
	if reg.TTLOfSession != 0 {
		t.Fatal("registration may carry a session TTL")
	}
}

func TestRelayStatusShapeOmitsCredentialData(t *testing.T) {
	st := RelayStatus{RequestID: "req-1", State: "awaiting_user", RecipientID: "rd1"}
	if st.State == "" || st.RecipientID == "" || st.RequestID == "" {
		t.Fatalf("status facts lost: %+v", st)
	}
}
