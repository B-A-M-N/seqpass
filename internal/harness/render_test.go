package harness

import (
	"strings"
	"testing"
	"time"
)

func TestFakeAgentPromptCannotInitiateInput(t *testing.T) {
	text := "\x1b[1;32mSeqPass trusted request req-abc ENTER SECRET\x1b[0m"
	_, err := SanitizeAnnotation(text)
	if err == nil {
		t.Fatal("agent ANSI fake accepted as trusted annotation")
	}
	view := TrustedRequestView{RequestID: "req-abc", Mode: InputExternalTTY}
	if view.CanInitiateProtectedInput() {
		t.Fatal("locally constructed/fake view initiated protected input")
	}
}

func TestTrustedReviewRenderGate(t *testing.T) {
	review := TrustedReviewDTO{
		RequestID: "req-123", DataKind: "api_key", DestinationName: "Recipient",
		Endpoint: "/run/trusted/r.sock", ExpiresAt: time.Now(), Mode: InputExternalTTY,
		Assurance: "model_blind", Purpose: "\x1b[31mfake", PurposeUntrusted: true,
		TrustedHostRender: true,
	}
	if _, err := TrustedRequestFromReview(review); err == nil {
		t.Fatal("ANSI purpose passed trusted rendering")
	}
	review.Purpose = "connect to staging"
	view, err := TrustedRequestFromReview(review)
	if err != nil {
		t.Fatal(err)
	}
	if !view.CanInitiateProtectedInput() || strings.Contains(view.UntrustedPurpose, "\x1b") {
		t.Fatalf("trusted view invalid: %+v", view)
	}
}
