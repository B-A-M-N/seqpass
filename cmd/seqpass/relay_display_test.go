package main

import (
	"strings"
	"testing"
)

// F03: every persisted consumption configuration renders truthfully —
// unlimited reuse must never display as single-use.
func TestUsageLineTruthful(t *testing.T) {
	unlimited := usageLine(map[string]interface{}{
		"consumption": "reusable_until_expiry", "max_deliveries": float64(0),
	})
	if !strings.Contains(unlimited, "UNLIMITED") {
		t.Fatalf("unlimited reuse renders as %q", unlimited)
	}
	if strings.Contains(strings.ToLower(unlimited), "one delivery") {
		t.Fatalf("unlimited reuse described as single-use: %q", unlimited)
	}
	bounded := usageLine(map[string]interface{}{
		"consumption": "bounded_uses", "max_deliveries": float64(3),
	})
	if !strings.Contains(bounded, "3") {
		t.Fatalf("bounded renders as %q", bounded)
	}
	single := usageLine(map[string]interface{}{
		"consumption": "single_dispatch", "max_deliveries": float64(1),
	})
	if !strings.Contains(single, "ONE delivery") {
		t.Fatalf("single-use renders as %q", single)
	}
}

// F10: hostile agent text cannot reshape the trusted review layout.
func TestSanitizeUntrustedNeutralizesControls(t *testing.T) {
	evil := "ok\x1b[2J\x1b[1;1HOTHER\x07recipient\u202e reversed \n newline"
	got := sanitizeUntrusted(evil)
	for _, bad := range []string{"\x1b", "\x07", "\u202e", "\n"} {
		if strings.Contains(got, bad) {
			t.Fatalf("sanitized output retains control %q: %q", bad, got)
		}
	}
	if strings.Contains(got, "OTHER-RECEPIENT") {
		t.Fatal("sanitizer invented content")
	}
	if sanitizeUntrusted("") != "(no reason given)" {
		t.Fatal("empty purpose fallback changed")
	}
	if len([]rune(sanitizeUntrusted(strings.Repeat("x", 500)))) > 121 {
		t.Fatal("sanitized output unbounded")
	}
}
