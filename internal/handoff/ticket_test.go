package handoff

import (
	"strings"
	"testing"
	"time"
)

func TestNewTicketIsOpaqueAndTTLBounded(t *testing.T) {
	now := time.Now()
	ticket, err := New("op-1", "dest-1", 42, now, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if len(ticket.TicketID) < 40 || len(ticket.Nonce) < 40 || strings.ContainsAny(ticket.TicketID, "=+/ ") {
		t.Fatal("ticket locator is not opaque URL-safe random data")
	}
	if !ticket.IssuedAt.Equal(now) || !ticket.ExpiresAt.Equal(now.Add(DefaultTTL)) || ticket.State != "issued" {
		t.Fatal("ticket timing/state incorrect")
	}
	for _, ttl := range []time.Duration{MinTTL - time.Second, MaxTTL + time.Second} {
		if _, err := New("op", "dest", 42, now, ttl); err == nil {
			t.Fatalf("accepted out-of-range TTL %s", ttl)
		}
	}
}
