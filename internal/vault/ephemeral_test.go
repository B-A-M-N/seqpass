package vault

import (
	"strings"
	"testing"
	"time"
)

// QR-01: the production spool holds bytes under lifetime + holders,
// fails unreserved reads, and zeroes on teardown.
func TestEphemeralReserveReadRelease(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.Store("k", []byte("s3cret"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// No reservation, no read — even with the exact key.
	if _, err := e.GetFor("k", "op-1"); err == nil {
		t.Fatal("unreserved read succeeded")
	}
	if err := e.Reserve("k", "op-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := e.GetFor("k", "op-1")
	if err != nil || string(raw) != "s3cret" {
		t.Fatalf("reserved read: %q %v", raw, err)
	}
	// Foreign operation cannot piggyback the reservation.
	if _, err := e.GetFor("k", "op-2"); err == nil {
		t.Fatal("foreign op read succeeded")
	}
	e.Release("k", "op-1")
	if e.Live("k") || e.HasBacking("k") {
		t.Fatal("single-use payload remained after its last holder released")
	}
}

func TestEphemeralRetainedAcrossOperationHolders(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.StoreRetained("reusable", []byte("grant-value"), time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"op-1", "op-2"} {
		if err := e.Reserve("reusable", op, time.Now()); err != nil {
			t.Fatalf("reserve %s: %v", op, err)
		}
		raw, err := e.GetFor("reusable", op)
		if err != nil || string(raw) != "grant-value" {
			t.Fatalf("read %s: %q %v", op, raw, err)
		}
		e.Release("reusable", op)
		if !e.Live("reusable") || !e.HasBacking("reusable") {
			t.Fatalf("payload cleared after releasing %s", op)
		}
	}
	e.Revoke("reusable")
	if e.Live("reusable") || e.HasBacking("reusable") {
		t.Fatal("revoked retained payload remained")
	}
}

func TestEphemeralRestageRefused(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.Store("k", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Rotation happens through a new relay, never by swapping bytes
	// under outstanding state.
	if err := e.Store("k", []byte("b"), time.Minute); err == nil {
		t.Fatal("live key re-staged")
	}
	if err := e.Store("k", nil, time.Minute); err == nil {
		t.Fatal("empty payload staged")
	}
	big := make([]byte, MaxEphemeralBytes+1)
	if err := e.Store("k2", big, time.Minute); err == nil {
		t.Fatal("oversize payload staged")
	}
	if err := e.Store("k3", []byte("x"), 0); err == nil {
		t.Fatal("zero TTL staged")
	}
}

func TestEphemeralExpiryAndSweep(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.Store("k", []byte("v"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := e.Reserve("k", "op-1", future); err == nil {
		t.Fatal("reservation past deadline succeeded")
	}
	// The failed reserve marked the entry; sweep now reaps its backing bytes.
	if n := e.Sweep(future); n != 1 {
		t.Fatalf("swept = %d, want 1 (marked entry reaped)", n)
	}
	if e.Live("k") {
		t.Fatal("expired entry still live")
	}
	// F02: holder count and backing-buffer zeroization, not just Live().
	if e.Holders("k") != 0 {
		t.Fatal("expired entry holders retained after sweep")
	}
	if e.HasBacking("k") {
		t.Fatal("expired entry backing bytes retained after sweep")
	}
	// A quiet expiry (no reserve attempt) is reaped by the sweep.
	if err := e.Store("q", []byte("v"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := e.Sweep(future); n != 1 {
		t.Fatalf("swept = %d, want 1", n)
	}
	if e.Live("q") {
		t.Fatal("swept entry still live")
	}
}

func TestEphemeralRevokeWithHolders(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.Store("k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Reserve("k", "op-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Revocation fails NEW reads at once; the in-flight holder keeps
	// its already-resolved copy (retraction is impossible), and the
	// backing bytes zero on last release.
	e.Revoke("k")
	if _, err := e.GetFor("k", "op-1"); err == nil {
		t.Fatal("read after revoke succeeded")
	}
	if err := e.Reserve("k", "op-2", time.Now()); err == nil {
		t.Fatal("reservation after revoke succeeded")
	}
	e.Release("k", "op-1")
	if e.Live("k") {
		t.Fatal("revoked entry still live after last release")
	}
}

func TestEphemeralDropAll(t *testing.T) {
	e := NewEphemeralStore()
	if err := e.Store("a", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Store("b", []byte("2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	e.DropAll()
	if e.Live("a") || e.Live("b") {
		t.Fatal("payloads survive DropAll")
	}
	if _, err := e.GetFor("a", "op-1"); err == nil {
		t.Fatal("read after DropAll succeeded")
	}
}

func TestEphemeralUnknownKey(t *testing.T) {
	e := NewEphemeralStore()
	if _, err := e.GetFor("nope", "op-1"); err == nil {
		t.Fatal("unknown key read")
	}
	if e.Delete("nope") {
		t.Fatal("delete reported phantom bytes")
	}
	if strings.Contains(ErrNotFound.Error(), "s3cret") {
		t.Fatal("error smuggles fixture")
	}
}
