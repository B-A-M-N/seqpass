package main

import "testing"

// Objective 8: UID parsing fails closed. A malformed token must never be
// silently dropped, because dropping an --agent-uid would widen who may
// reach the broker.
func TestParseUIDsFailsClosed(t *testing.T) {
	for _, bad := range []string{"abc", "1001,abc", "1001,,1002", "1001,", "1.5", "-3"} {
		if _, err := parseUIDs(bad); err == nil {
			t.Fatalf("parseUIDs(%q) accepted malformed input", bad)
		}
	}
	// Duplicates are ambiguous and refused rather than collapsed.
	if _, err := parseUIDs("1001,1001"); err == nil {
		t.Fatal("parseUIDs accepted a duplicate UID")
	}
	// A well-formed list parses in order.
	got, err := parseUIDs("1001, 1002,1003")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{1001, 1002, 1003}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
	// Empty input is "unset", not an error.
	if out, err := parseUIDs("   "); err != nil || out != nil {
		t.Fatalf("empty UID list = %v, %v; want nil, nil", out, err)
	}
}
