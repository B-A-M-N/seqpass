package main

import "testing"

// The doctor must not read a missing or unexpected assurance field as proof of
// a boundary. Absence of evidence is not evidence.
func TestHealthVerifiedRequiresTheExactLabel(t *testing.T) {
	cases := []struct {
		name string
		data interface{}
		want bool
	}{
		{"verified", map[string]interface{}{"assurance": "verified"}, true},
		{"unverified", map[string]interface{}{"assurance": "unverified"}, false},
		{"provisional", map[string]interface{}{"assurance": "provisional"}, false},
		{"empty label", map[string]interface{}{"assurance": ""}, false},
		{"missing field", map[string]interface{}{"assurance_mode": "isolated"}, false},
		{"wrong type", map[string]interface{}{"assurance": true}, false},
		{"not a map", "verified", false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := healthVerified(tc.data); got != tc.want {
			t.Errorf("%s: healthVerified(%v) = %v, want %v", tc.name, tc.data, got, tc.want)
		}
	}
}

func TestJoinUIDsRendersFlagSyntax(t *testing.T) {
	if got := joinUIDs(nil); got != "" {
		t.Fatalf("empty list = %q, want empty", got)
	}
	if got := joinUIDs([]uint32{2001, 2002, 7}); got != "2001,2002,7" {
		t.Fatalf("joinUIDs = %q", got)
	}
	// The rendered form must round-trip through the single shared parser,
	// otherwise the printed "next step" command would not run.
	parsed, err := parseUIDs(joinUIDs([]uint32{2001, 2002, 7}))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 3 || parsed[0] != 2001 || parsed[2] != 7 {
		t.Fatalf("round trip = %v", parsed)
	}
}
