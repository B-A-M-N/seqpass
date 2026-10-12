package metadata

import (
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

// SC-01: the audit's delimiter counterexample must collide no more.
// {"a":"b;c=d"} and {"a":"b","c":"d"} encoded identically under the old
// key=value; scheme; the length-framed digest must separate them.
func TestUseOpHashDelimiterAttack(t *testing.T) {
	res := types.ResourceDescriptor{Kind: "k", Identifier: "id"}
	a := UseOpHash("p", "s", "op", "t", map[string]string{"a": "b;c=d"}, res)
	b := UseOpHash("p", "s", "op", "t", map[string]string{"a": "b", "c": "d"}, res)
	if a == b {
		t.Fatal("delimiter collision: distinct param maps share an op hash (SC-01)")
	}
}

// SC-01: every execution-affecting field changes the approval digest,
// including the component selector.
func TestOpHashBindsEveryField(t *testing.T) {
	res := types.ResourceDescriptor{Kind: "k", Identifier: "id"}
	params := map[string]string{"repo": "o/r"}
	base := UseOpHash("p", "s", "op", "t", params, res)
	mutations := []struct {
		name string
		hash string
	}{
		{"principal", UseOpHash("q", "s", "op", "t", params, res)},
		{"secret", UseOpHash("p", "s2", "op", "t", params, res)},
		{"operation", UseOpHash("p", "s", "op2", "t", params, res)},
		{"target", UseOpHash("p", "s", "op", "t2", params, res)},
		{"params", UseOpHash("p", "s", "op", "t", map[string]string{"repo": "o/r2"}, res)},
		{"resource", UseOpHash("p", "s", "op", "t", params, types.ResourceDescriptor{Kind: "k", Identifier: "id2"})},
	}
	for _, m := range mutations {
		if m.hash == base {
			t.Fatalf("field %q not bound in op hash (SC-01)", m.name)
		}
	}
	tb := TransferOpHash("p", "s", "d", "")
	for _, pr := range []string{"component:a", "component:b", "component:a/b"} {
		if h := TransferOpHash("p", "s", "d", pr); h == tb {
			t.Fatalf("payload ref %q not bound in transfer hash (SC-01)", pr)
		}
	}
}

// SC-01: canonical encoding is order-independent, injection-proof across
// hostile inputs (empty, unicode, quotes, separators), and length-framing
// makes part-boundary shifts collide-free.
func TestCanonicalEncodingProperties(t *testing.T) {
	inputs := []map[string]string{
		{},
		{"": ""},
		{"a": "b;c=d", "e": "f\"g\\h"},
		{" devise": "ünïcodé☃", "k\x00": "v\n\t"},
		{"x": strings.Repeat("y", 1000)},
		{";": "=", "=": ";"},
	}
	seen := map[string]string{}
	for i, in := range inputs {
		enc1 := CanonicalParamsJSON(in)
		// Rebuild the map in a different insertion order; JSON must match.
		dup := map[string]string{}
		keys := []string{}
		for k := range in {
			keys = append(keys, k)
		}
		for j := len(keys) - 1; j >= 0; j-- {
			dup[keys[j]] = in[keys[j]]
		}
		if enc2 := CanonicalParamsJSON(dup); enc1 != enc2 {
			t.Fatalf("case %d: encoding depends on map order", i)
		}
		h := CanonicalOpHash("v1", "use", enc1)
		if prev, ok := seen[h]; ok && prev != enc1 {
			t.Fatalf("case %d: hash collision over distinct encodings", i)
		}
		seen[h] = enc1
	}
	// Part-boundary shift: {"ab","c"} vs {"a","bc"} must differ.
	if CanonicalOpHash("ab", "c") == CanonicalOpHash("a", "bc") {
		t.Fatal("length framing broken: part-boundary collision (SC-01)")
	}
}
