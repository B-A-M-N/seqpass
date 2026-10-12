package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

func testEngine(t *testing.T, policies ...*types.Policy) *Engine {
	t.Helper()
	db, err := metadata.NewDB(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range policies {
		if err := db.CreatePolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	return NewEngine(db)
}

func pol(priority int, rules ...types.PolicyRule) *types.Policy {
	return &types.Policy{Name: "p", Priority: priority, Enabled: true, Rules: rules}
}

var (
	broadPreauth = types.PolicyRule{Principal: "uid:1000", SecretRefs: []string{"cert1"},
		Ops: []string{"transfer"}, DestIDs: []string{"*"}, Resources: []string{"*"}, NoApproval: true}
	narrowReview = types.PolicyRule{Principal: "uid:1000", SecretRefs: []string{"cert1"},
		Ops: []string{"transfer"}, DestIDs: []string{"d1"}, Resources: []string{"*"}}
)

func transferReq() Request {
	return Request{Principal: "uid:1000", Op: "transfer", SecretRef: "cert1",
		DestID: "d1", ExpiresAt: time.Now().Add(time.Hour)}
}

// P2-9: conservative approval combination. A broad preauthorization grant
// overlapping a narrower mandatory-review rule NEVER preauthorizes —
// regardless of rule order within a policy or priority order across
// policies. The same configuration always yields the same approval mode.
func TestOverlappingRulesForceApproval(t *testing.T) {
	cases := map[string][]*types.Policy{
		"broad rule first":  {pol(10, broadPreauth, narrowReview)},
		"narrow rule first": {pol(10, narrowReview, broadPreauth)},
		"broad higher priority": {
			pol(100, broadPreauth),
			pol(1, narrowReview),
		},
		"narrow higher priority": {
			pol(100, narrowReview),
			pol(1, broadPreauth),
		},
	}
	for name, policies := range cases {
		e := testEngine(t, policies...)
		dec, err := e.Evaluate(transferReq())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !dec.Allow {
			t.Fatalf("%s: overlapping rules denied (want allow + human review)", name)
		}
		if !dec.RequiresApproval {
			t.Fatalf("%s: broad grant bypassed mandatory review (order decided approval)", name)
		}
	}
}

// Unanimous opt-in still preauthorizes: every applicable rule agrees.
func TestUnanimousPreauthStillPreauthorizes(t *testing.T) {
	other := broadPreauth
	other.DestIDs = []string{"d1"}
	e := testEngine(t, pol(10, broadPreauth, other))
	dec, err := e.Evaluate(transferReq())
	if err != nil || !dec.Allow || dec.RequiresApproval {
		t.Fatalf("unanimous preauth denied or gated: %+v %v", dec, err)
	}
}

// A lone mandatory-review rule requires approval (no behavior change).
func TestSingleReviewRuleRequiresApproval(t *testing.T) {
	e := testEngine(t, pol(10, narrowReview))
	dec, err := e.Evaluate(transferReq())
	if err != nil || !dec.Allow || !dec.RequiresApproval {
		t.Fatalf("single review rule: %+v %v", dec, err)
	}
}

// A rule that does not match the destination is not applicable and does
// not drag the decision toward review.
func TestNonApplicableRuleIgnored(t *testing.T) {
	unrelated := narrowReview
	unrelated.DestIDs = []string{"elsewhere"}
	e := testEngine(t, pol(10, broadPreauth, unrelated))
	dec, err := e.Evaluate(transferReq())
	if err != nil || !dec.Allow || dec.RequiresApproval {
		t.Fatalf("non-applicable rule affected approval: %+v %v", dec, err)
	}
}
