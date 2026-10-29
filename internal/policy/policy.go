package policy

import (
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

// Decision is the outcome of an authorization check.
type Decision struct {
	Allow            bool
	RequiresApproval bool
	AuthEpoch        int64
	Reason           string
}

// Request is a validated broker-side authorization request.
// Principal must be broker-authenticated (peercred), never agent-supplied.
// Destinationless declares whether the operation definition takes no
// destination; empty DestID is valid only then.
type Request struct {
	Principal       string
	Op              string // operation name, e.g. "github.get_repo", "transfer"
	SecretRef       string
	DestID          string
	Destinationless bool
	Resource        types.ResourceDescriptor
	ExpiresAt       time.Time
}

// ValidateRule is the single policy-schema validator (SC-10): it delegates
// to types.ValidateRule so creation, loading, and evaluation share one
// definition of a legal rule.
func ValidateRule(r types.PolicyRule) error {
	return types.ValidateRule(r)
}

type Engine struct {
	db *metadata.DB
}

func NewEngine(db *metadata.DB) *Engine {
	return &Engine{db: db}
}

// Evaluate applies default-deny authorization against the current epoch.
//   - No matching enabled allow rule => denial.
//   - Destination-scoped rules never match an empty destination unless the
//     operation is explicitly destinationless.
//   - DB errors => denial (never fail open).
//   - Approval-mode contract (P2-9, conservative combination): the operation
//     is allowed when ANY enabled rule matches, but it preauthorizes only
//     when EVERY matching rule opts into NoApproval. Any applicable rule
//     that does not opt in forces human approval. Rule order and priority
//     never decide the approval mode, so a broad preauthorization grant
//     cannot silently bypass a narrower mandatory-review rule, and the same
//     policy configuration always produces the same approval behavior.
func (e *Engine) Evaluate(req Request) (Decision, error) {
	epoch, err := e.db.CurrentEpoch()
	if err != nil {
		return Decision{Allow: false, Reason: "policy store error"},
			fmt.Errorf("policy lookup failed: %w", err)
	}
	if req.Principal == "" {
		return Decision{Allow: false, AuthEpoch: epoch, Reason: "missing principal"}, nil
	}
	if req.Op == "" {
		return Decision{Allow: false, AuthEpoch: epoch, Reason: "unknown operation"}, nil
	}
	if req.SecretRef == "" {
		return Decision{Allow: false, AuthEpoch: epoch, Reason: "missing secret ref"}, nil
	}
	if !req.ExpiresAt.IsZero() && time.Now().After(req.ExpiresAt) {
		return Decision{Allow: false, AuthEpoch: epoch, Reason: "expired"}, nil
	}

	policies, err := e.db.ListPolicies()
	if err != nil {
		return Decision{Allow: false, Reason: "policy store error"},
			fmt.Errorf("policy lookup failed: %w", err)
	}

	matched := false
	requireApproval := false
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if !matchField(r.Principal, req.Principal) {
				continue
			}
			if !matchList(r.SecretRefs, req.SecretRef) {
				continue
			}
			// Discover asks only whether ANY access to the ref exists;
			// op/destination/resource scoping is enforced at submit and admission.
			if req.Op != "discover" {
				if !matchList(r.Ops, req.Op) {
					continue
				}
				if !matchDest(r.DestIDs, req.DestID, req.Destinationless) {
					continue
				}
				if !matchResource(r.Resources, req.Resource) {
					continue
				}
			}
			matched = true
			if !r.NoApproval {
				requireApproval = true
			}
		}
	}
	if !matched {
		return Decision{Allow: false, AuthEpoch: epoch, Reason: "default deny: no matching allow rule"}, nil
	}
	return Decision{Allow: true, RequiresApproval: requireApproval, AuthEpoch: epoch, Reason: "allow"}, nil
}

// MatchingRules returns the enabled allow-rules matching principal +
// secret ref + operation, ignoring destination and resource scope (G06).
// Capability discovery uses these to separate catalog-visible operations
// from actually authorized ones: a rule scoped to one repo makes the op
// visible but "scoped", never falsely "ready" for every resource.
func (e *Engine) MatchingRules(principal, secretRef, op string) ([]types.PolicyRule, error) {
	policies, err := e.db.ListPolicies()
	if err != nil {
		return nil, err
	}
	var out []types.PolicyRule
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		for _, r := range p.Rules {
			if !matchField(r.Principal, principal) {
				continue
			}
			if !matchList(r.SecretRefs, secretRef) {
				continue
			}
			if !matchList(r.Ops, op) {
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// RuleDestOpen reports whether a rule leaves destination choice open
// (empty or wildcard). Shared with capability discovery so the catalog
// cannot maintain an independent approximation of policy semantics.
func RuleDestOpen(r types.PolicyRule) bool {
	if len(r.DestIDs) == 0 {
		return true
	}
	for _, d := range r.DestIDs {
		if d == "*" {
			return true
		}
	}
	return false
}

// RuleCoversResource reports whether a rule broadly authorizes a
// resource kind for discovery: explicit "*" or "kind/*" only. An empty
// resource list authorizes NOTHING for a resource-bearing operation —
// matchResource denies it at admission, so discovery must agree.
func RuleCoversResource(r types.PolicyRule, kind string) bool {
	if kind == "" {
		return true
	}
	for _, res := range r.Resources {
		// Both wildcard spellings: "kind:*" (creatable) and "kind/*"
		// (accepted by the matcher for legacy rows).
		if res == "*" || res == kind+"/*" || res == kind+":*" {
			return true
		}
	}
	return false
}

// matchField and matchList never treat empty as wildcard (SC-10): creation
// requires explicit values, and loaded legacy rules are revalidated, so an
// empty pattern reaching the engine is malformed and must deny.
func matchField(pattern, v string) bool {
	return pattern != "" && (pattern == "*" || pattern == v)
}

func matchList(list []string, v string) bool {
	for _, s := range list {
		if s == "*" || (s != "" && s == v) {
			return true
		}
	}
	return false
}

// matchResource binds credential permission to the exact typed resource
// (C10/SC-10). Entries are "kind:identifier", "kind/*", or "*". Bare
// identifiers never match: a scope for one resource kind must not silently
// open another. Resource-less requests (e.g. transfers) skip this check.
func matchResource(ruleRes []string, req types.ResourceDescriptor) bool {
	if req.Identifier == "" {
		return true
	}
	if len(ruleRes) == 0 {
		return false
	}
	for _, r := range ruleRes {
		if r == "*" || r == req.Kind+"/*" {
			return true
		}
		if kind, id, ok := types.ParseResource(r); ok && kind == req.Kind && (id == "*" || id == req.Identifier) {
			return true
		}
	}
	return false
}

// matchDest enforces destination constraints strictly: an empty request
// destination matches only operations explicitly declared destinationless,
// and then only against rules that do not scope concrete destinations
// (empty list or wildcard). Destination-scoped rules never match empty.
func matchDest(ruleDests []string, reqDest string, destinationless bool) bool {
	if reqDest == "" {
		if !destinationless {
			return false
		}
		if len(ruleDests) == 0 {
			return true
		}
		for _, d := range ruleDests {
			if d == "*" {
				return true
			}
		}
		return false
	}
	return matchList(ruleDests, reqDest)
}
