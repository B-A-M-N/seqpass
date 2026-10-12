package secureops

import (
	"context"
	"errors"
	"sync"
	"time"
)

// OutcomeState is the closed outcome enumeration (CV-01). A Boolean cannot
// distinguish "independent observation disproved the intended effect" from
// "no independent observation exists": those are materially different
// claims, so they are different states.
//
//   - Satisfied: an observation source separate from the credentialed
//     execution driver confirmed the intended external effect.
//   - Contradicted: independent observation established the intended
//     effect did NOT occur (confirmed postcondition failure).
//   - Inconclusive: no contradiction, but no independent observation
//     either (observer unavailable, propagation window open, no verifier).
//
// CheckFailed is NOT a state: it means the observation mechanism itself
// failed and is reported through the error return, never as proof of
// either success or failure.
type OutcomeState string

const (
	OutcomeSatisfied    OutcomeState = "satisfied"
	OutcomeContradicted OutcomeState = "contradicted"
	OutcomeInconclusive OutcomeState = "inconclusive"
)

// Outcome is the independently observed postcondition of an executed
// operation. EvidenceRef is a stable pointer to the (redacted) evidence
// the verifier relied on; ObservedAt is when the observation was taken.
// Both survive into the durable observation record (CV-03/G07).
//
// EvidenceKind states what the digest covers (G07): "assertion" means
// only the verifier's identity + claim (no independently retained
// evidence — a reviewer takes the verifier's word); "receipt" points at
// the broker's durable receipt; "recipient" at a recipient readback;
// "external" at independently retained, redacted external evidence.
// Verifiers must use the strongest kind their observation supports.
//
// What counts as verifiable evidence: for satisfied, the externally
// readable state showing the intended effect (recipient store contents,
// remote object version/ETag, ledger entry) referenced so a reviewer can
// re-read it; for contradicted, the same showing its absence with the
// propagation window already elapsed. A bare "I checked" is assertion.
type Outcome struct {
	State        OutcomeState
	Detail       string
	EvidenceRef  string
	EvidenceKind string
	ObservedAt   time.Time
}

// OutcomeVerifier checks the external postcondition of an already-executed
// operation. It is deliberately separate from OperationDriver: the verifier
// must not use the operation's credential and must not repeat the side
// effect — it observes resulting state through an independently authorized
// path (SC-14).
//
// Per-operation contract (registered alongside each driver that needs one):
//   - success predicate: what external state counts as the intended effect
//   - observation source: where that state is read from (not the driver's
//     write response or the recipient ack alone)
//   - acceptable delay: how long propagation may take before
//     OutcomeInconclusive is reported (never reported as contradiction)
//
// Read-only operations need no verifier: correct authorization + valid
// response schema + delivery of the permitted information IS completion.
// Such operations declare CompletionMode ResponseValidated and register
// nothing.
type OutcomeVerifier interface {
	Verify(ctx context.Context, input UseInput, result SafeResult) (Outcome, error)
}

var (
	verifyMu        sync.RWMutex
	verifiers       = map[string]verifierReg{}
	verifiersFrozen bool
)

type verifierReg struct {
	v       OutcomeVerifier
	id      string
	version string
}

// RegisterVerifier attaches an independent postcondition check to an
// operation name. Called from init() alongside driver registration.
// Duplicate registration is rejected loudly (CV-07): silently replacing
// the active completion contract would let one build change what
// "verified" means without any error. Use RegisterVerifierEx to attach a
// stable identifier and implementation version so persisted observations
// stay interpretable after upgrades.
func RegisterVerifier(op string, v OutcomeVerifier) {
	if err := RegisterVerifierEx(op, op, "unversioned", v); err != nil {
		panic(err.Error())
	}
}

// RegisterVerifierEx is RegisterVerifier with an explicit stable identity.
// It returns an error instead of panicking so bootstrap validation
// (ValidateRegistries) can report every problem at once.
func RegisterVerifierEx(op, id, version string, v OutcomeVerifier) error {
	if op == "" || v == nil {
		return errors.New("invalid verifier registration")
	}
	if id == "" || version == "" {
		return errors.New("verifier requires stable id and version")
	}
	verifyMu.Lock()
	defer verifyMu.Unlock()
	if verifiersFrozen {
		return errors.New("verifier registration after freeze: " + op)
	}
	if _, dup := verifiers[op]; dup {
		return errors.New("duplicate verifier registration for " + op)
	}
	verifiers[op] = verifierReg{v: v, id: id, version: version}
	return nil
}

// LookupVerifier returns the verifier for op, or false when the operation's
// completion definition needs no independent postcondition check
// (ResponseValidated operations) or none has been implemented yet.
func LookupVerifier(op string) (OutcomeVerifier, bool) {
	verifyMu.RLock()
	defer verifyMu.RUnlock()
	r, ok := verifiers[op]
	if !ok {
		return nil, false
	}
	return r.v, true
}

// LookupVerifierInfo returns the stable identity of the active verifier.
func LookupVerifierInfo(op string) (id, version string, ok bool) {
	verifyMu.RLock()
	defer verifyMu.RUnlock()
	r, found := verifiers[op]
	if !found {
		return "", "", false
	}
	return r.id, r.version, true
}

// ValidateOutcomeDetail keeps verifier observations inside the same closed
// contract as results: bounded, scalar, safe for receipts and audit logs.
func ValidateOutcomeDetail(detail string) error {
	if len(detail) > maxStringLen {
		return errors.New("outcome detail too large")
	}
	for _, r := range detail {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			return errors.New("outcome detail has control characters")
		}
	}
	return nil
}
