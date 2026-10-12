package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// Verification is the recorded independent postcondition check for one
// completed operation (SC-14, CV-01). Execution state and verification
// state are separate: an operation can be "completed" at the execution
// layer and "contradicted" at the outcome layer. States:
//
//   - satisfied: an independent observation confirmed the intended effect.
//   - contradicted: independent observation established the intended
//     effect did NOT occur (confirmed failure, not absence of evidence).
//   - inconclusive: no contradiction, but no independent observation
//     either (e.g. transfers, where the recipient ack proves durable
//     acceptance, not application).
//   - response_validated: read-only operation whose completion definition
//     is authorized execution + the closed result gate; there is no
//     external postcondition to observe, and this state never claims an
//     independent observation took place.
//   - check-failed: the observation mechanism itself errored — never
//     reported as proof of either success or failure.
type Verification struct {
	OpID            string
	OpType          string
	State           string // satisfied | contradicted | inconclusive | response_validated | check-failed
	Detail          string
	EvidenceRef     string
	EvidenceKind    string // assertion | receipt | recipient | external (G07)
	VerifierID      string
	VerifierVersion string
	ObservationID   string
	Checked         time.Time
}

// VerifyOutcome runs the operation's registered OutcomeVerifier against the
// durable receipt, or against the operation identity when reconciling an
// uncertain post-dispatch effect, and appends a typed observation (CV-03/F05).
// Only the submitting principal (or operator) may request it. The check
// result never rewrites the execution receipt.
//
// Completion requirements are explicit per driver (CV-02): transfers
// without a verifier report inconclusive (ack = acceptance, not
// application); ResponseValidated drivers report response_validated;
// ExternalPostcondition drivers without a verifier are a configuration
// error and fail closed instead of silently claiming success.
func (s *Service) VerifyOutcome(ctx context.Context, principal, opType, opID string, operator bool) (Verification, error) {
	if principal == "" {
		return Verification{}, errors.New("missing principal")
	}
	// Three distinct instants (G07): check start (when verification was
	// requested), observation time (when the external state was read —
	// taken from the verifier when trustworthy, else stamped after the
	// call returns), and record-commit time (stamped by the store).
	// History orders by observation time, so concurrent verifications
	// completing out of order still sequence correctly.
	verifyStart := time.Now()
	now := verifyStart
	// record persists the observation, then emits a distinctly-named audit
	// event (CV-03): one action for "an observation was recorded", with
	// the state in the outcome field — never a generic "verified" label
	// on inconclusive or failed observations.
	record := func(state, detail, evidenceRef, evidenceKind, verifierID, verifierVersion string, observedAt time.Time) (Verification, error) {
		attemptID, _ := s.db.LatestAttemptID(opID)
		if observedAt.IsZero() || observedAt.After(time.Now()) {
			observedAt = time.Now()
			now = observedAt
		} else {
			now = observedAt
		}
		if evidenceKind == "" {
			evidenceKind = metadata.EvidenceAssertion
		}
		sum := sha256.Sum256([]byte(evidenceKind + "\x00" + verifierID + "\x00" + verifierVersion + "\x00" + detail + "\x00" + evidenceRef))
		obs := &metadata.Observation{
			OperationID:     opID,
			AttemptID:       attemptID,
			VerifierID:      verifierID,
			VerifierVersion: verifierVersion,
			State:           state,
			ObservedAt:      observedAt,
			EvidenceDigest:  hex.EncodeToString(sum[:]),
			EvidenceKind:    evidenceKind,
			Source:          observationSource(verifierID),
			Details:         detail,
		}
		if err := s.db.RecordObservation(obs); err != nil {
			return Verification{}, fmt.Errorf("observation not durable: %w", err)
		}
		s.audit(opID, "outcome_observation_recorded", principal, opType, state)
		return Verification{
			OpID: opID, OpType: opType, State: state, Detail: detail,
			EvidenceRef: evidenceRef, EvidenceKind: evidenceKind, VerifierID: verifierID,
			VerifierVersion: verifierVersion, ObservationID: obs.ID, Checked: now,
		}, nil
	}
	var owner, status, opName string
	var input secureops.UseInput
	switch opType {
	case "transfer", "secret_transfer":
		tr, err := s.db.GetTransfer(opID)
		if err != nil || tr == nil {
			return Verification{}, errors.New("not found")
		}
		owner, status, opName = tr.RequestedBy, tr.Status, "transfer"
		input = secureops.UseInput{OpID: tr.ID, Principal: tr.RequestedBy}
	case "use", "secret_use":
		ur, err := s.db.GetUse(opID)
		if err != nil || ur == nil {
			return Verification{}, errors.New("not found")
		}
		owner, status, opName = ur.RequestedBy, ur.Status, ur.Operation
		input = secureops.UseInput{Operation: ur.Operation, Target: ur.Target, Params: ur.Params, OpID: ur.ID, Principal: ur.RequestedBy}
	default:
		return Verification{}, errors.New("unknown op type")
	}
	// The submitting principal may verify its own op; the trusted operator
	// (admin socket) may verify any op. Other principals learn nothing.
	if owner != principal && !operator {
		return Verification{}, errors.New("access denied")
	}
	uncertain := status == types.StatusUncertain
	if status != types.StatusCompleted && !uncertain {
		return Verification{}, fmt.Errorf("only completed or uncertain operations can be verified (status=%s)", status)
	}
	r, err := s.db.GetReceipt(opID)
	if err != nil {
		return Verification{}, errors.New("receipt not readable")
	}
	if r == nil && !uncertain {
		return Verification{}, errors.New("no durable receipt")
	}
	var result secureops.SafeResult
	if r != nil {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(r.Result), &data); err != nil {
			return Verification{}, errors.New("receipt not readable")
		}
		result = secureops.SafeResult{Summary: r.ResultType, Data: data}
	}

	// Transfers are not operation drivers, so they carry no CompletionMode:
	// the recipient ack proves durable acceptance, not application
	// (SC-06/SC-14). Inconclusive is the honest terminal state until a
	// recipient readback protocol promotes it (CV-10).
	if opType == "transfer" || opType == "secret_transfer" {
		if _, ok := secureops.LookupVerifier(opName); !ok {
			if uncertain {
				return Verification{}, errors.New("uncertain transfer requires an independent recipient verifier for reconciliation")
			}
			// No external observation exists here; the claim is the
			// broker's own contract reading, recorded as assertion (G07).
			return record(metadata.ObsInconclusive,
				"no independent verifier registered; recipient ack attests durable acceptance only",
				"", metadata.EvidenceAssertion, "none", "none", time.Time{})
		}
	}
	driver, derr := secureops.Lookup(opName)
	if derr == nil {
		switch driver.Completion() {
		case secureops.ResponseValidated:
			// No postcondition exists to observe; the closed result
			// gate at finalization IS the completion definition.
			// Reported as response_validated, never as an independent
			// external verification (CV-02).
			return record(metadata.ObsResponseValidated,
				"read-only operation: authorized execution + closed result gate is the completion definition; no postcondition to observe",
				"", metadata.EvidenceAssertion, "completion-contract", "v1", time.Time{})
		case secureops.ExternalPostcondition:
			// The verifier path below handles the observation.
			// FreezeRegistries should have refused startup when no
			// verifier exists; failing closed here too (CV-02).
			if _, ok := secureops.LookupVerifier(opName); !ok {
				return Verification{}, errors.New("operation requires an independent verifier: none registered")
			}
			// Verifier present: continue to the observation below.
		default:
			return Verification{}, errors.New("operation declares unknown completion mode")
		}
	}
	// Unknown operation names (e.g. legacy transfer pseudo-name with a
	// verifier registered, or unregistered drivers) fall through to the
	// verifier lookup: an explicit registration is still honored, and its
	// absence is inconclusive rather than success.
	v, ok := secureops.LookupVerifier(opName)
	if !ok {
		if uncertain {
			return Verification{}, errors.New("uncertain operation requires an independent verifier for reconciliation")
		}
		return record(metadata.ObsInconclusive,
			"no independent verifier registered for "+opName,
			"", metadata.EvidenceAssertion, "none", "none", time.Time{})
	}
	vid, vver, _ := secureops.LookupVerifierInfo(opName)
	out, err := v.Verify(ctx, input, result)
	if err != nil {
		detail := out.Detail
		if secureops.ValidateOutcomeDetail(detail) != nil {
			detail = "observation failed"
		}
		return record(metadata.ObsCheckFailed, detail, out.EvidenceRef, out.EvidenceKind, vid, vver, out.ObservedAt)
	}
	if err := secureops.ValidateOutcomeDetail(out.Detail); err != nil {
		return record(metadata.ObsCheckFailed, "verifier detail rejected by result contract", "", metadata.EvidenceAssertion, vid, vver, time.Time{})
	}
	if len(out.EvidenceRef) > 512 {
		return record(metadata.ObsCheckFailed, "verifier evidence ref oversized", "", metadata.EvidenceAssertion, vid, vver, time.Time{})
	}
	// Evidence kind travels with the observation (G07): assertion-only
	// claims stay visibly distinct from corroborated evidence.
	kind := out.EvidenceKind
	if kind == "" {
		kind = metadata.EvidenceAssertion
	}
	switch out.State {
	case secureops.OutcomeSatisfied:
		return record(metadata.ObsSatisfied, out.Detail, out.EvidenceRef, kind, vid, vver, out.ObservedAt)
	case secureops.OutcomeContradicted:
		return record(metadata.ObsContradicted, out.Detail, out.EvidenceRef, kind, vid, vver, out.ObservedAt)
	case secureops.OutcomeInconclusive:
		return record(metadata.ObsInconclusive, out.Detail, out.EvidenceRef, kind, vid, vver, out.ObservedAt)
	default:
		// A verifier that returns an empty or unknown state is a broken
		// observer, not a successful observation (CV-01 validation).
		return record(metadata.ObsCheckFailed, "verifier returned unknown outcome state", "", metadata.EvidenceAssertion, vid, vver, time.Time{})
	}
}

// observationSource names the independent system behind an observation so
// a reviewer can tell broker-contract claims apart from external checks.
func observationSource(verifierID string) string {
	switch verifierID {
	case "", "none":
		return "broker:completion-contract"
	case "completion-contract":
		return "broker:completion-contract"
	default:
		return "verifier:" + verifierID
	}
}
