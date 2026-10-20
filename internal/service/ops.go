package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/policy"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// resolveSource maps a secret ref to its credential source.
// Production refs carry an AegisKeys binding. Relay refs (relay:<id>)
// resolve to the ephemeral relay grant in EVERY vault mode (QR-01): the
// grant — not a standing policy rule or vault type — authorizes the
// handoff, and unbound legacy refs still fail closed outside
// memory-test (SC-08).
func (s *Service) resolveSource(secretRef string) (types.SecretSource, error) {
	if _, ok := relayIDOf(secretRef); ok {
		return types.SecretSource{Kind: types.SourceEphemeral, Ref: secretRef}, nil
	}
	sr, err := s.db.GetSecretRef(secretRef)
	if err != nil {
		return types.SecretSource{}, err
	}
	if sr == nil {
		return types.SecretSource{}, fmt.Errorf("unknown secret ref")
	}
	// Provisioned-reference lifecycle gate (P0-A/P0-3): terminal or
	// conflicted references never resolve. Identity conflicts in
	// particular block ALL subsequent execution until explicit operator
	// reconciliation, so an existing operation approval cannot dispatch
	// against a drifted credential.
	switch sr.ReconcileStatus {
	case types.ProvisionReconcileIdentityConflict:
		return types.SecretSource{}, fmt.Errorf("credential identity conflict: provider identity diverges from the pinned record/binding identity; execution blocked pending operator reconciliation")
	case types.ProvisionReconcileConflict:
		return types.SecretSource{}, fmt.Errorf("credential provisioning conflict: operator reconciliation required")
	case types.ProvisionReconcileConsumed:
		return types.SecretSource{}, fmt.Errorf("credential revoked")
	case types.ProvisionReconcileFailed:
		return types.SecretSource{}, fmt.Errorf("credential provisioning failed")
	}
	if sr.Binding != "" {
		src := types.SecretSource{Kind: types.SourceAegisKeys, Binding: sr.Binding}
		// P0-3 rebind protection: provisioned refs carry their stable
		// provider identity on EVERY authorized resolve, so a later
		// rebind of the binding name cannot silently redirect an
		// approved operation (the provider denies generically on pin
		// mismatch). Non-provisioned refs keep unpinned resolves.
		src.BindingID = sr.BindingID
		src.RecordID = sr.RecordID
		src.UseOnce = sr.UseOnce
		return src, nil
	}
	if s.cfg.VaultType != "memory-test" && s.cfg.VaultType != "memory" {
		return types.SecretSource{}, fmt.Errorf("ephemeral intake is development-only (memory-test); production refs require an AegisKeys binding")
	}
	return types.SecretSource{Kind: types.SourceEphemeral, Ref: secretRef}, nil
}

// validateDriverParams rejects unknown operations, unknown param keys and
// driver-invalid values before persistence, so approval sees the exact
// resource semantics that will execute (F07).
func validateDriverParams(op string, params map[string]string) (secureops.OperationDriver, error) {
	driver, err := secureops.Lookup(op)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, k := range driver.AllowedParams() {
		allowed[k] = true
	}
	for k := range params {
		if !allowed[k] {
			return nil, fmt.Errorf("unknown parameter %q for %s", k, op)
		}
	}
	if err := driver.Validate(secureops.UseInput{Operation: op, Params: params}); err != nil {
		return nil, err
	}
	return driver, nil
}

// SubmitUse validates + authorizes, then creates requested/pending_approval.
// Principal must be broker-authenticated. Never auto-marks authorized.
func (s *Service) SubmitUse(principal string, req *types.UseRequest) (string, error) {
	if principal == "" {
		return "", errors.New("missing principal")
	}
	if req.Operation == "" || req.SecretRef == "" {
		return "", errors.New("unknown operation or secret ref")
	}
	// Typed validation first: unknown ops/params never reach the policy
	// engine or the approval queue.
	driver, err := validateDriverParams(req.Operation, req.Params)
	if err != nil {
		s.audit("", "secret_use_denied", principal, req.Target, "invalid-operation")
		return "", err
	}
	src, err := s.resolveSource(req.SecretRef)
	if err != nil {
		s.audit(req.ID, "secret_use_denied", principal, req.Target, "unknown-secret")
		return "", err
	}
	req.Source = src

	dec, err := s.policy.Evaluate(policy.Request{
		Principal:       principal,
		Op:              req.Operation,
		SecretRef:       req.SecretRef,
		DestID:          req.Target,
		Destinationless: !driver.RequiresDestination(),
		Resource:        driver.Resource(req.Params),
		ExpiresAt:       req.ExpiresAt,
	})
	if err != nil {
		return "", err
	}
	if !dec.Allow {
		s.audit("", "secret_use_denied", principal, req.Target, "deny")
		return "", errors.New("access denied")
	}

	// Resolve the effective destination; unknown IDs denied, digest bound.
	var destDigest string
	var destRev int
	if req.Target != "" {
		dest, err := s.db.GetDestination(req.Target)
		if err != nil {
			return "", err
		}
		if dest == nil {
			return "", errors.New("unknown destination")
		}
		destDigest = metadata.DestDigest(dest)
		destRev = dest.Revision
	} else if driver.RequiresDestination() {
		return "", errors.New("destination required")
	}

	req.RequestedBy = principal
	req.CreatedAt = time.Now()
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(s.opTTL())
	}
	req.OpHash = metadata.UseOpHash(principal, req.SecretRef, req.Operation, req.Target, req.Params, driver.Resource(req.Params))
	req.AuthEpoch = dec.AuthEpoch
	req.DestDigest = destDigest
	req.DestRevision = destRev
	// Approval mode (SC-05): the policy engine is the single authority.
	// An explicit NoApproval rule preauthorizes (status authorized, consumed
	// by the worker through the normal claim path). Anything else needs a
	// human; a destination with RequiresApproval set forces human approval
	// even under a preauthorizing rule (escalation only).
	req.Status = types.StatusRequested
	destNeedsHuman := false
	if req.Target != "" {
		if dest, _ := s.db.GetDestination(req.Target); dest != nil {
			destNeedsHuman = dest.RequiresApproval
			// Destination AllowedOps is a compatibility restriction
			// enforced at admission (SC-05): when non-empty, the
			// operation must be listed. Empty means no dest-level
			// restriction; the policy engine remains authoritative.
			if len(dest.AllowedOps) > 0 && !containsOp(dest.AllowedOps, req.Operation) {
				s.audit("", "secret_use_denied", principal, req.Target, "dest-op-denied")
				return "", errors.New("operation not permitted for destination")
			}
		}
	}
	if !dec.RequiresApproval && !destNeedsHuman {
		req.Status = types.StatusAuthorized
		req.ApprovedBy = "policy:preauthorized"
	} else if destNeedsHuman {
		req.Status = types.StatusPendingApproval
	}

	if err := s.db.CreateUse(req); err != nil {
		return "", err
	}
	s.audit(req.ID, "secret_use_requested", principal, req.Target, req.Status)
	return req.ID, nil
}

// SubmitTransfer validates + authorizes a blind transfer request.
func (s *Service) SubmitTransfer(principal string, req *types.TransferRequest) (string, error) {
	if principal == "" {
		return "", errors.New("missing principal")
	}
	if req.SecretRef == "" || req.DestinationID == "" {
		return "", errors.New("missing secret ref or destination")
	}
	dest, err := s.db.GetDestination(req.DestinationID)
	if err != nil {
		return "", err
	}
	if dest == nil {
		s.audit("", "secret_transfer_denied", principal, req.DestinationID, "unknown-destination")
		return "", errors.New("unknown destination")
	}

	src, err := s.resolveSource(req.SecretRef)
	if err != nil {
		return "", err
	}
	req.Source = src

	// Relay follow-up (QR-04/QR-05): an agent bound by a live grant
	// with remaining budget submits directly against it — no standing
	// policy rule required. The grant scopes agent, recipient,
	// deadline and budget; admission revalidates all of it per op.
	if relayID, ok := relayIDOf(req.SecretRef); ok {
		return s.submitRelayTransfer(principal, req, relayID, dest)
	}

	dec, err := s.policy.Evaluate(policy.Request{
		Principal: principal,
		Op:        "transfer",
		SecretRef: req.SecretRef,
		DestID:    req.DestinationID,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		return "", err
	}
	if !dec.Allow {
		s.audit("", "secret_transfer_denied", principal, req.DestinationID, "deny")
		return "", errors.New("access denied")
	}

	req.RequestedBy = principal
	req.CreatedAt = time.Now()
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(s.opTTL())
	}
	// Destination AllowedOps compatibility restriction (SC-05).
	if len(dest.AllowedOps) > 0 && !containsOp(dest.AllowedOps, "transfer") {
		s.audit("", "secret_transfer_denied", principal, req.DestinationID, "dest-op-denied")
		return "", errors.New("operation not permitted for destination")
	}

	// Component selection is bound at submit (SC-08): only the empty ref
	// (default value) or an explicit component:<name> selector reaches
	// approval; anything else is rejected before it can bind an approval.
	// The current AegisKeys v2 contract matches its logical component key;
	// the v1 compatibility fallback matches the returned map key.
	if req.PayloadRef != "" {
		if _, ok := componentRef(req.PayloadRef); !ok {
			s.audit("", "secret_transfer_denied", principal, req.DestinationID, "bad-payload-ref")
			return "", errors.New("invalid payload ref: want \"\" or \"component:<name>\"")
		}
	}
	req.OpHash = metadata.TransferOpHash(principal, req.SecretRef, req.DestinationID, req.PayloadRef)
	req.AuthEpoch = dec.AuthEpoch
	req.DestDigest = metadata.DestDigest(dest)
	req.DestRevision = dest.Revision
	req.Status = types.StatusRequested
	if !dec.RequiresApproval && !dest.RequiresApproval {
		req.Status = types.StatusAuthorized
		req.ApprovedBy = "policy:preauthorized"
	} else if dest.RequiresApproval {
		req.Status = types.StatusPendingApproval
	}

	if err := s.db.CreateTransfer(req); err != nil {
		return "", err
	}
	s.audit(req.ID, "secret_transfer_requested", principal, req.DestinationID, req.Status)
	return req.ID, nil
}

// OpStatus is the agent-visible status of one operation plus its durable
// sanitized receipt when completed. Receipts contain only closed, sanitized
// result DTOs (never raw HTTP or credential material) and are visible only
// to the authenticated submitting principal (C12).
// OpStatus is the agent-visible status of one operation plus its durable
// sanitized receipt when completed. VerifyState carries the latest
// authorized verification observation (CV-03): "" when nothing has been
// observed yet, otherwise one of satisfied | contradicted | inconclusive |
// response_validated | check-failed | verification_unavailable (the last
// meaning the observation store could not be read — P2-8). A contradiction
// for operator reconciliation instead of hiding behind execution status.
type OpStatus struct {
	Status string
	// EffectiveOutcome composes execution state with the latest durable
	// observation. It never rewrites the immutable execution receipt.
	EffectiveOutcome string
	ResultType       string
	Result           string
	CompletedAt      time.Time
	HasReceipt       bool
	VerifyState      string
	VerifyDetail     string
	VerifyChecked    time.Time
	HasObservation   bool
	// VerifyUnavailable marks a verification-history read failure
	// (P2-8): VerifyState is then "verification_unavailable" and must
	// not be mistaken for "no verification performed".
	VerifyUnavailable bool
	// NextAction tells the agent what happens next (G03): which side
	// acts, so an authorized op is never silently stranded and an
	// expired one is never mistaken for pending work.
	NextAction string
}

// StatusDetail returns the caller's own operation status plus the durable
// receipt when the operation completed. Non-completed ops carry no receipt;
// other principals' ops are denied without revealing existence.
func (s *Service) StatusDetail(principal, opType, opID string) (OpStatus, error) {
	if principal == "" {
		return OpStatus{}, errors.New("missing principal")
	}
	var owner, status, operationType string
	var expires time.Time
	switch opType {
	case "transfer", "secret_transfer":
		tr, err := s.db.GetTransfer(opID)
		if err != nil || tr == nil {
			return OpStatus{}, errors.New("not found")
		}
		owner, status, expires = tr.RequestedBy, tr.Status, tr.ExpiresAt
		operationType = "transfer"
	case "use", "secret_use":
		ur, err := s.db.GetUse(opID)
		if err != nil || ur == nil {
			return OpStatus{}, errors.New("not found")
		}
		owner, status, expires = ur.RequestedBy, ur.Status, ur.ExpiresAt
		operationType = ur.Operation
	default:
		return OpStatus{}, errors.New("unknown op type")
	}
	if owner != principal {
		return OpStatus{}, errors.New("access denied")
	}
	// Effective expiry (G04): an open op past its deadline reads as
	// expired even when no worker has run the transition yet. The
	// stored row still says requested until ExpireOpenOperations
	// sweeps it; readers must never present it as actionable.
	out := OpStatus{Status: effectiveStatus(status, expires, time.Now())}
	if status == types.StatusCompleted {
		r, err := s.db.GetReceipt(opID)
		if err != nil {
			return OpStatus{}, err
		}
		if r != nil {
			out.ResultType, out.Result, out.CompletedAt, out.HasReceipt =
				r.ResultType, r.Result, r.CompletedAt, true
		}
	}
	// Latest authorized verification state rides along for completed and
	// uncertain dispatches. This lets status distinguish accepted delivery
	// from an unresolved post-dispatch effect (CV-03/F05).
	if status == types.StatusCompleted || status == types.StatusUncertain {
		if obs, err := s.db.LatestObservation(opID); err != nil {
			// P2-8: a verification read failure is a distinct condition
			// — never reported as "no verification performed". A
			// contradiction hidden behind a read error must not read
			// as a clean absence of evidence.
			out.VerifyUnavailable = true
			out.VerifyState = "verification_unavailable"
		} else if obs != nil {
			out.VerifyState, out.VerifyDetail, out.VerifyChecked, out.HasObservation =
				obs.State, obs.Details, obs.ObservedAt, true
		}
	}
	out.EffectiveOutcome = effectiveOutcome(out.Status, operationType, out.HasReceipt, out.VerifyState, out.VerifyUnavailable)
	out.NextAction = outcomeNextAction(out.Status, operationType, out.EffectiveOutcome, out.VerifyState)
	return out, nil
}

// OpEnvelope returns the canonical reviewed action for operator approval
// display (SC-02). Envelope rows carry no plaintext, so this is safe to
// show on the operator terminal. The operator reviews digest + revision +
// epoch and the approval CAS-checks all three atomically.
func (s *Service) OpEnvelope(opType, opID string) (map[string]interface{}, error) {
	switch opType {
	case "transfer", "secret_transfer":
		tr, err := s.db.GetTransfer(opID)
		if err != nil || tr == nil {
			return nil, errors.New("not found")
		}
		return map[string]interface{}{
			"op_type": "transfer", "op_id": tr.ID,
			"requested_by": tr.RequestedBy, "secret_ref": tr.SecretRef,
			"source_kind": string(tr.Source.Kind), "source_binding": tr.Source.Binding,
			"destination_id": tr.DestinationID, "payload_ref": tr.PayloadRef,
			"status": tr.Status, "revision": tr.Revision, "auth_epoch": tr.AuthEpoch,
			"dest_digest": tr.DestDigest, "op_hash": tr.OpHash,
			"expires_at": tr.ExpiresAt,
		}, nil
	case "use", "secret_use":
		ur, err := s.db.GetUse(opID)
		if err != nil || ur == nil {
			return nil, errors.New("not found")
		}
		return map[string]interface{}{
			"op_type": "use", "op_id": ur.ID,
			"requested_by": ur.RequestedBy, "secret_ref": ur.SecretRef,
			"source_kind": string(ur.Source.Kind), "source_binding": ur.Source.Binding,
			"operation": ur.Operation, "target": ur.Target, "params": ur.Params,
			"status": ur.Status, "revision": ur.Revision, "auth_epoch": ur.AuthEpoch,
			"dest_digest": ur.DestDigest, "op_hash": ur.OpHash,
			"expires_at": ur.ExpiresAt,
		}, nil
	default:
		return nil, errors.New("unknown op type")
	}
}

// Status returns only the caller's own operation status (safe receipt metadata).
func (s *Service) Status(principal, opType, opID string) (string, error) {
	d, err := s.StatusDetail(principal, opType, opID)
	if err != nil {
		return "", err
	}
	return d.Status, nil
}

// effectiveStatus maps a stored open status past its deadline to expired
// (G04). Terminal and in-flight states pass through untouched.
func effectiveStatus(stored string, expires, now time.Time) string {
	switch stored {
	case types.StatusRequested, types.StatusPendingApproval, types.StatusAuthorized:
		if !expires.IsZero() && !now.Before(expires) {
			return types.StatusExpired
		}
	}
	return stored
}

// nextAction names the next actor for every lifecycle state (G03), so no
// valid authorized operation sits stranded without an observable route
// to execution or cancellation.
func nextAction(status string) string {
	switch status {
	case types.StatusRequested, types.StatusPendingApproval:
		return "awaiting operator approval (admin approve)"
	case types.StatusAuthorized:
		return "authorized, awaiting execution (admin execute or auto worker)"
	case types.StatusExecuting, types.StatusDispatching:
		return "execution in progress"
	case types.StatusUncertain:
		return "uncertain delivery: reconcile via recipient-status, do not resend blindly"
	case types.StatusExpired:
		return "expired: submit a fresh request for a new authorization cycle"
	default:
		return "terminal: no further action"
	}
}

func effectiveOutcome(status, operationType string, hasReceipt bool, verifyState string, verifyUnavailable bool) string {
	if verifyUnavailable || verifyState == metadata.ObsCheckFailed {
		return "uncertain"
	}
	switch verifyState {
	case metadata.ObsSatisfied:
		return "satisfied"
	case metadata.ObsContradicted:
		return "contradicted"
	case metadata.ObsInconclusive:
		if status == types.StatusUncertain {
			return "uncertain"
		}
		if operationType == "transfer" {
			return "accepted"
		}
		return "unverified"
	case metadata.ObsResponseValidated:
		return "response_validated"
	}
	if status == types.StatusUncertain || status == types.StatusCompleted && !hasReceipt {
		return "uncertain"
	}
	if status == types.StatusCompleted {
		return "unverified"
	}
	return status
}

func outcomeNextAction(status, operationType, outcome, verifyState string) string {
	switch outcome {
	case "contradicted":
		return "operator: reconcile the contradictory observation and choose a corrective action; execution receipt is immutable"
	case "uncertain":
		if verifyState == metadata.ObsCheckFailed || verifyState == "verification_unavailable" {
			return "operator: retry independent verification/readback; do not repeat the operation"
		}
		if operationType == "transfer" {
			return "operator: reconcile recipient acceptance/status before any resend; do not retry blindly"
		}
		return "operator: reconcile the external effect before any retry; do not replay blindly"
	case "accepted":
		return "recipient accepted the transfer; operator may verify application/readback; do not resend based on acceptance alone"
	case "unverified":
		return "execution receipt is recorded; request independent verification when the operation has an external postcondition"
	case "response_validated", "satisfied":
		return "terminal: outcome contract satisfied"
	default:
		return nextAction(status)
	}
}

func containsOp(list []string, op string) bool {
	for _, s := range list {
		if s == op {
			return true
		}
	}
	return false
}

func (s *Service) audit(opID, action, actor, target, outcome string) {
	_ = s.db.WriteAuditLog(&types.AuditLog{
		OperationID: opID,
		Action:      action,
		Actor:       actor,
		Target:      target,
		Outcome:     outcome,
	})
}
