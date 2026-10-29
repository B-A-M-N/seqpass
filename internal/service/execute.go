package service

import (
	"context"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/policy"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// resolveCredentialMaterial resolves plaintext inside the trusted executor only.
// AegisKeys is authoritative; the ephemeral spool covers trusted-intake payloads.
// operation is the logical driver operation (ur.Operation for approved uses,
// "transfer" for transfers) — it is bound into the broker's operation-scoped
// authorization and audit path. The approval hash (UseOpHash) pins
// ur.Operation, so an agent cannot claim a different operation than the one
// the operator approved.
func (s *Service) resolveCredentialMaterial(ctx context.Context, src types.SecretSource, operation, opID string) (secureops.Credential, error) {
	switch src.Kind {
	case types.SourceAegisKeys:
		if s.cfg.VaultType == "relay-only" {
			return secureops.Credential{}, fmt.Errorf("relay-only has no persistent credential backend")
		}
		socket := s.cfg.AegisKeysSocket
		if socket == "" {
			socket = aegiskeys.SocketPath(s.cfg.AegisKeysDir)
		}
		// P0-1: with the trusted resolve helper configured (isolated
		// deployments), the resolution runs in a short-lived dumpable
		// helper so AegisKeys can verify /proc/<pid>/exe — the broker
		// itself stays non-dumpable and cannot authenticate. The helper
		// path is operator configuration, never agent-supplied input.
		// P0-3: src.BindingID/RecordID (when provisioned) pin the stable
		// identity through to the provider — rebind protection.
		if s.cfg.AegisKeysResolveHelper != "" {
			return aegisResolved(ctx, s.cfg.AegisKeysResolveHelper, socket, src, operation, opID, s.cfg.AegisKeysAttestKey)
		}
		cli, err := aegiskeys.ConnectSocket(socket)
		if err != nil {
			return secureops.Credential{}, err
		}
		mat, err := cli.ResolvePinned(ctx, aegiskeys.ResolvePinFromSource(src.Binding, src.BindingID, src.RecordID, operation, opID))
		if err != nil {
			return secureops.Credential{}, err
		}
		// C13: the binding identity must match the resolved response.
		// AegisKeys already validates raw.Binding == requested binding at
		// the wire layer; this check is defense in depth against a future
		// client regression.
		respRef := mat.Binding
		wantRef := src.Binding
		if wantRef == "" {
			wantRef = src.BindingID
		}
		if respRef != wantRef {
			return secureops.Credential{}, fmt.Errorf("binding identity mismatch: requested %q, resolved %q", wantRef, respRef)
		}
		return secureops.Credential{Value: mat.Value, Components: mat.Components}, nil
	case types.SourceEphemeral:
		// Relay payloads resolve ONLY under a live reservation for
		// this exact operation (QR-06): knowledge of the relay ref
		// is not a read capability. Legacy spool refs keep the old
		// memory-test path.
		if relayID, ok := relayIDOf(src.Ref); ok {
			raw, err := s.eph.GetFor(relayPayloadKey(relayID), opID)
			if err != nil {
				return secureops.Credential{}, err
			}
			// F15: own a disposable copy; clear the store copy's twin
			// once it is encoded into the credential string. String
			// copies cannot be zeroed (immutable), so lifetimes are
			// kept minimal and every owned buffer is cleared on return.
			v := string(raw)
			for i := range raw {
				raw[i] = 0
			}
			return secureops.Credential{Value: v}, nil
		}
		// P0-C transient use-once: the same reservation-gated read for
		// the staged intake payload. The bytes are deleted AFTER the
		// dispatch barrier commits (ExecuteUse), so this read is the
		// operation's one look at the credential.
		if id, ok := transientIDOf(src.Ref); ok {
			raw, err := s.eph.GetFor(transientPayloadKey(id), opID)
			if err != nil {
				return secureops.Credential{}, err
			}
			v := string(raw)
			for i := range raw {
				raw[i] = 0
			}
			return secureops.Credential{Value: v}, nil
		}
		raw, err := s.vault.Get(src.Ref)
		if err != nil {
			return secureops.Credential{}, err
		}
		v := string(raw)
		for i := range raw {
			raw[i] = 0
		}
		return secureops.Credential{Value: v}, nil
	default:
		return secureops.Credential{}, fmt.Errorf("unknown credential source")
	}
}

func failUsePreClaim(s *Service, ur *types.UseRequest, outcome, auditAction string) error {
	_ = s.db.MarkUsePreClaim(ur.ID, types.StatusFailed)
	if auditAction != "" {
		s.audit(ur.ID, auditAction, ur.RequestedBy, ur.Target, outcome)
	}
	return fmt.Errorf("%s", outcome)
}

// admitUse is the single execution gate for credentialed operations. Short
// admission only; no network I/O inside. Returns the driver and attempt ID.
func (s *Service) admitUse(ur *types.UseRequest, worker string) (secureops.OperationDriver, string, error) {
	if time.Now().After(ur.ExpiresAt) {
		_ = s.db.MarkUsePreClaim(ur.ID, types.StatusExpired)
		return nil, "", fmt.Errorf("operation expired")
	}
	src, err := s.resolveSource(ur.SecretRef)
	if err != nil {
		return nil, "", failUsePreClaim(s, ur, "credential revoked", "")
	}
	// P0-3 use-once: a consumed use-once reference fails closed BEFORE
	// any claim or resolve. Consumption itself happens at dispatch (after
	// resolve) so a failed execution does not burn the single use.
	if src.UseOnce {
		ref, gerr := s.db.GetSecretRef(ur.SecretRef)
		if gerr != nil || ref == nil || ref.ReconcileStatus == types.ProvisionReconcileConsumed {
			return nil, "", failUsePreClaim(s, ur, "credential revoked", "")
		}
	}
	// P0-C transient use-once: register THIS operation as the payload's
	// authorized holder NOW (same ordering as the relay transfer path).
	// A missing/expired payload fails closed generically — the transient
	// credential is unrecoverable by design. The read itself stays
	// reservation-gated at resolve time, and the bytes are deleted at the
	// dispatch barrier (at-most-once dispatch).
	if id, ok := transientIDOf(src.Ref); ok && src.Kind == types.SourceEphemeral {
		if err := s.eph.Reserve(transientPayloadKey(id), ur.ID, time.Now()); err != nil {
			return nil, "", failUsePreClaim(s, ur, "credential revoked", "")
		}
	}
	// Source-changed check against the PERSISTED identity triple (the use
	// row stores kind/binding/ref, not the derived pins): a
	// binding-association change between approval and execution still
	// trips it. The stable identity pins are enforced by the provider at
	// resolve time (generic denial on pin mismatch).
	if src.Kind != ur.Source.Kind || src.Binding != ur.Source.Binding || src.Ref != ur.Source.Ref {
		return nil, "", failUsePreClaim(s, ur, "credential binding changed", "")
	}
	// In-memory enrichment: the execution path resolves with the CURRENT
	// identity pins (P0-3 rebind protection); the DB row persists only
	// the identity triple.
	ur.Source = src
	driver, err := validateDriverParams(ur.Operation, ur.Params)
	if err != nil {
		return nil, "", failUsePreClaim(s, ur, err.Error(), "")
	}
	if metadata.UseOpHash(ur.RequestedBy, ur.SecretRef, ur.Operation, ur.Target, ur.Params, driver.Resource(ur.Params)) != ur.OpHash {
		return nil, "", failUsePreClaim(s, ur, "operation tampered", "")
	}
	var destDigest string
	if ur.Target != "" {
		dest, err := s.db.GetDestination(ur.Target)
		if err != nil || dest == nil {
			return nil, "", failUsePreClaim(s, ur, "destination revoked", "")
		}
		if len(dest.AllowedOps) > 0 && !containsOp(dest.AllowedOps, ur.Operation) {
			return nil, "", failUsePreClaim(s, ur, "operation not permitted for destination", "")
		}
		destDigest = metadata.DestDigest(dest)
		if destDigest != ur.DestDigest {
			return nil, "", failUsePreClaim(s, ur, "destination changed since approval", "")
		}
	}
	dec, err := s.policy.Evaluate(policy.Request{
		Principal:       ur.RequestedBy,
		Op:              ur.Operation,
		SecretRef:       ur.SecretRef,
		DestID:          ur.Target,
		Destinationless: !driver.RequiresDestination(),
		Resource:        driver.Resource(ur.Params),
		ExpiresAt:       ur.ExpiresAt,
	})
	if err != nil || !dec.Allow {
		_ = s.db.MarkUsePreClaim(ur.ID, types.StatusFailed)
		s.audit(ur.ID, "secret_use_failed", ur.RequestedBy, ur.Target, "revoked")
		return nil, "", fmt.Errorf("access denied")
	}
	// Claim against the live epoch inside one statement; a committed
	// revocation always defeats a racing claim (C04).
	attemptID, claimed, err := s.db.ClaimUse(ur.ID, ur.OpHash, destDigest, ur.Revision, worker, time.Now())
	if err != nil || !claimed {
		// The transient payload hold (if any) dies with the failed claim.
		if id, ok := transientIDOf(src.Ref); ok && src.Kind == types.SourceEphemeral {
			s.eph.Release(transientPayloadKey(id), ur.ID)
		}
		return nil, "", fmt.Errorf("operation not claimable (status=%s)", ur.Status)
	}
	return driver, attemptID, nil
}

// ExecuteUse admits, resolves, crosses the atomic dispatch barrier, executes
// and finalizes receipt + status + attempt in one transaction.
func (s *Service) ExecuteUse(ctx context.Context, useID, worker string) (map[string]interface{}, error) {
	ur, err := s.db.GetUse(useID)
	if err != nil || ur == nil {
		return nil, fmt.Errorf("use not found")
	}
	driver, attemptID, err := s.admitUse(ur, worker)
	if err != nil {
		return nil, err
	}
	input := secureops.UseInput{
		Operation: ur.Operation,
		Target:    ur.Target,
		Params:    ur.Params,
		OpID:      ur.ID,
		Principal: ur.RequestedBy,
		Resource:  driver.Resource(inputParams(ur)),
	}
	// Destination-pinned drivers execute against the operator-registered
	// endpoint. Re-read here (not carried over from admission) so the
	// executed profile is the destination record as it exists at dispatch;
	// admission already bound the digest, so a concurrent change fails the
	// claim, not silently re-pins the profile.
	if ur.Target != "" {
		if dest, derr := s.db.GetDestination(ur.Target); derr == nil && dest != nil {
			input.Dest = dest
		}
	}
	cred, err := s.resolveCredentialMaterial(ctx, ur.Source, ur.Operation, ur.ID)
	if err != nil {
		s.audit(ur.ID, "secret_use_failed", ur.RequestedBy, ur.Target, "resolve-failed")
		_ = s.db.FinalizeOp("use", ur.ID, attemptID, types.StatusFailed, "", nil)
		return nil, err
	}
	// P0-3 use-once: the guarded exactly-once consumption commits only
	// after the credential resolved (a resolve failure leaves the single
	// use intact). The guarded UPDATE fails closed if a concurrent
	// dispatch consumed it first — that dispatch owns the credential.
	if ur.Source.UseOnce {
		if err := s.db.ConsumeUseOnceSecretRef(ur.SecretRef); err != nil {
			s.audit(ur.ID, "secret_use_failed", ur.RequestedBy, ur.Target, "use-once already consumed")
			_ = s.db.FinalizeOp("use", ur.ID, attemptID, types.StatusFailed, "", nil)
			return nil, fmt.Errorf("use-once credential already consumed")
		}
	}
	defer func() {
		cred.Value = ""
		for name := range cred.Components {
			cred.Components[name] = ""
			delete(cred.Components, name)
		}
	}()
	// Atomic dispatch barrier (SC-03): the commit of BeginDispatch is the
	// defined point authorizing external I/O. No I/O happens without it.
	// The barrier re-checks the live deadline: a claim that spent its
	// window resolving credentials cannot dispatch after expiry (P0).
	if err := s.db.BeginDispatch("use", ur.ID, attemptID, ur.OpHash, ur.DestDigest, worker, time.Now()); err != nil {
		return s.finalizeDispatchDenied("use", ur.ID, attemptID, ur.RequestedBy, ur.Target, ur.ExpiresAt, err)
	}
	// P0-C transient use-once: the dispatch barrier commit is the point
	// of no return — destroy the staged bytes NOW. At-most-once dispatch:
	// a post-dispatch failure has already consumed the transient
	// credential and is reported honestly (never silently retried); a
	// denied barrier never reaches here, so the credential survives for
	// its remaining lifetime.
	if tid, ok := transientIDOf(ur.Source.Ref); ok && ur.Source.Kind == types.SourceEphemeral {
		s.eph.Delete(transientPayloadKey(tid))
	}
	result, err := driver.Execute(ctx, cred, input)
	if err != nil {
		status := postDispatchFailureStatus(driver)
		event := "secret_use_failed"
		if status == types.StatusUncertain {
			event = "secret_use_uncertain"
		}
		s.audit(ur.ID, event, ur.RequestedBy, ur.Target, "exec-failed")
		_ = s.db.FinalizeOp("use", ur.ID, attemptID, status, "", nil)
		// Driver errors can include arbitrary upstream text. Do not return that
		// text to the model after a credentialed request.
		return nil, fmt.Errorf("credentialed operation failed")
	}
	// Closed result contract (SC-09): no driver output reaches persistence
	// or the model without passing the shared gate. A violating driver
	// fails the operation rather than publishing an unbounded result.
	if err := secureops.ValidateSafeResult(result); err != nil {
		status := postDispatchFailureStatus(driver)
		event := "secret_use_failed"
		if status == types.StatusUncertain {
			event = "secret_use_uncertain"
		}
		s.audit(ur.ID, event, ur.RequestedBy, ur.Target, "unsafe-result")
		_ = s.db.FinalizeOp("use", ur.ID, attemptID, status, "", nil)
		return nil, fmt.Errorf("driver result rejected by safety policy")
	}
	if err := secureops.ValidateCredentialNonDisclosure(result, cred); err != nil {
		status := postDispatchFailureStatus(driver)
		event := "secret_use_failed"
		if status == types.StatusUncertain {
			event = "secret_use_uncertain"
		}
		s.audit(ur.ID, event, ur.RequestedBy, ur.Target, "credential-disclosure-blocked")
		_ = s.db.FinalizeOp("use", ur.ID, attemptID, status, "", nil)
		return nil, fmt.Errorf("driver result rejected by credential-disclosure policy")
	}
	// Receipt + completed status + attempt outcome commit together: never a
	// clean completion without durable evidence (SC-07).
	if err := s.db.FinalizeOp("use", ur.ID, attemptID, types.StatusCompleted, ur.Operation, result.Data); err != nil {
		s.audit(ur.ID, "secret_use_failed", ur.RequestedBy, ur.Target, "receipt-failed")
		return nil, fmt.Errorf("completion not durable: %w", err)
	}
	s.audit(ur.ID, "secret_use_completed", ur.RequestedBy, ur.Target, "success")
	return map[string]interface{}{
		"success": true,
		"op_id":   ur.ID,
		"summary": result.Summary,
		"data":    result.Data,
	}, nil
}

// Once an external-postcondition driver crosses dispatch, an error or
// rejected response cannot prove that its side effect did not occur. Preserve
// that ambiguity so callers reconcile instead of replaying it.
func postDispatchFailureStatus(driver secureops.OperationDriver) string {
	if driver != nil && driver.Completion() == secureops.ExternalPostcondition {
		return types.StatusUncertain
	}
	return types.StatusFailed
}

func inputParams(ur *types.UseRequest) map[string]string { return ur.Params }

// finalizeDispatchDenied reconciles a refused dispatch through the
// transactional finalizer. Expiry at the barrier is an explicit expired
// outcome — never a generic failure that hides a lapsed authorization.
// Callers pass the op identity they already hold; no extra DB read can
// race the barrier because the barrier itself already decided.
func (s *Service) finalizeDispatchDenied(opType, id, attemptID, requester, target string, expiresAt time.Time, cause error) (map[string]interface{}, error) {
	if !expiresAt.IsZero() && !time.Now().Before(expiresAt) {
		s.audit(id, "secret_"+opType+"_expired", requester, target, "expired-at-dispatch")
		if ferr := s.db.FinalizeOp(opType, id, attemptID, types.StatusExpired, "", nil); ferr != nil {
			return nil, fmt.Errorf("expired at dispatch and finalization failed: %v / %w", cause, ferr)
		}
		return nil, fmt.Errorf("operation expired before dispatch: %w", cause)
	}
	s.audit(id, "secret_"+opType+"_failed", requester, target, "revoked-at-dispatch")
	_ = s.db.FinalizeOp(opType, id, attemptID, types.StatusFailed, "", nil)
	return nil, fmt.Errorf("dispatch denied: %w", cause)
}

func failTransferPreClaim(s *Service, tr *types.TransferRequest, outcome, auditAction string) error {
	_ = s.db.MarkTransferPreClaim(tr.ID, types.StatusFailed)
	if auditAction != "" {
		s.audit(tr.ID, auditAction, tr.RequestedBy, tr.DestinationID, outcome)
	}
	return fmt.Errorf("%s", outcome)
}

// admitTransfer is the single execution gate for blind transfers.
func (s *Service) admitTransfer(tr *types.TransferRequest, worker string) (*types.Destination, string, error) {
	return s.admitTransferMode(tr, worker, false)
}

func (s *Service) admitTransferMode(tr *types.TransferRequest, worker string, recipientPull bool) (*types.Destination, string, error) {
	if time.Now().After(tr.ExpiresAt) {
		_ = s.db.MarkTransferPreClaim(tr.ID, types.StatusExpired)
		return nil, "", fmt.Errorf("operation expired")
	}
	src, err := s.resolveSource(tr.SecretRef)
	if err != nil {
		return nil, "", failTransferPreClaim(s, tr, "credential revoked", "")
	}
	// Source-changed check against the PERSISTED identity triple, then
	// in-memory pin enrichment — same P0-3 semantics as admitUse.
	if src.Kind != tr.Source.Kind || src.Binding != tr.Source.Binding || src.Ref != tr.Source.Ref {
		return nil, "", failTransferPreClaim(s, tr, "credential binding changed", "")
	}
	tr.Source = src
	if metadata.TransferOpHash(tr.RequestedBy, tr.SecretRef, tr.DestinationID, tr.PayloadRef) != tr.OpHash {
		return nil, "", failTransferPreClaim(s, tr, "operation tampered", "")
	}
	dest, err := s.db.GetDestination(tr.DestinationID)
	if err != nil || dest == nil {
		return nil, "", failTransferPreClaim(s, tr, "destination revoked", "")
	}
	if dest.HandoffMode == types.HandoffRecipientPull {
		if !recipientPull {
			return nil, "", failTransferPreClaim(s, tr, "recipient-pull transfer requires a claimed ticket", "")
		}
		if dest.CredentialTarget == nil || dest.CredentialTarget.SourceRef != tr.SecretRef || dest.CredentialTarget.SourceRevision <= 0 {
			return nil, "", failTransferPreClaim(s, tr, "recipient target source binding changed", "")
		}
	}
	if dest.HandoffMode == types.HandoffSealedCapsule {
		if worker != "capsule" {
			return nil, "", failTransferPreClaim(s, tr, "sealed-capsule transfer requires recipient capsule issuance", "")
		}
		if dest.CredentialTarget == nil || dest.CredentialTarget.SourceRef != tr.SecretRef || dest.CredentialTarget.SourceRevision <= 0 {
			return nil, "", failTransferPreClaim(s, tr, "sealed target source binding changed", "")
		}
	}
	if len(dest.AllowedOps) > 0 && !containsOp(dest.AllowedOps, "transfer") {
		return nil, "", failTransferPreClaim(s, tr, "operation not permitted for destination", "")
	}
	destDigest := metadata.DestDigest(dest)
	if destDigest != tr.DestDigest {
		return nil, "", failTransferPreClaim(s, tr, "destination changed since approval", "")
	}
	// Relay-backed operations are authorized by their user-approved
	// grant (QR-04/QR-06), not by standing policy — with the same
	// admission rigor: scope, reservation budget, live recipient config
	// and both deadlines, then the identical atomic claim below.
	if relayID, ok := relayIDOf(tr.SecretRef); ok {
		return s.admitRelayTransfer(tr, dest, destDigest, relayID, worker)
	}
	dec, err := s.policy.Evaluate(policy.Request{
		Principal: tr.RequestedBy,
		Op:        "transfer",
		SecretRef: tr.SecretRef,
		DestID:    tr.DestinationID,
		ExpiresAt: tr.ExpiresAt,
	})
	if err != nil || !dec.Allow {
		_ = s.db.MarkTransferPreClaim(tr.ID, types.StatusFailed)
		s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "revoked")
		return nil, "", fmt.Errorf("access denied")
	}
	attemptID, claimed, err := s.db.ClaimTransfer(tr.ID, tr.OpHash, destDigest, tr.Revision, worker, time.Now())
	if err != nil || !claimed {
		return nil, "", fmt.Errorf("operation not claimable (status=%s)", tr.Status)
	}
	return dest, attemptID, nil
}

// admitRelayTransfer gates a relay handoff through its grant envelope:
// the operation must be the grant's fulfillment (or a budget-bound
// follow-up the grant still covers), for the same agent and recipient,
// inside both deadlines, against the live recipient config. The relay
// grant never consults standing policy and never bumps the epoch.
func (s *Service) admitRelayTransfer(tr *types.TransferRequest, dest *types.Destination, destDigest, relayID, worker string) (*types.Destination, string, error) {
	now := time.Now()
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, "", failTransferPreClaim(s, tr, "relay revoked", "")
	}
	if tr.ApprovedBy != "relay:"+relayID {
		return nil, "", failTransferPreClaim(s, tr, "not relay-authorized", "")
	}
	if r.AgentPrincipal != tr.RequestedBy || r.DestinationID != tr.DestinationID {
		return nil, "", failTransferPreClaim(s, tr, "relay scope mismatch", "")
	}
	// Atomic consumption (QR-05): validates budget, both deadlines
	// and the live recipient, then spends one delivery unit.
	if err := s.db.ReserveRelay(relayID, tr.ID, tr.RequestedBy, tr.DestinationID, now); err != nil {
		s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "relay-reserve-denied: "+err.Error())
		_ = s.db.MarkTransferPreClaim(tr.ID, types.StatusFailed)
		return nil, "", fmt.Errorf("relay reservation denied: %w", err)
	}
	key := relayPayloadKey(relayID)
	if err := s.eph.Reserve(key, tr.ID, now); err != nil {
		_ = s.db.ReleaseRelayReservation(relayID, tr.ID, now)
		_ = s.db.MarkTransferPreClaim(tr.ID, types.StatusFailed)
		return nil, "", fmt.Errorf("relay payload unavailable")
	}
	attemptID, claimed, err := s.db.ClaimTransfer(tr.ID, tr.OpHash, destDigest, tr.Revision, worker, now)
	if err != nil || !claimed {
		// No attempt exists: nothing happened, release the hold.
		_ = s.db.ReleaseRelayReservation(relayID, tr.ID, now)
		s.eph.Release(key, tr.ID)
		return nil, "", fmt.Errorf("operation not claimable (status=%s)", tr.Status)
	}
	return dest, attemptID, nil
}

// ExecuteTransfer admits, resolves, crosses the atomic dispatch barrier and
// delivers broker->recipient, finalizing atomically.
func (s *Service) ExecuteTransfer(ctx context.Context, transferID, worker string) (map[string]interface{}, error) {
	tr, err := s.db.GetTransfer(transferID)
	if err != nil || tr == nil {
		return nil, fmt.Errorf("transfer not found")
	}
	// Relay settlement (QR-05): the grant row follows its operation to
	// delivered/uncertain, and pre-dispatch failures release the hold.
	// Audited but never gating: display state must not fail delivery.
	defer s.settleRelayTransfer(tr)
	dest, attemptID, err := s.admitTransfer(tr, worker)
	if err != nil {
		return nil, err
	}
	fail := func(status, outcome, auditAction string, cause error) (map[string]interface{}, error) {
		s.audit(tr.ID, auditAction, tr.RequestedBy, tr.DestinationID, outcome)
		if ferr := s.db.FinalizeOp("transfer", tr.ID, attemptID, status, "", nil); ferr != nil {
			return nil, fmt.Errorf("%s: finalization failed: %w", outcome, ferr)
		}
		if cause != nil {
			return nil, cause
		}
		return nil, fmt.Errorf("%s", outcome)
	}
	cred, err := s.resolveCredentialMaterial(ctx, tr.Source, types.OperationTransfer, tr.ID)
	if err != nil {
		_ = s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusFailed, "", nil)
		s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "resolve-failed")
		return nil, err
	}
	// F15: best-effort clearing of owned transient copies on every
	// return path; no long-lived object retains the relay payload.
	defer func() {
		cred.Value = ""
		for name := range cred.Components {
			cred.Components[name] = ""
			delete(cred.Components, name)
		}
	}()
	// Atomic dispatch barrier (SC-03): no payload byte moves without it.
	// The barrier re-checks the live deadline (P0): resolution that ran
	// past expiry cannot dispatch.
	if err := s.db.BeginDispatch("transfer", tr.ID, attemptID, tr.OpHash, tr.DestDigest, worker, time.Now()); err != nil {
		return s.finalizeDispatchDenied("transfer", tr.ID, attemptID, tr.RequestedBy, tr.DestinationID, tr.ExpiresAt, err)
	}
	// Component selection (C15): transfer only explicitly permitted components.
	// Empty PayloadRef means the default single value. A "component:<name>"
	// ref selects one named component. Anything else is denied: never fan out
	// every component just because the resolver returned them.
	payload, components, err := selectTransferPayload(cred, tr)
	if err != nil {
		return fail(types.StatusFailed, "component-denied", "secret_transfer_failed", err)
	}
	_ = components
	// Trusted dispatch record (G02): snapshot the exact destination
	// identity and payload digest that crossed the barrier. Later
	// reconciliation consults THIS record — never the destination's
	// current configuration. The digest lives only here and inside
	// the delivery protocol, never in agent-visible receipts (G01).
	if err := s.db.RecordDispatch(&metadata.DispatchRecord{
		OpID: tr.ID, AttemptID: attemptID,
		DestID: dest.ID, DestEndpoint: dest.Endpoint,
		DestExpectedUID: dest.ExpectedUID, DestExpectedGID: dest.ExpectedGID,
		DestConfigDigest: tr.DestDigest,
		PayloadDigest:    transfer.DigestPayload(payload),
		PayloadBytes:     len(payload),
	}); err != nil {
		return fail(types.StatusFailed, "dispatch-record-failed", "secret_transfer_failed", err)
	}
	// SP-13: relay state transitions from committed dispatch truth.
	// If the relay state transition fails, the dispatch has already been
	// committed, so we must not fabricate a failure that would imply the
	// operation was never dispatched. The relay state will be reconciled
	// from the authoritative execution attempt record.
	if relayID, ok := relayIDOf(tr.SecretRef); ok {
		if err := s.db.SetRelayOpState(relayID, types.RelayDispatching, time.Now()); err != nil {
			// The dispatch barrier has already committed. Log but do not
			// report failure as if no dispatch occurred. The status
			// reconciliation derives relay state from the execution attempt.
			s.audit(relayID, "relay_dispatch_state_reconcile_needed", tr.RequestedBy, tr.DestinationID, "dispatch-committed")
		}
	}
	deliverer := transfer.NewDeliverer()
	receipt, err := deliverer.Deliver(ctx, tr.ID, payload, dest)
	if err != nil {
		if err == transfer.ErrUncertain {
			s.audit(tr.ID, "secret_transfer_uncertain", tr.RequestedBy, tr.DestinationID, "uncertain")
			if ferr := s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusUncertain, "", nil); ferr != nil {
				return nil, fmt.Errorf("uncertain delivery and finalization failed: %v / %w", err, ferr)
			}
			return nil, err
		}
		// §10: an authenticated, digest-bound refusal is a deterministic
		// recipient application failure. Finalize as clean failed — the
		// settle path marks the grant's history truthful and never
		// refunds budget (dispatch was committed). Never reported as
		// uncertain: the broker KNOWS no acceptance occurred.
		if err == transfer.ErrRecipientRejected {
			s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "recipient-rejected")
			if ferr := s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusFailed, "", nil); ferr != nil {
				return nil, fmt.Errorf("recipient refusal and finalization failed: %v / %w", err, ferr)
			}
			return nil, fmt.Errorf("recipient refused the delivery")
		}
		return fail(types.StatusFailed, "deliver-failed", "secret_transfer_failed", err)
	}
	// The broker-built delivery receipt passes the same closed contract as
	// driver results (SC-09): fixed scalar shape, no unbounded content.
	if err := secureops.ValidateSafeResult(secureops.SafeResult{Summary: "delivery ok", Data: receipt}); err != nil {
		s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "unsafe-result")
		if ferr := s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusFailed, "", nil); ferr != nil {
			return nil, fmt.Errorf("unsafe result and finalization failed: %v / %w", err, ferr)
		}
		return nil, fmt.Errorf("delivery result rejected: %w", err)
	}
	// Receipt + completed status + attempt outcome commit together (SC-07).
	if err := s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusCompleted, "delivery", receipt); err != nil {
		s.audit(tr.ID, "secret_transfer_failed", tr.RequestedBy, tr.DestinationID, "receipt-failed")
		return nil, fmt.Errorf("completion not durable: %w", err)
	}
	s.audit(tr.ID, "secret_transfer_completed", tr.RequestedBy, tr.DestinationID, "success")
	return map[string]interface{}{
		"success":        true,
		"op_id":          tr.ID,
		"destination_id": dest.ID,
		"receipt":        receipt,
	}, nil
}

// selectTransferPayload enforces explicit component selection (C15).
func selectTransferPayload(cred secureops.Credential, tr *types.TransferRequest) (string, map[string]string, error) {
	if tr.PayloadRef == "" {
		if cred.Value == "" {
			return "", nil, fmt.Errorf("no default credential value")
		}
		return cred.Value, nil, nil
	}
	if name, ok := componentRef(tr.PayloadRef); ok {
		v, ok := cred.Components[name]
		if !ok || v == "" {
			return "", nil, fmt.Errorf("component not available")
		}
		return v, map[string]string{name: v}, nil
	}
	return "", nil, fmt.Errorf("unsupported payload ref")
}

func componentRef(ref string) (string, bool) {
	const pfx = "component:"
	if len(ref) <= len(pfx) || ref[:len(pfx)] != pfx {
		return "", false
	}
	name := ref[len(pfx):]
	if name == "" || len(name) > 128 {
		return "", false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return "", false
		}
	}
	return name, true
}

// ApproveUse / ApproveTransfer are admin-only (operator terminal via IPC
// admin socket). expectRevision carries the operator-observed revision from
// the reviewed display (SC-02): negative means "use current", and the
// database still CAS-checks hash, revision and live epoch atomically.
func (s *Service) ApproveUse(id, approver string, expectRevision int) error {
	ur, err := s.db.GetUse(id)
	if err != nil || ur == nil {
		return fmt.Errorf("use not found")
	}
	driver, err := validateDriverParams(ur.Operation, ur.Params)
	if err != nil {
		return err
	}
	rev := ur.Revision
	if expectRevision >= 0 {
		rev = expectRevision
	}
	expected := metadata.UseOpHash(ur.RequestedBy, ur.SecretRef, ur.Operation, ur.Target, ur.Params, driver.Resource(ur.Params))
	return s.db.ApproveUse(id, approver, expected, ur.AuthEpoch, rev)
}

func (s *Service) RejectUse(id, approver string) error {
	return s.db.RejectUse(id, approver)
}

func (s *Service) ApproveTransfer(id, approver string, expectRevision int) error {
	tr, err := s.db.GetTransfer(id)
	if err != nil || tr == nil {
		return fmt.Errorf("transfer not found")
	}
	rev := tr.Revision
	if expectRevision >= 0 {
		rev = expectRevision
	}
	expected := metadata.TransferOpHash(tr.RequestedBy, tr.SecretRef, tr.DestinationID, tr.PayloadRef)
	return s.db.ApproveTransfer(id, approver, expected, tr.AuthEpoch, rev)
}

func (s *Service) RejectTransfer(id, approver string) error {
	return s.db.RejectTransfer(id, approver)
}
