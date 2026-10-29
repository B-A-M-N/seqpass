package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

// newRelayID mints the unpredictable locator. Possession alone
// authorizes nothing — every transition revalidates the envelope — but
// unguessability keeps request IDs out of bulk-probe reach.
func newRelayID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("relay id randomness unavailable: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// RelayRefPrefix namespaces synthetic secret refs bound to one relay
// grant (QR-04). A relay ref authorizes exactly the handoff the user
// approved — never a standing credential, never a broad policy rule.
const RelayRefPrefix = "relay:"

// TransientRefPrefix namespaces synthetic secret refs bound to one
// TRANSIENT use-once intake (P0-C). Like a relay ref it resolves ONLY
// through the ephemeral spool under a live reservation — but it backs a
// protected-USE operation (one approved driver execution), not a relay
// transfer, and its payload is deleted at the dispatch barrier.
const TransientRefPrefix = "tuse:"

func relayIDOf(secretRef string) (string, bool) {
	if !strings.HasPrefix(secretRef, RelayRefPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(secretRef, RelayRefPrefix)
	if id == "" {
		return "", false
	}
	return id, true
}

// transientIDOf parses a transient use-once source ref.
func transientIDOf(secretRef string) (string, bool) {
	if !strings.HasPrefix(secretRef, TransientRefPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(secretRef, TransientRefPrefix)
	if id == "" {
		return "", false
	}
	return id, true
}

// transientPayloadKey namespaces the ephemeral spool entry holding a
// transient credential (never a durable table; restart loses it by design).
func transientPayloadKey(refID string) string { return "transient-payload:" + refID }

// relayDataKinds is the closed vocabulary an agent may request (QR-03 /
// SP-TUI-08): the kind tells the user WHAT is being asked for, and the
// TUI displays it from this broker-side set — never free-form agent
// text in the reviewed fields.
var relayDataKinds = map[string]bool{
	"password":      true,
	"one_time_code": true,
	"api_key":       true,
	"token":         true,
	"pin":           true,
	"text":          true,
}

// Relay TTL bounds (QR-05): a 30-second verification code must be
// expressible even though the general operation window differs. Payload
// lifetime always equals the relay deadline — never longer.
const (
	minRelayTTL     = 30 * time.Second
	maxRelayTTL     = 24 * time.Hour
	defaultRelayTTL = 5 * time.Minute
)

func clampRelayTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return defaultRelayTTL
	}
	if ttl < minRelayTTL {
		return minRelayTTL
	}
	if ttl > maxRelayTTL {
		return maxRelayTTL
	}
	return ttl
}

// RelayRequest creates an agent-scoped handoff request (Workflow A).
// The agent names a REGISTERED recipient and a data kind; the broker
// assigns the unpredictable ID, pins the recipient's current
// configuration, and returns awaiting_user. No payload flows here, and
// the agent's free-form purpose is stored as untrusted annotation —
// the TUI renders verified fields from the broker snapshot, never the
// agent's claims (SP-TUI-08).
func (s *Service) RelayRequest(agent, destID, dataKind, purpose string, ttl time.Duration, consumption string, maxDeliveries uint32) (string, error) {
	if agent == "" {
		return "", errors.New("missing agent principal")
	}
	if !relayDataKinds[dataKind] {
		s.audit("", "relay_request_denied", agent, destID, "bad-data-kind")
		return "", fmt.Errorf("unknown data kind %q", dataKind)
	}
	// F10/F17: bounded admission for untrusted agent text and volume.
	// The purpose is an untrusted annotation: length-capped here and
	// sanitized at every rendering site. Control characters are refused.
	if len(purpose) > 500 {
		s.audit("", "relay_request_denied", agent, destID, "purpose-too-long")
		return "", errors.New("purpose too long (max 500 chars)")
	}
	for _, r := range purpose {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			s.audit("", "relay_request_denied", agent, destID, "purpose-controls")
			return "", errors.New("purpose contains control characters")
		}
	}
	dest, err := s.db.GetDestination(destID)
	if err != nil || dest == nil {
		s.audit("", "relay_request_denied", agent, destID, "unknown-destination")
		return "", errors.New("unknown destination: requests name registered recipients only")
	}
	if consumption == "" {
		consumption = types.RelaySingleDispatch
	}
	if s.cfg.VaultType == "relay-only" && consumption != types.RelaySingleDispatch {
		return "", errors.New("relay-only supports one-time single-dispatch handoffs only")
	}
	if consumption == types.RelayBoundedUses && maxDeliveries == 0 {
		return "", errors.New("bounded_uses requires max_deliveries >= 1")
	}
	if consumption == types.RelaySingleDispatch {
		maxDeliveries = 1
	}
	// F17/SP-17: transactional per-principal pending-request bound so one
	// agent cannot flood the broker store or hide legitimate requests.
	// The count and insert happen in the same atomic operation — a race
	// between the check and insert cannot exceed the quota. Database
	// errors fail closed, never silently disable protection.
	rid, err := newRelayID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	r := &types.RelayRecord{
		ID:             "req-" + rid,
		AgentPrincipal: agent,
		DestinationID:  dest.ID,
		DestRevision:   dest.Revision,
		DestDigest:     metadata.DestDigest(dest),
		DataKind:       dataKind,
		Purpose:        purpose,
		Consumption:    consumption,
		MaxDeliveries:  maxDeliveries,
		ExpiresAt:      now.Add(clampRelayTTL(ttl)),
		CreatedAt:      now,
	}
	if err := s.db.CreateRelayWithQuota(agent, r); err != nil {
		if strings.Contains(err.Error(), "too many pending relay requests") {
			s.audit("", "relay_request_denied", agent, destID, "pending-limit")
		}
		return "", err
	}
	s.audit(r.ID, "relay_requested", agent, destID, dataKind)
	return r.ID, nil
}

// RelayFulfill stages the user's payload and authorizes the handoff
// (intake identity only — never the agent). The reviewed recipient
// configuration is re-read live and pinned; the payload lifetime equals
// the relay deadline. The authorized transfer operation commits in the
// SAME transaction as the grant (QR-04), so the worker (or manual
// execute) delivers through the normal path.
func (s *Service) RelayFulfill(intakePrincipal, relayID string, expectedRevision uint64, payload []byte) (string, error) {
	if intakePrincipal == "" || relayID == "" {
		return "", errors.New("missing intake identity or request")
	}
	if len(payload) == 0 {
		return "", errors.New("empty payload refused")
	}
	if expectedRevision == 0 {
		return "", errors.New("missing reviewed request revision")
	}
	now := time.Now()
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return "", errors.New("unknown relay request")
	}
	if expectedRevision != r.Revision {
		s.audit(relayID, "relay_fulfill_denied", intakePrincipal, r.DestinationID, "review-revision-stale")
		return "", errors.New("request changed since review: fulfill refused")
	}
	// SP-10: once an intake owner has claimed this request, only that
	// owner can fulfill it. A pre-claim request is fulfillable by any
	// trusted intake identity (claiming assigns ownership in the same
	// CAS inside FulfillRelay).
	if r.IntakeOwner != "" && r.IntakeOwner != intakePrincipal {
		s.audit(relayID, "relay_fulfill_denied", intakePrincipal, r.DestinationID, "foreign-intake-owner")
		return "", errors.New("access denied")
	}
	if r.State != types.RelayAwaitingUser {
		return "", fmt.Errorf("relay is not awaiting input (state=%s)", r.State)
	}
	if !now.Before(r.ExpiresAt) {
		return "", errors.New("relay expired")
	}
	// Reviewed configuration, revalidated live against the immutable
	// request-time fingerprint (F01/SP-TUI-08): fulfillment is refused
	// when the destination was repointed or re-pinned after the
	// agent's request. A changed recipient needs a new request and a
	// new human review — never a silent rebind.
	dest, err := s.db.GetDestination(r.DestinationID)
	if err != nil || dest == nil {
		return "", errors.New("recipient revoked")
	}
	if len(dest.AllowedOps) > 0 && !containsOp(dest.AllowedOps, "transfer") {
		return "", errors.New("recipient does not accept transfers")
	}
	destDigest := metadata.DestDigest(dest)
	if destDigest != r.DestDigest || dest.Revision != r.DestRevision {
		s.audit(relayID, "relay_fulfill_denied", intakePrincipal, r.DestinationID, "recipient-changed")
		return "", errors.New("recipient changed since request: fulfill refused, submit a fresh relay_request")
	}
	// Stage first (payload lifetime = remaining relay lifetime), then
	// commit the grant. On grant conflict the staged bytes are dropped.
	key := relayPayloadKey(relayID)
	var stageErr error
	if r.Consumption == types.RelaySingleDispatch {
		stageErr = s.eph.Store(key, payload, r.ExpiresAt.Sub(now))
	} else {
		stageErr = s.eph.StoreRetained(key, payload, r.ExpiresAt.Sub(now))
	}
	if stageErr != nil {
		return "", fmt.Errorf("payload staging failed: %w", stageErr)
	}
	staged := true
	defer func() {
		if staged {
			s.eph.Delete(key)
		}
	}()
	secretRef := RelayRefPrefix + relayID
	opID, err := newRelayID()
	if err != nil {
		s.eph.Delete(key)
		staged = false
		return "", err
	}
	epoch, err := relayEpoch(s)
	if err != nil {
		s.eph.Delete(key)
		staged = false
		s.audit(relayID, "relay_fulfill_denied", intakePrincipal, r.DestinationID, "epoch-read-failed")
		return "", fmt.Errorf("authorization epoch unavailable: %w", err)
	}
	op := &types.TransferRequest{
		ID:            opID,
		SecretRef:     secretRef,
		Source:        types.SecretSource{Kind: types.SourceEphemeral, Ref: secretRef},
		DestinationID: dest.ID,
		RequestedBy:   r.AgentPrincipal,
		CreatedAt:     now,
		ExpiresAt:     r.ExpiresAt,
		Status:        types.StatusAuthorized,
		ApprovedBy:    "relay:" + relayID,
		AuthEpoch:     epoch,
		DestDigest:    destDigest,
		DestRevision:  dest.Revision,
	}
	op.OpHash = metadata.TransferOpHash(op.RequestedBy, op.SecretRef, op.DestinationID, op.PayloadRef)
	if err := s.db.FulfillRelay(relayID, intakePrincipal, destDigest, dest.Revision, op, now); err != nil {
		s.audit(relayID, "relay_fulfill_denied", intakePrincipal, r.DestinationID, "conflict")
		return "", err
	}
	staged = false
	s.audit(relayID, "relay_fulfilled", intakePrincipal, r.DestinationID, r.DataKind)
	return op.ID, nil
}

// RelayUserInit is Workflow B: the user already knows what to supply.
// It creates a self-scoped relay (agent = caller) and fulfills it in
// one trusted interaction — no permanent policy setup (QR-04).
func (s *Service) RelayUserInit(caller, destID, dataKind, purpose string, ttl time.Duration, payload []byte) (string, string, error) {
	return s.RelayUserInitWithConsumption(caller, destID, dataKind, purpose, ttl, types.RelaySingleDispatch, 1, payload)
}

// RelayUserInitWithConsumption is the trusted intake creation path (F03,
// F13): unlike the agent IPC surface (single-use only), an explicit
// trusted-user choice may select a broader consumption policy.
func (s *Service) RelayUserInitWithConsumption(caller, destID, dataKind, purpose string, ttl time.Duration, consumption string, maxDeliveries uint32, payload []byte) (string, string, error) {
	reqID, err := s.RelayRequest(caller, destID, dataKind, purpose, ttl, consumption, maxDeliveries)
	if err != nil {
		return "", "", err
	}
	r, err := s.db.GetRelay(reqID)
	if err != nil || r == nil {
		return "", "", errors.New("created relay unavailable")
	}
	opID, err := s.RelayFulfill(caller, reqID, r.Revision, payload)
	if err != nil {
		return "", "", err
	}
	return reqID, opID, nil
}

// RelayReject refuses a pending request (intake only). No payload has
// been staged at this point by construction.
func (s *Service) RelayReject(intakePrincipal, relayID string, expectedRevision uint64) error {
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return errors.New("unknown relay request")
	}
	if expectedRevision == 0 {
		return errors.New("missing reviewed request revision")
	}
	if expectedRevision != r.Revision {
		return errors.New("request changed since review: reject refused")
	}
	// SP-10: claimed requests are locked to their intake owner.
	if r.IntakeOwner != "" && r.IntakeOwner != intakePrincipal {
		return errors.New("access denied")
	}
	if err := s.db.RejectRelay(relayID, intakePrincipal, r.Revision, time.Now()); err != nil {
		return err
	}
	s.audit(relayID, "relay_rejected", intakePrincipal, r.DestinationID, r.DataKind)
	return nil
}

// RelayCancel withdraws a request. Agents may cancel only their own
// undecided/undispatched relays; intake may cancel any non-dispatched
// one. Cancellation drops staged bytes and fails a live authorized op
// in the same transaction (no cancelled handoff is delivered).
func (s *Service) RelayCancel(caller string, relayID string, asIntake bool) error {
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return errors.New("unknown relay request")
	}
	if !asIntake && r.AgentPrincipal != caller {
		return errors.New("access denied")
	}
	// F09: once an intake owner has claimed the request, a different
	// intake identity cannot cancel it out from under them — even with
	// the request ID. (Pre-claim inbox scoping for multi-user fleets
	// needs a broker-side agent→human mapping; single-operator remains
	// the recommended topology — see README.)
	if asIntake && r.IntakeOwner != "" && r.IntakeOwner != caller {
		return errors.New("access denied")
	}
	if err := s.db.CancelRelay(relayID, r.Revision, time.Now()); err != nil {
		return err
	}
	s.eph.Delete(relayPayloadKey(relayID))
	s.audit(relayID, "relay_cancelled", caller, r.DestinationID, r.State)
	return nil
}

// RelayCancelPrompt cancels a host presentation prompt without forcing a
// dispatch cancellation (HI-10). Returns false when the relay is not in
// a cancellable-prompt state; the caller then treats the action as
// ambiguous rather than reporting a definitive rejection.
func (s *Service) RelayCancelPrompt(agent, relayID string) (bool, error) {
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return false, errors.New("unknown relay request")
	}
	if r.AgentPrincipal != agent {
		return false, errors.New("access denied")
	}
	if r.State != types.RelayAwaitingUser {
		return false, nil
	}
	if err := s.db.CancelRelay(relayID, r.Revision, time.Now()); err != nil {
		return false, err
	}
	s.eph.Delete(relayPayloadKey(relayID))
	s.audit(relayID, "relay_prompt_cancelled", agent, r.DestinationID, r.State)
	return true, nil
}

// submitRelayTransfer binds one more operation to a live grant (QR-05
// bounded/reusable follow-ups). Every check the user-approved envelope
// requires is revalidated here; the budget itself is spent atomically
// later at reservation, so concurrent submits race safely on the grant.
func (s *Service) submitRelayTransfer(principal string, req *types.TransferRequest, relayID string, dest *types.Destination) (string, error) {
	now := time.Now()
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		s.audit("", "secret_transfer_denied", principal, req.DestinationID, "unknown-relay")
		return "", errors.New("unknown relay")
	}
	deny := func(outcome string) (string, error) {
		s.audit("", "secret_transfer_denied", principal, req.DestinationID, outcome)
		return "", errors.New("relay grant does not cover this handoff")
	}
	if r.AgentPrincipal != principal {
		return deny("relay-foreign-agent")
	}
	if r.DestinationID != req.DestinationID {
		return deny("relay-foreign-recipient")
	}
	if r.State != types.RelayAuthorized && r.State != types.RelayReserved {
		return deny("relay-not-dispatchable")
	}
	if !now.Before(r.ExpiresAt) {
		return deny("relay-expired")
	}
	if r.MaxDeliveries > 0 && r.UsedDeliveries >= r.MaxDeliveries {
		return deny("relay-exhausted")
	}
	if metadata.DestDigest(dest) != r.DestDigest || dest.Revision != r.DestRevision {
		return deny("relay-recipient-changed")
	}
	if req.PayloadRef != "" {
		return deny("relay-no-components")
	}
	epoch, err := relayEpoch(s)
	if err != nil {
		return "", fmt.Errorf("authorization epoch unavailable: %w", err)
	}
	req.RequestedBy = principal
	req.CreatedAt = now
	req.ExpiresAt = r.ExpiresAt
	req.OpHash = metadata.TransferOpHash(principal, req.SecretRef, req.DestinationID, req.PayloadRef)
	req.AuthEpoch = epoch
	req.DestDigest = r.DestDigest
	req.DestRevision = r.DestRevision
	req.Status = types.StatusAuthorized
	req.ApprovedBy = "relay:" + relayID
	if err := s.db.CreateTransfer(req); err != nil {
		return "", err
	}
	s.audit(req.ID, "relay_op_requested", principal, req.DestinationID, r.Consumption)
	return req.ID, nil
}

// RelayInspect serves the trusted intake inbox (QR-02/SP-TUI-03): the
// pending queue or one request's reviewed envelope. Rows carry no
// payload by construction — inspection can never leak the value.
func (s *Service) RelayInspect(intakePrincipal, relayID string, limit int) (interface{}, error) {
	if relayID != "" {
		r, err := s.db.GetRelay(relayID)
		if err != nil || r == nil {
			return nil, errors.New("unknown relay request")
		}
		// SP-10: once an intake owner has claimed a request, only that
		// owner (or a pre-claim unclaimed request) is inspectable by
		// this intake identity. Unclaimed rows are visible to any
		// trusted intake UID; owned rows are locked to their owner.
		if r.IntakeOwner != "" && r.IntakeOwner != intakePrincipal {
			return nil, errors.New("access denied")
		}
		return r, nil
	}
	// SP-10: the inbox only shows unclaimed rows plus the caller's
	// own claimed rows — another intake identity's claimed requests
	// are never visible.
	return s.db.ListPendingRelaysForIntake(intakePrincipal, limit)
}

// RelayStatus is the agent-visible handshake (SP-TUI-07): the
// requester's own request only, composed from the relay row and its
// operation. Payload-adjacent metadata (byte lengths, digests) is
// omitted — status answers "what happened", never "what was it".
func (s *Service) RelayStatus(agent, relayID string) (map[string]interface{}, error) {
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, errors.New("unknown relay request")
	}
	if r.AgentPrincipal != agent {
		return nil, errors.New("access denied")
	}
	now := time.Now()
	state := r.State
	if !now.Before(r.ExpiresAt) {
		// SP-13: once external dispatch is committed, deadline expiry
		// cannot retroactively classify the operation as never dispatched.
		switch state {
		case types.RelayAwaitingUser, types.RelayReady, types.RelayAuthorized, types.RelayReserved:
			state = types.RelayExpired
		case types.RelayDispatching:
			// Do not overwrite committed dispatch with "expired" — the
			// operation outcome will overlay the authoritative truth.
		}
	}
	var opState string
	var opRecipient string
	if r.OpID != "" {
		if tr, _ := s.db.GetTransfer(r.OpID); tr != nil {
			opState = string(effectiveStatus(tr.Status, tr.ExpiresAt, now))
			// Operation truth overlays the grant row: a completed
			// transfer means the recipient accepted (delivered); an
			// uncertain one needs reconciliation, not a resend.
			switch opState {
			case types.StatusCompleted:
				state = types.RelayDelivered
				opRecipient = "durably_accepted"
			case types.StatusUncertain:
				state = types.RelayUncertain
			case types.StatusFailed:
				state = "failed"
			}
		}
	}
	// F07: derive next-action guidance from the reconciled final state,
	// never from the pre-overlay grant row. The broker asserts only what
	// it can observe (no plaintext in its own public receipt); it never
	// claims properties of the agent host, recipient application, or OS.
	out := map[string]interface{}{
		"request_id":     r.ID,
		"status":         state,
		"destination_id": r.DestinationID,
		"data_kind":      r.DataKind,
		"expires_at":     r.ExpiresAt,
		"consumption":    r.Consumption,
		// F07: the broker asserts only what it can observe — that its
		// own public receipt carries no plaintext. It never claims the
		// agent host, recipient application, or OS never had the value,
		// so no secret_exposed-style field is returned here.
		"plaintext_in_public_receipt": false,
	}
	var remaining interface{}
	if r.MaxDeliveries > 0 {
		rem := int64(r.MaxDeliveries) - int64(r.UsedDeliveries)
		if rem < 0 {
			rem = 0
		}
		remaining = rem
	}
	out["remaining_deliveries"] = remaining
	out["next"] = relayNext(state)
	if r.OpID != "" {
		out["op_id"] = r.OpID
		if opState != "" {
			out["op_status"] = opState
		}
		if opRecipient != "" {
			out["recipient_status"] = opRecipient
		}
	}
	return out, nil
}

func relayNext(state string) string {
	switch state {
	case types.RelayAwaitingUser:
		return "Fulfill through the trusted intake (relay fulfill) before expiry"
	case types.RelayAuthorized, types.RelayReserved, types.RelayDispatching:
		return "Authorized: the trusted worker delivers; poll for the outcome"
	case types.RelayDelivered:
		return "Recipient accepted; continue the workflow"
	case types.RelayUncertain:
		return "Delivery may have occurred: reconcile via recipient-status, do not resend blindly"
	case types.RelayRejected:
		return "User refused; do not retry without asking"
	case types.RelayExpired:
		return "Expired: submit a fresh relay_request"
	case types.RelayCancelled:
		return "Withdrawn: submit a fresh relay_request if still needed"
	case types.RelayUnavailable:
		return "Payload lost (restart/revocation): submit a fresh relay_request"
	case "failed":
		// §10: a deterministic failure (including an authenticated
		// recipient refusal) must never read as terminal-and-silent.
		// The user needs to know this is NOT an ambiguous dispatch: no
		// reconciliation is pending, and the corrective action is to fix
		// the cause and submit a fresh request.
		return "Delivery failed deterministically (recipient refused or dispatch refused): fix the cause, then submit a fresh relay_request"
	default:
		return "terminal: no further action"
	}
}

// relayPayloadKey namespaces ephemeral payloads so relay bytes and
// legacy spool entries can never collide.
func relayPayloadKey(relayID string) string { return "relay-payload:" + relayID }

// relayEpoch reads the authorization epoch without substitution (C11):
// a database failure must fail the relay, never default to epoch 1.
func relayEpoch(s *Service) (int64, error) {
	return s.db.CurrentEpoch()
}

// settleRelayTransfer advances the relay grant from its operation's
// outcome. Called from the transfer execution path for relay-backed
// ops only; failures here are audited but never fail delivery itself
// (display state must not gate the trusted path).
func (s *Service) settleRelayTransfer(tr *types.TransferRequest) {
	relayID, ok := relayIDOf(tr.SecretRef)
	if !ok {
		return
	}
	now := time.Now()
	cur, err := s.db.GetTransfer(tr.ID)
	if err != nil || cur == nil {
		return
	}
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return
	}
	single := r.Consumption == types.RelaySingleDispatch
	key := relayPayloadKey(relayID)
	switch cur.Status {
	case types.StatusCompleted:
		_ = s.db.RecordDeliveryOutcome(relayID, tr.ID, "delivered", now)
		if single {
			if err := s.db.SetRelayOpState(relayID, types.RelayDelivered, now); err != nil {
				s.audit(relayID, "relay_settle_note", tr.RequestedBy, tr.DestinationID, "delivered-mark-failed")
			}
			// F02: Delete tombstones while a holder is outstanding, so
			// the completed operation's own holder must be released too
			// — otherwise the backing bytes are retained indefinitely.
			// Completed deliveries release memory but never refund budget.
			s.eph.Delete(key)
			s.eph.Release(key, tr.ID)
		} else {
			s.eph.Release(key, tr.ID)
		}
	case types.StatusUncertain:
		_ = s.db.RecordDeliveryOutcome(relayID, tr.ID, "uncertain", now)
		if single {
			if err := s.db.SetRelayOpState(relayID, types.RelayUncertain, now); err != nil {
				s.audit(relayID, "relay_settle_note", tr.RequestedBy, tr.DestinationID, "uncertain-mark-failed")
			}
			// Payload is dropped: the uncertain op is terminal and the
			// value is single-use. Reconciliation consults the
			// dispatch record + recipient, never a second delivery.
			s.eph.Delete(key)
			s.eph.Release(key, tr.ID)
		} else {
			s.eph.Release(key, tr.ID)
		}
	case types.StatusFailed, types.StatusExpired, types.StatusCancelled:
		// Pre-dispatch failure may release the hold (QR-05) — but
		// ONLY when this operation actually holds it. The ephemeral
		// holder set is the witness: an op that never reserved (e.g.
		// denied at the gate) must not decrement another op's
		// budget. The release itself refuses anything at/after
		// dispatch, so a lost-ack race cannot free a delivered
		// value for a second consumer.
		if s.eph.HasReservation(key, tr.ID) {
			if err := s.db.ReleaseRelayReservation(relayID, tr.ID, now); err == nil {
				s.eph.Release(key, tr.ID)
			}
		}
		if r.State == types.RelayDispatching {
			s.audit(relayID, "relay_settle_note", tr.RequestedBy, tr.DestinationID, "failed-after-dispatch")
			// §10: a post-dispatch deterministic failure (e.g. an
			// authenticated, digest-bound recipient refusal) must not
			// leave its delivery-history row stuck in "reserved" nor
			// retain the staged value. Mark the row terminal so the
			// grant's delivery history reports the truthful outcome.
			// Budget is NOT refunded (dispatch was committed — the peer
			// received the bytes even though it refused). A single-use
			// payload is dead with its operation: tombstone it exactly
			// as the uncertain path does, so no second consumer can
			// ever read a refused value.
			_ = s.db.RecordDeliveryOutcome(relayID, tr.ID, "failed", now)
			if single {
				s.eph.Delete(key)
				s.eph.Release(key, tr.ID)
			} else {
				s.eph.Release(key, tr.ID)
			}
		}
	}
}
