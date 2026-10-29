package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/handoff"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// IssueHandoff selects the registered transport. Recipient-pull returns an
// opaque one-use locator; sealed-capsule returns signed HPKE ciphertext. Both
// are available only to the original requester after approval.
func (s *Service) IssueHandoff(ctx context.Context, principal, operationID string) (any, error) {
	tr, err := s.db.GetTransfer(operationID)
	if err != nil || tr == nil || tr.RequestedBy != principal {
		return nil, fmt.Errorf("authorized operation unavailable")
	}
	dest, err := s.db.GetDestination(tr.DestinationID)
	if err != nil || dest == nil {
		return nil, fmt.Errorf("handoff destination unavailable")
	}
	if dest.HandoffMode == types.HandoffSealedCapsule && tr.Status == types.StatusUncertain {
		return s.RetrieveHandoffCapsule(principal, operationID)
	}
	if tr.Status != types.StatusAuthorized {
		return nil, fmt.Errorf("authorized operation unavailable")
	}
	switch dest.HandoffMode {
	case types.HandoffRecipientPull:
		return s.IssueHandoffTicket(principal, operationID)
	case types.HandoffSealedCapsule:
		return s.IssueSealedHandoffCapsule(ctx, principal, operationID)
	default:
		return nil, fmt.Errorf("destination does not use a handoff transport")
	}
}

// IssueSealedHandoffCapsule resolves the approved credential only after the
// authorization and destination pins are revalidated, then returns only the
// recipient-encrypted capsule. Issuance leaves the operation uncertain until
// an authenticated recipient receipt is added and verified.
func (s *Service) IssueSealedHandoffCapsule(ctx context.Context, principal, operationID string) (*types.HandoffCapsule, error) {
	if len(s.cfg.HandoffSigningKey) != ed25519.PrivateKeySize || s.cfg.HandoffSigningKeyID == "" {
		return nil, fmt.Errorf("sealed handoff issuer is not configured")
	}
	tr, err := s.db.GetTransfer(operationID)
	if err != nil || tr == nil || tr.RequestedBy != principal || tr.Status != types.StatusAuthorized {
		return nil, fmt.Errorf("authorized operation unavailable")
	}
	dest, attemptID, err := s.admitTransferMode(tr, "capsule", false)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*types.HandoffCapsule, error) {
		_ = s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusFailed, "", nil)
		return nil, cause
	}
	issuerPublic := ed25519.PrivateKey(s.cfg.HandoffSigningKey).Public().(ed25519.PublicKey)
	if dest.HandoffMode != types.HandoffSealedCapsule || dest.CredentialTarget == nil || len(dest.RecipientPublicKey) != 32 || dest.RecipientKeyID == "" || dest.ReceiptKeyID == "" || len(dest.ReceiptPublicKey) != ed25519.PublicKeySize || dest.IssuerKeyID == "" || dest.IssuerKeyID != s.cfg.HandoffSigningKeyID || !bytes.Equal(dest.IssuerPublicKey, issuerPublic) || dest.CredentialTarget.SourceRef != tr.SecretRef {
		return fail(fmt.Errorf("sealed handoff destination registration is invalid"))
	}
	pub, err := capsule.RecipientPublicHandle(dest.RecipientPublicKey)
	if err != nil {
		return fail(fmt.Errorf("recipient public key is invalid"))
	}
	cred, err := s.resolveCredentialMaterial(ctx, tr.Source, types.OperationTransfer, tr.ID)
	if err != nil {
		return fail(err)
	}
	defer zeroCredential(&cred)
	if err := s.db.BeginDispatch("transfer", tr.ID, attemptID, tr.OpHash, tr.DestDigest, "capsule", time.Now()); err != nil {
		return fail(fmt.Errorf("handoff dispatch denied"))
	}
	value, _, err := selectTransferPayload(cred, tr)
	if err != nil {
		return fail(err)
	}
	defer func() { value = "" }()
	if len(value) == 0 || len(value) > 512*1024 {
		return fail(fmt.Errorf("handoff payload size rejected"))
	}
	now := time.Now().UTC()
	ttl := handoff.DefaultTTL
	if remaining := tr.ExpiresAt.Sub(now); remaining < ttl {
		ttl = remaining
	}
	identity, err := handoff.New(tr.ID, dest.ID, 0, now, ttl)
	if err != nil {
		return fail(err)
	}
	expires := identity.ExpiresAt
	target := dest.CredentialTarget
	payload := capsule.Payload{
		HandoffID: identity.TicketID, OperationID: tr.ID, DestinationID: dest.ID,
		DestinationRevision: dest.Revision, TargetID: target.ID, App: target.App, Provider: target.Provider, Account: target.Account, Slot: target.Slot,
		UpdateMethod: target.UpdateMethod, Activation: target.Activation,
		SourceRef: target.SourceRef, SourceRevision: target.SourceRevision,
		IssuedAt: now, NotBefore: now, ExpiresAt: expires, Credential: []byte(value),
	}
	env, err := capsule.Seal(payload, dest.RecipientKeyID, s.cfg.HandoffSigningKeyID, pub, s.cfg.HandoffSigningKey)
	for i := range payload.Credential {
		payload.Credential[i] = 0
	}
	if err != nil {
		return fail(fmt.Errorf("sealed handoff creation failed"))
	}
	encoded, err := capsule.Marshal(env)
	if err != nil {
		return fail(fmt.Errorf("sealed handoff encoding failed"))
	}
	digest := transfer.DigestPayload(string(encoded))
	if err := s.db.RecordSealedCapsuleDispatch(&metadata.DispatchRecord{OpID: tr.ID, AttemptID: attemptID, DestID: dest.ID, DestEndpoint: dest.Endpoint, DestExpectedUID: dest.ExpectedUID, DestExpectedGID: dest.ExpectedGID, DestConfigDigest: tr.DestDigest, PayloadDigest: digest, PayloadBytes: len(encoded), CapsuleBytes: append([]byte{}, encoded...), HandoffMode: types.HandoffSealedCapsule, HandoffID: identity.TicketID}); err != nil {
		return fail(fmt.Errorf("handoff dispatch record failed"))
	}
	// Capsule creation alone is never recipient completion. Ciphertext and
	// uncertain state were committed together before this response is sent.
	s.audit(tr.ID, "handoff_capsule_issued", principal, dest.ID, "recipient-encrypted")
	return &types.HandoffCapsule{Version: capsule.Version, OperationID: tr.ID, DestinationID: dest.ID, HandoffID: identity.TicketID, IssuedAt: now, ExpiresAt: expires, Envelope: json.RawMessage(encoded)}, nil
}

// RetrieveHandoffCapsule returns the exact previously persisted ciphertext to
// the original requester while it remains valid. It never resolves the source
// credential or generates a replacement capsule, so retrieval cannot extend
// authorization or expiry.
func (s *Service) RetrieveHandoffCapsule(principal, operationID string) (*types.HandoffCapsule, error) {
	dispatch, err := s.db.GetRetrievableSealedCapsule(operationID, principal, time.Now())
	if err != nil || dispatch == nil || dispatch.HandoffMode != types.HandoffSealedCapsule ||
		dispatch.HandoffID == "" || len(dispatch.CapsuleBytes) == 0 || len(dispatch.CapsuleBytes) > capsule.MaxSize ||
		dispatch.PayloadBytes != len(dispatch.CapsuleBytes) || transfer.DigestPayload(string(dispatch.CapsuleBytes)) != dispatch.PayloadDigest {
		return nil, fmt.Errorf("sealed handoff retrieval unavailable")
	}
	env, err := capsule.Parse(dispatch.CapsuleBytes)
	if err != nil || env.OperationID != operationID || env.DestinationID != dispatch.DestID ||
		env.HandoffID != dispatch.HandoffID || !env.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("sealed handoff retrieval unavailable")
	}
	return &types.HandoffCapsule{
		Version: env.Version, OperationID: env.OperationID, DestinationID: env.DestinationID,
		HandoffID: env.HandoffID, IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt,
		Envelope: append(json.RawMessage(nil), dispatch.CapsuleBytes...),
	}, nil
}

// IssueHandoffTicket returns an opaque, short-lived locator for an already
// approved recipient-pull operation. It never resolves the secret.
func (s *Service) IssueHandoffTicket(principal, operationID string) (*types.HandoffTicket, error) {
	tr, err := s.db.GetTransfer(operationID)
	if err != nil || tr == nil || tr.RequestedBy != principal || tr.Status != types.StatusAuthorized {
		return nil, fmt.Errorf("authorized operation unavailable")
	}
	dest, err := s.db.GetDestination(tr.DestinationID)
	if err != nil || dest == nil || dest.HandoffMode != types.HandoffRecipientPull || dest.ExpectedUID == nil || dest.CredentialTarget == nil {
		return nil, fmt.Errorf("destination is not configured for recipient-pull")
	}
	if _, relay := relayIDOf(tr.SecretRef); relay {
		return nil, fmt.Errorf("relay credentials cannot be issued as recipient tickets")
	}
	now := time.Now()
	ttl := handoff.DefaultTTL
	if remaining := tr.ExpiresAt.Sub(now); remaining < ttl {
		ttl = remaining
	}
	t, err := handoff.New(tr.ID, dest.ID, *dest.ExpectedUID, now, ttl)
	if err != nil {
		return nil, err
	}
	if err := s.db.CreateHandoffTicket(t, time.Now()); err != nil {
		return nil, fmt.Errorf("handoff ticket unavailable")
	}
	s.audit(tr.ID, "handoff_ticket_issued", principal, dest.ID, "recipient-pull")
	return t, nil
}

// RedeemHandoffTicket resolves credential material only after the ticket's
// recipient UID has been authenticated and atomically claimed.
func (s *Service) RedeemHandoffTicket(ctx context.Context, ticketID, nonce string, recipientUID uint32) (*types.HandoffDelivery, error) {
	t, err := s.db.ClaimHandoffTicket(ticketID, nonce, recipientUID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("handoff ticket unavailable")
	}
	tr, err := s.db.GetTransfer(t.OperationID)
	if err != nil || tr == nil {
		return nil, fmt.Errorf("handoff operation unavailable")
	}
	dest, attemptID, err := s.admitTransferMode(tr, "recipient", true)
	if err != nil {
		_ = s.db.SetHandoffTicketState(tr.ID, "rejected")
		return nil, err
	}
	fail := func(cause error) (*types.HandoffDelivery, error) {
		_ = s.db.FinalizeOp("transfer", tr.ID, attemptID, types.StatusFailed, "", nil)
		_ = s.db.SetHandoffTicketState(tr.ID, "rejected")
		return nil, cause
	}
	cred, err := s.resolveCredentialMaterial(ctx, tr.Source, types.OperationTransfer, tr.ID)
	if err != nil {
		return fail(err)
	}
	defer zeroCredential(&cred)
	if err := s.db.BeginDispatch("transfer", tr.ID, attemptID, tr.OpHash, tr.DestDigest, "recipient", time.Now()); err != nil {
		return fail(fmt.Errorf("handoff dispatch denied"))
	}
	payload, _, err := selectTransferPayload(cred, tr)
	if err != nil {
		return fail(err)
	}
	defer func() { payload = "" }()
	if len(payload) == 0 || len(payload) > 512*1024 {
		return fail(fmt.Errorf("handoff payload size rejected"))
	}
	digest := transfer.DigestPayload(payload)
	if err := s.db.RecordDispatch(&metadata.DispatchRecord{OpID: tr.ID, AttemptID: attemptID, DestID: dest.ID, DestEndpoint: dest.Endpoint, DestExpectedUID: dest.ExpectedUID, DestExpectedGID: dest.ExpectedGID, DestConfigDigest: tr.DestDigest, PayloadDigest: digest, PayloadBytes: len(payload), HandoffMode: types.HandoffRecipientPull}); err != nil {
		return fail(fmt.Errorf("handoff dispatch record failed"))
	}
	s.audit(tr.ID, "handoff_ticket_redeemed", tr.RequestedBy, dest.ID, "recipient-authenticated")
	return &types.HandoffDelivery{OperationID: tr.ID, DestinationID: dest.ID, Target: *dest.CredentialTarget, Payload: []byte(payload), PayloadDigest: digest}, nil
}

func zeroCredential(c *secureops.Credential) {
	c.Value = ""
	for k := range c.Components {
		c.Components[k] = ""
		delete(c.Components, k)
	}
}

// CompleteHandoff records a UID-authenticated, digest-bound recipient result.
func (s *Service) CompleteHandoff(uid uint32, operationID, digest, state string, byteCount int) error {
	return s.completeHandoff(uid, "", operationID, digest, state, byteCount, nil)
}

// CompleteSealedHandoff binds an authenticated receipt to the exact capsule.
func (s *Service) CompleteSealedHandoff(uid uint32, handoffID, operationID, digest, state string, byteCount int) error {
	if handoffID == "" {
		return fmt.Errorf("sealed handoff receipt requires handoff ID")
	}
	return s.completeHandoff(uid, handoffID, operationID, digest, state, byteCount, nil)
}

// CompleteSealedHandoffReceipt accepts a recipient-signed capsule receipt over
// the agent channel. The courier can relay the proof but cannot create or
// retarget it. Destination key rotation invalidates old receipts fail-closed.
func (s *Service) CompleteSealedHandoffReceipt(encoded []byte) error {
	r, err := capsule.ParseReceipt(encoded)
	if err != nil {
		return fmt.Errorf("recipient receipt unavailable")
	}
	d, err := s.db.GetDispatch(r.OperationID)
	if err != nil || d == nil || d.HandoffMode != types.HandoffSealedCapsule || d.HandoffID != r.HandoffID || d.DestID != r.DestinationID || d.PayloadDigest != r.CapsuleDigest || d.PayloadBytes != r.CapsuleBytes {
		return fmt.Errorf("recipient receipt mismatch")
	}
	dest, err := s.db.GetDestination(d.DestID)
	if err != nil || dest == nil || dest.HandoffMode != types.HandoffSealedCapsule || dest.Revision != r.DestinationRevision || dest.ReceiptKeyID != r.ReceiptKeyID || len(dest.ReceiptPublicKey) != ed25519.PublicKeySize || metadata.DestDigest(dest) != d.DestConfigDigest {
		return fmt.Errorf("recipient receipt identity changed")
	}
	if _, err := capsule.VerifyReceipt(encoded, dest.ReceiptKeyID, ed25519.PublicKey(dest.ReceiptPublicKey)); err != nil {
		return fmt.Errorf("recipient receipt signature invalid")
	}
	if d.DestExpectedUID == nil {
		return fmt.Errorf("recipient receipt identity unavailable")
	}
	pin := &metadata.HandoffReceiptPin{DestinationID: dest.ID, Revision: dest.Revision, Digest: d.DestConfigDigest, ReceiptKeyID: dest.ReceiptKeyID}
	return s.completeHandoff(*d.DestExpectedUID, r.HandoffID, r.OperationID, r.CapsuleDigest, r.State, r.CapsuleBytes, pin)
}

func (s *Service) completeHandoff(uid uint32, handoffID, operationID, digest, state string, byteCount int, receiptPin *metadata.HandoffReceiptPin) error {
	if byteCount <= 0 || byteCount > 1<<20 {
		return fmt.Errorf("invalid handoff receipt")
	}
	d, err := s.db.GetDispatch(operationID)
	if err != nil || d == nil || d.PayloadDigest != digest || d.PayloadBytes != byteCount || d.DestExpectedUID == nil || *d.DestExpectedUID != uid ||
		(d.HandoffMode == types.HandoffRecipientPull && handoffID != "") || (d.HandoffMode == types.HandoffSealedCapsule && (handoffID == "" || d.HandoffID != handoffID)) ||
		(d.HandoffMode != types.HandoffRecipientPull && d.HandoffMode != types.HandoffSealedCapsule) {
		return fmt.Errorf("handoff receipt mismatch")
	}
	maxBytes := 512 * 1024
	if d.HandoffMode == types.HandoffSealedCapsule {
		maxBytes = 1 << 20
	}
	if byteCount > maxBytes {
		return fmt.Errorf("invalid handoff receipt")
	}
	tr, err := s.db.GetTransfer(operationID)
	if err != nil || tr == nil {
		return fmt.Errorf("handoff operation unavailable")
	}
	if tr.Status == types.StatusUncertain {
		if state == "uncertain" {
			return nil
		}
		if err := s.db.ReconcileHandoff(operationID, uid, digest, state, byteCount, time.Now(), receiptPin); err != nil {
			return err
		}
		_ = s.db.SetHandoffTicketState(operationID, state)
		return nil
	}
	status := ""
	resultType := "handoff"
	switch state {
	case "applied":
		status = types.StatusCompleted
	case "rejected":
		status = types.StatusFailed
		resultType = ""
	case "uncertain":
		status = types.StatusUncertain
		resultType = ""
	default:
		return fmt.Errorf("unknown handoff result")
	}
	var result interface{}
	if state == "applied" {
		result = map[string]interface{}{"state": "applied", "bytes": byteCount}
	}
	if tr.Status == status {
		return nil
	} // lost completion ACK; same pinned dispatch already settled
	if err := s.db.FinalizeOp("transfer", operationID, d.AttemptID, status, resultType, result); err != nil {
		return err
	}
	_ = s.db.SetHandoffTicketState(operationID, state)
	s.audit(operationID, "handoff_recipient_completed", d.DestID, d.DestID, state)
	return nil
}
