package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

// relayHostState maps the reconciled relay state to the restricted host
// event vocabulary. Only these three event classes are exposed.
func relayHostState(state string) (harness.HostEventType, bool) {
	switch state {
	case types.RelayAwaitingUser:
		return harness.HostRelayPending, true
	case types.RelayRejected, types.RelayExpired, types.RelayCancelled,
		types.RelayUnavailable, types.RelayDelivered, types.RelayUncertain:
		return harness.HostRelayResolved, true
	case types.RelayReady, types.RelayAuthorized, types.RelayReserved,
		types.RelayDispatching:
		return harness.HostRelayChanged, true
	default:
		return "", false
	}
}

// HostRelayEvent refreshes the host presentation channel from the
// authoritative relay row. It verifies the relay belongs to the same
// authenticated agent as the supplied host session and emits public
// metadata only. The `sequence` parameter is correlation metadata;
// the broker derives its own monotonic event sequence from the relay
// revision (SP-23).
func (s *Service) HostRelayEvent(agent, relayID string, session *types.HostSession, sequence uint64) (*harness.HostEvent, error) {
	if session == nil {
		return nil, errors.New("missing host session")
	}
	if err := s.requireRelayHostSession(agent, relayID, session); err != nil {
		return nil, err
	}
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, errors.New("unknown relay request")
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
			// Preserve the committed dispatch truth; outcome will overlay.
		}
	}
	kind, ok := relayHostState(state)
	if !ok {
		return nil, fmt.Errorf("unsupported relay state")
	}
	// SP-23: the broker owns the event sequence. The caller-supplied
	// sequence is correlation metadata only — the broker derives its own
	// monotonic value from the relay revision, ensuring reconnection
	// cursors always reflect the broker's authoritative ordering.
	return &harness.HostEvent{
		Type:       kind,
		RequestID:  r.ID,
		SessionID:  session.ID,
		Sequence:   r.Revision,
		State:      state,
		Revision:   r.Revision,
		OccurredAt: now,
	}, nil
}

// HostRelayReview returns the complete trusted review DTO for a host UI.
// Sensitive bytes do not exist in relay state; this function therefore
// cannot return one. The agent principal is displayed as broker-derived
// requester metadata, and purpose is marked untrusted.
func (s *Service) HostRelayReview(intakePrincipal, relayID string, session *types.HostSession) (*harness.TrustedReviewDTO, error) {
	if session == nil {
		return nil, errors.New("missing host session")
	}
	if err := s.requireRelayHostSession(session.AgentPrincipal, relayID, session); err != nil {
		return nil, err
	}
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, errors.New("unknown relay request")
	}
	if session.HumanPrincipal != intakePrincipal {
		return nil, errors.New("host session does not bind this relay")
	}
	dest, err := s.db.GetDestination(r.DestinationID)
	if err != nil || dest == nil {
		return nil, errors.New("recipient unavailable")
	}
	// S8: the user must never enter sensitive material against a changed
	// recipient. The later fulfillment CAS is not sufficient because the
	// review itself would already have exposed trusted UI context.
	if metadata.DestDigest(dest) != r.DestDigest || dest.Revision != r.DestRevision {
		return nil, errors.New("recipient changed since request; review refused")
	}
	state := r.State
	now := time.Now()
	if !now.Before(r.ExpiresAt) {
		// SP-13: once external dispatch is committed, deadline expiry
		// cannot retroactively classify the operation as never dispatched.
		switch state {
		case types.RelayAwaitingUser, types.RelayReady, types.RelayAuthorized, types.RelayReserved:
			state = types.RelayExpired
		case types.RelayDispatching:
			// Preserve the committed dispatch truth; the outcome overlay
			// will determine the authoritative final state.
		}
	}
	if state != types.RelayAwaitingUser {
		return nil, errors.New("relay is not awaiting trusted input")
	}
	return &harness.TrustedReviewDTO{
		RequestID:           r.ID,
		RequestRevision:     r.Revision,
		DataKind:            r.DataKind,
		DestinationDigest:   r.DestDigest,
		DestinationRevision: r.DestRevision,
		DestinationID:       dest.ID,
		DestinationName:     dest.Name,
		Endpoint:            dest.Endpoint,
		Action:              "transfer",
		ExpiresAt:           r.ExpiresAt,
		Consumption:         r.Consumption,
		MaxDeliveries:       r.MaxDeliveries,
		Mode:                harness.SecureInputMode(session.InputMode),
		Assurance:           session.Assurance,
		AgentPrincipal:      r.AgentPrincipal,
		HumanPrincipal:      session.HumanPrincipal,
		SessionID:           session.ID,
		ThreadID:            session.ThreadID,
		Purpose:             r.Purpose,
		PurposeUntrusted:    r.Purpose != "",
		TrustedHostRender:   true,
	}, nil
}

// HostRelayNotice returns the versioned payload-free protected-input notice
// for native adapters (CORE-01). Every authorization-relevant field comes
// from the relay row, live destination snapshot, and broker-authenticated
// host session; the agent's purpose text is retained only as untrusted
// annotation and can never overwrite trusted fields.
func (s *Service) HostRelayNotice(intakePrincipal, relayID string, session *types.HostSession) (*harness.ProtectedInputNotice, error) {
	review, err := s.HostRelayReview(intakePrincipal, relayID, session)
	if err != nil {
		return nil, err
	}
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, errors.New("unknown relay request")
	}
	notice := &harness.ProtectedInputNotice{
		Version:          harness.ProtectedInputNoticeSchemaVersion,
		RequestID:        review.RequestID,
		RequestRev:       r.Revision,
		HostSessionID:    session.ID,
		DataKind:         review.DataKind,
		RecipientID:      review.DestinationID,
		RecipientLabel:   review.DestinationName,
		Consumption:      review.Consumption,
		ExpiresAt:        review.ExpiresAt,
		Mode:             review.Mode,
		Assurance:        review.Assurance,
		UntrustedPurpose: review.Purpose,
	}
	if err := notice.Validate(); err != nil {
		return nil, err
	}
	return notice, nil
}

// HostRelayStatus returns the sanitized, payload-free outcome for a relay
// request, bound to the same authenticated host session. It never returns
// credential bytes or recipient wire data.
func (s *Service) HostRelayStatus(agent, relayID string, session *types.HostSession) (*harness.RelayStatus, error) {
	if session == nil {
		return nil, errors.New("missing host session")
	}
	if err := s.requireRelayHostSession(agent, relayID, session); err != nil {
		return nil, err
	}
	r, err := s.db.GetRelay(relayID)
	if err != nil || r == nil {
		return nil, errors.New("unknown relay request")
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
			// Preserve the committed dispatch truth; outcome overlay determines.
		}
	}
	var opState string
	if r.OpID != "" {
		if tr, _ := s.db.GetTransfer(r.OpID); tr != nil {
			opState = string(effectiveStatus(tr.Status, tr.ExpiresAt, now))
			switch opState {
			case types.StatusCompleted:
				state = types.RelayDelivered
			case types.StatusUncertain:
				state = types.RelayUncertain
			case types.StatusFailed:
				state = "failed"
			}
		}
	}
	st := &harness.RelayStatus{
		RequestID:   r.ID,
		State:       state,
		RecipientID: r.DestinationID,
		Consumption: r.Consumption,
		ExpiresAt:   r.ExpiresAt,
	}
	if r.OpID != "" {
		st.OperationID = r.OpID
	}
	if r.MaxDeliveries > 0 {
		rem := int64(r.MaxDeliveries) - int64(r.UsedDeliveries)
		if rem < 0 {
			rem = 0
		}
		st.RemainingDeliveries = &rem
	}
	// S9: reusable and bounded grants must report each per-operation
	// delivery, not let the latest relay op column stand in for concurrent
	// or repeated use. Records are payload-free and bounded.
	if r.Consumption != types.RelaySingleDispatch {
		rows, err := s.db.ListRelayDeliveries(r.ID, 50)
		if err != nil {
			return nil, err
		}
		deliveries := make([]harness.RelayDeliveryStatus, 0, len(rows))
		for _, row := range rows {
			d := harness.RelayDeliveryStatus{
				OperationID: row.OperationID,
				State:       row.State,
				Outcome:     row.TerminalOutcome,
				CreatedAt:   row.CreatedAt,
				CompletedAt: row.CompletedAt,
			}
			deliveries = append(deliveries, d)
		}
		st.Deliveries = deliveries
	}
	return st, nil
}

// requireRelayHostSession enforces the exact persisted association between
// one relay and one broker-issued host session. Principal equality is
// necessary but never sufficient (S2).
func (s *Service) requireRelayHostSession(agent, relayID string, session *types.HostSession) error {
	if agent == "" || relayID == "" || session == nil || session.ID == "" {
		return errors.New("missing relay host binding")
	}
	b, err := s.db.GetRelayHostSession(relayID)
	if err != nil {
		return err
	}
	if b == nil || b.SessionID != session.ID || b.AgentPrincipal != agent ||
		b.HumanPrincipal != session.HumanPrincipal || b.HostKind != session.HostKind ||
		session.AgentPrincipal != agent {
		return errors.New("relay and host session bind to different agents")
	}
	return nil
}
