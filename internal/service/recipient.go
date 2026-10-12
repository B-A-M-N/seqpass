package service

import (
	"context"
	"errors"
	"time"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// RecipientStatus is the reconciliation path for uncertain transfers
// (CV-10, G02). It asks the ORIGINAL recipient — reconstructed from the
// trusted dispatch record, never from the destination's current
// configuration — what happened to one transfer: unknown | received |
// durably_accepted | applied | rejected. Only the submitting principal or
// the operator may ask; other principals learn nothing.
//
// Two bindings make a false reconciliation impossible:
//   - the query goes to the recorded endpoint/identity, so a destination
//     repointed after dispatch cannot answer for the original delivery;
//   - the query pins the recorded payload digest (LookupExact), so a
//     recipient holding a different payload under the same op ID cannot
//     settle it.
//
// When the original recipient cannot be contacted or securely identified,
// reconciliation is UNAVAILABLE — never silently substituted. The response
// carries no secret-derived fingerprint (G01): status + length only.
//
// The answer is the recipient's own report of acceptance/application —
// not an independent external postcondition. SeqPass keeps retry
// authorization: a durably_accepted answer means "do not resend", never
// "the downstream effect happened".
func (s *Service) RecipientStatus(ctx context.Context, principal, opID string, operator bool) (map[string]interface{}, error) {
	if principal == "" {
		return nil, errors.New("missing principal")
	}
	if opID == "" {
		return nil, errors.New("missing operation id")
	}
	tr, err := s.db.GetTransfer(opID)
	if err != nil || tr == nil {
		return nil, errors.New("not found")
	}
	if tr.RequestedBy != principal && !operator {
		return nil, errors.New("access denied")
	}
	rec, err := s.db.GetDispatch(opID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		// Never dispatched: there is no original delivery to ask
		// about. Do not consult the current destination — it may be
		// a different recipient entirely.
		s.audit(opID, "recipient_status_unavailable", principal, tr.DestinationID, "never-dispatched")
		return nil, errors.New("reconciliation unavailable: operation never dispatched")
	}
	dest := &types.Destination{
		ID: tr.DestinationID, Name: rec.DestID, Type: "recipient-socket",
		Endpoint: rec.DestEndpoint,
		ExpectedUID: rec.DestExpectedUID, ExpectedGID: rec.DestExpectedGID,
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := transfer.NewDeliverer().LookupExact(ctx, dest, opID, rec.PayloadDigest)
	if err != nil {
		s.audit(opID, "recipient_status_unavailable", principal, rec.DestID, err.Error())
		return nil, errors.New("reconciliation unavailable: " + err.Error())
	}
	s.audit(opID, "recipient_status_queried", principal, rec.DestID, res.Status)
	return map[string]interface{}{
		"op_id":          opID,
		"destination_id": rec.DestID,
		"status":         res.Status,
		"bytes":          res.Bytes,
	}, nil
}
