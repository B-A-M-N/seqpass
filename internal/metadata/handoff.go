package metadata

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

var errHandoffTicket = errors.New("handoff ticket authorization failed")

// CreateHandoffTicket stores an opaque locator only after rechecking the
// approved transfer and its pinned recipient inside one transaction.
func (d *DB) CreateHandoffTicket(t *types.HandoffTicket, now time.Time) error {
	if t == nil || t.Version != 1 || t.TicketID == "" || t.Nonce == "" || t.OperationID == "" || t.DestinationID == "" || t.State != "issued" || !t.ExpiresAt.After(now) {
		return errHandoffTicket
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, destID, destDigest string
	var expires time.Time
	var authEpoch int64
	var destRevision int
	if err := tx.QueryRow(`SELECT status,destination_id,expires_at,auth_epoch,dest_digest,dest_revision FROM transfers WHERE id=?`, t.OperationID).Scan(&status, &destID, &expires, &authEpoch, &destDigest, &destRevision); err != nil || status != types.StatusAuthorized || destID != t.DestinationID || !expires.After(now) || t.ExpiresAt.After(expires) {
		return errHandoffTicket
	}
	dest, err := scanDestination(func(args ...interface{}) error {
		return tx.QueryRow(`SELECT id,name,type,endpoint,source_repo,auth_method,allowed_ops,requires_approval,approved_by,revision,expected_uid,expected_gid,handoff_mode,recipient_key_id,recipient_public_key,receipt_key_id,receipt_public_key,issuer_key_id,issuer_public_key,credential_target,created_at,updated_at FROM destinations WHERE id=?`, destID).Scan(args...)
	})
	if err != nil || dest == nil || dest.ExpectedUID == nil || *dest.ExpectedUID != t.RecipientUID || dest.HandoffMode != types.HandoffRecipientPull || dest.Revision != destRevision || DestDigest(dest) != destDigest {
		return errHandoffTicket
	}
	var epoch int64
	if err := tx.QueryRow(`SELECT epoch FROM authorization_state WHERE id=1`).Scan(&epoch); err != nil || epoch != authEpoch {
		return errHandoffTicket
	}
	res, err := tx.Exec(`UPDATE handoff_tickets SET ticket_id=?,nonce=?,destination_id=?,recipient_uid=?,issued_at=?,expires_at=?,state='issued' WHERE operation_id=? AND state IN ('issued','expired') AND (state='expired' OR expires_at<=?)`, t.TicketID, t.Nonce, t.DestinationID, t.RecipientUID, t.IssuedAt, t.ExpiresAt, t.OperationID, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		if _, err := tx.Exec(`INSERT INTO handoff_tickets(ticket_id,nonce,operation_id,destination_id,recipient_uid,issued_at,expires_at,state) VALUES(?,?,?,?,?,?,?,'issued')`, t.TicketID, t.Nonce, t.OperationID, t.DestinationID, t.RecipientUID, t.IssuedAt, t.ExpiresAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ClaimHandoffTicket atomically consumes a ticket for its registered UID.
func (d *DB) ClaimHandoffTicket(id, nonce string, uid uint32, now time.Time) (*types.HandoffTicket, error) {
	if id == "" || nonce == "" {
		return nil, errHandoffTicket
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	t := &types.HandoffTicket{}
	var recipient int64
	err = tx.QueryRow(`SELECT ticket_id,nonce,operation_id,destination_id,recipient_uid,issued_at,expires_at,state FROM handoff_tickets WHERE ticket_id=?`, id).Scan(&t.TicketID, &t.Nonce, &t.OperationID, &t.DestinationID, &recipient, &t.IssuedAt, &t.ExpiresAt, &t.State)
	if err != nil || t.State != "issued" || t.Nonce != nonce || !t.ExpiresAt.After(now) || uint32(recipient) != uid {
		return nil, errHandoffTicket
	}
	t.RecipientUID = uint32(recipient)
	var status, destID string
	var opExpiry time.Time
	var epoch int64
	var digest string
	var revision int
	if err = tx.QueryRow(`SELECT status,destination_id,expires_at,auth_epoch,dest_digest,dest_revision FROM transfers WHERE id=?`, t.OperationID).Scan(&status, &destID, &opExpiry, &epoch, &digest, &revision); err != nil || status != types.StatusAuthorized || destID != t.DestinationID || !opExpiry.After(now) {
		return nil, errHandoffTicket
	}
	var currentEpoch int64
	if err = tx.QueryRow(`SELECT epoch FROM authorization_state WHERE id=1`).Scan(&currentEpoch); err != nil || epoch != currentEpoch {
		return nil, errHandoffTicket
	}
	dest, err := scanDestination(func(args ...interface{}) error {
		return tx.QueryRow(`SELECT id,name,type,endpoint,source_repo,auth_method,allowed_ops,requires_approval,approved_by,revision,expected_uid,expected_gid,handoff_mode,recipient_key_id,recipient_public_key,receipt_key_id,receipt_public_key,issuer_key_id,issuer_public_key,credential_target,created_at,updated_at FROM destinations WHERE id=?`, destID).Scan(args...)
	})
	if err != nil || dest == nil || dest.ExpectedUID == nil || *dest.ExpectedUID != uid || dest.HandoffMode != types.HandoffRecipientPull || dest.Revision != revision || DestDigest(dest) != digest {
		return nil, errHandoffTicket
	}
	res, err := tx.Exec(`UPDATE handoff_tickets SET state='claimed' WHERE ticket_id=? AND state='issued' AND expires_at>?`, id, now)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil, errHandoffTicket
	}
	t.State = "claimed"
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

// ReconcileHandoffTickets repairs only states whose dispatch evidence proves
// the recipient did not receive a credential. A claimed ticket with no
// dispatch record and a still-authorized transfer is made retryable with its
// original deadline and nonce. Once dispatch is durable, recovery is
// uncertain and the ticket is never reissued.
func (d *DB) ReconcileHandoffTickets(now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Expiry is terminal and takes precedence over retry eligibility.
	if _, err := tx.Exec(`UPDATE handoff_tickets SET state='expired'
		WHERE state='claimed' AND (expires_at<=? OR EXISTS(
			SELECT 1 FROM transfers t WHERE t.id=operation_id AND t.expires_at<=?))`, now, now); err != nil {
		return err
	}
	// Reopen a terminal pre-dispatch orphan only when startup reconciliation
	// marked its attempt orphaned, the same approval epoch is still active,
	// the operation remains in TTL, and no dispatch evidence exists.
	if _, err := tx.Exec(`UPDATE transfers SET status='authorized',completed_at=NULL,revision=revision+1
		WHERE status='failed' AND expires_at>? AND auth_epoch=(SELECT epoch FROM authorization_state WHERE id=1)
		AND EXISTS(SELECT 1 FROM handoff_tickets h WHERE h.operation_id=transfers.id AND h.state='claimed')
		AND EXISTS(SELECT 1 FROM execution_attempts e WHERE e.op_id=transfers.id AND e.op_type='transfer' AND e.outcome='orphaned')
		AND NOT EXISTS(SELECT 1 FROM dispatch_records d WHERE d.op_id=transfers.id)`, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE handoff_tickets SET state='issued'
		WHERE state='claimed' AND expires_at>? AND EXISTS(
			SELECT 1 FROM transfers t JOIN authorization_state a ON a.id=1
			WHERE t.id=operation_id AND t.status='authorized' AND t.expires_at>? AND t.auth_epoch=a.epoch)
		AND NOT EXISTS(SELECT 1 FROM dispatch_records d WHERE d.op_id=operation_id)`, now, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE handoff_tickets SET state='uncertain'
		WHERE state='claimed' AND EXISTS(
			SELECT 1 FROM transfers t JOIN dispatch_records d ON d.op_id=t.id
			WHERE t.id=operation_id AND t.status='uncertain')`); err != nil {
		return err
	}
	// Every other terminal or stale claim is closed without implying delivery.
	if _, err := tx.Exec(`UPDATE handoff_tickets SET state='rejected'
		WHERE state='claimed' AND NOT EXISTS(
			SELECT 1 FROM transfers t JOIN authorization_state a ON a.id=1
			WHERE t.id=operation_id AND t.status='authorized' AND t.expires_at>? AND t.auth_epoch=a.epoch)
		AND NOT EXISTS(SELECT 1 FROM dispatch_records d WHERE d.op_id=operation_id)`, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) SetHandoffTicketState(operationID, state string) error {
	switch state {
	case "claimed", "applied", "rejected", "uncertain", "expired":
	default:
		return errHandoffTicket
	}
	_, err := d.db.Exec(`UPDATE handoff_tickets SET state=? WHERE operation_id=? AND state IN ('issued','claimed','uncertain')`, state, operationID)
	return err
}

// HandoffReceiptPin closes the destination-rotation race for an offline
// signed capsule receipt. The current target and receipt key must still match
// the immutable destination snapshot that authorized issuance.
type HandoffReceiptPin struct {
	DestinationID string
	Revision      int
	Digest        string
	ReceiptKeyID  string
}

// ReconcileHandoff settles a recipient-pull dispatch after broker restart.
// The caller must present the pinned UID and exact digest recorded before release.
// A non-nil pin adds an atomic destination-revision check for couriered receipts.
func (d *DB) ReconcileHandoff(operationID string, uid uint32, digest, state string, byteCount int, now time.Time, pin *HandoffReceiptPin) error {
	if operationID == "" || digest == "" || byteCount <= 0 || byteCount > 1<<20 || (state != "applied" && state != "rejected") {
		return errHandoffTicket
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expected uint32
	var storedDigest, attemptID, destID string
	var storedBytes int
	var handoffMode string
	if err = tx.QueryRow(`SELECT dest_id,dest_expected_uid,payload_digest,payload_bytes,handoff_mode,attempt_id FROM dispatch_records WHERE op_id=?`, operationID).Scan(&destID, &expected, &storedDigest, &storedBytes, &handoffMode, &attemptID); err != nil || expected != uid || storedDigest != digest || storedBytes != byteCount || (handoffMode != string(types.HandoffRecipientPull) && handoffMode != string(types.HandoffSealedCapsule)) || (handoffMode == string(types.HandoffRecipientPull) && byteCount > 512*1024) {
		return errHandoffTicket
	}
	if pin != nil {
		if handoffMode != string(types.HandoffSealedCapsule) || pin.DestinationID != destID || pin.Revision <= 0 || pin.Digest == "" || pin.ReceiptKeyID == "" {
			return errHandoffTicket
		}
		dest, scanErr := scanDestination(func(args ...interface{}) error {
			return tx.QueryRow(`SELECT id,name,type,endpoint,source_repo,auth_method,allowed_ops,requires_approval,approved_by,revision,expected_uid,expected_gid,handoff_mode,recipient_key_id,recipient_public_key,receipt_key_id,receipt_public_key,issuer_key_id,issuer_public_key,credential_target,created_at,updated_at FROM destinations WHERE id=?`, destID).Scan(args...)
		})
		if scanErr != nil || dest == nil || dest.Revision != pin.Revision || dest.ReceiptKeyID != pin.ReceiptKeyID || DestDigest(dest) != pin.Digest {
			return errHandoffTicket
		}
	}
	var status string
	if err = tx.QueryRow(`SELECT status FROM transfers WHERE id=?`, operationID).Scan(&status); err != nil || status != types.StatusUncertain {
		return errHandoffTicket
	}
	final, resultType := types.StatusCompleted, "handoff"
	if state == "rejected" {
		final, resultType = types.StatusFailed, ""
	}
	if state == "applied" {
		raw, e := json.Marshal(map[string]interface{}{"state": "applied", "bytes": byteCount})
		if e != nil || len(raw) > maxReceiptBytes {
			return errHandoffTicket
		}
		if _, e = tx.Exec(`INSERT INTO op_receipts(op_id,op_type,status,result_type,result_json,completed_at) VALUES(?, 'transfer','completed',?,?,?) ON CONFLICT(op_id) DO UPDATE SET status='completed',result_type=excluded.result_type,result_json=excluded.result_json,completed_at=excluded.completed_at`, operationID, resultType, string(raw), now); e != nil {
			return e
		}
	}
	res, err := tx.Exec(`UPDATE execution_attempts SET outcome=?,finished_at=? WHERE id=? AND op_id=? AND op_type='transfer' AND outcome IN ('orphaned','uncertain')`, final, now, attemptID, operationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errHandoffTicket
	}
	res, err = tx.Exec(`UPDATE transfers SET status=?,completed_at=?,revision=revision+1 WHERE id=? AND status='uncertain'`, final, now, operationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errHandoffTicket
	}
	ticketState := state
	if _, err = tx.Exec(`UPDATE handoff_tickets SET state=? WHERE operation_id=? AND state IN ('claimed','uncertain')`, ticketState, operationID); err != nil {
		return err
	}
	return tx.Commit()
}
