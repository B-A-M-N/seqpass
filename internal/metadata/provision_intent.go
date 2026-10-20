package metadata

// Durable save_and_use continuation records (P0-B). The intent is the
// user's RECORDED workflow: operation, destination, parameters, request
// identity and principal — persisted at save time, BEFORE any approval.
// The continuation (service layer) converts a pending intent into an
// ordinary pending use request via SubmitUse; nothing here executes or
// authorizes anything. All state changes are expected-state CAS updates:
// a repeated or concurrent continuation can never duplicate a submitted
// dispatch (op_id anchors the single use request).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// ErrIntentStateConflict marks a CAS refusal: the intent moved past the
// expected state (a concurrent or recovered continuation already acted).
var ErrIntentStateConflict = errors.New("provision use intent already advanced")

// CreateProvisionUseIntent records the intended use durably. One intent
// per provisioning request (UNIQUE anchor): a concurrent second creation
// fails closed instead of duplicating the recorded workflow.
func (d *DB) CreateProvisionUseIntent(it *types.ProvisionUseIntent) error {
	if it.ID == "" {
		it.ID = generateID()
	}
	now := time.Now()
	it.CreatedAt = now
	it.UpdatedAt = now
	if it.State == "" {
		it.State = types.ProvisionUseIntentPending
	}
	params := ""
	if len(it.Params) > 0 {
		raw, err := json.Marshal(it.Params)
		if err != nil {
			return err
		}
		params = string(raw)
	}
	_, err := d.db.Exec(`
		INSERT INTO provision_use_intents
			(id, provision_request_id, ref_id, principal, operation, target, params, op_id, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)
	`, it.ID, it.ProvisionRequestID, it.RefID, it.Principal, it.Operation, it.Target, params, it.State, now, now)
	if err != nil {
		// A UNIQUE violation means the intent already exists: the caller
		// treats the recorded (pre-existing) intent as authoritative.
		return err
	}
	return nil
}

// GetProvisionUseIntentByRequest returns the intent for a provisioning
// request, or nil when none was recorded.
func (d *DB) GetProvisionUseIntentByRequest(requestID string) (*types.ProvisionUseIntent, error) {
	row := d.db.QueryRow(`
		SELECT id, provision_request_id, ref_id, principal, operation, target, params, op_id, state, created_at, updated_at
		FROM provision_use_intents WHERE provision_request_id = ?
	`, requestID)
	return scanProvisionUseIntent(row)
}

// GetProvisionUseIntentByRef returns the intent for a secret reference.
func (d *DB) GetProvisionUseIntentByRef(refID string) (*types.ProvisionUseIntent, error) {
	row := d.db.QueryRow(`
		SELECT id, provision_request_id, ref_id, principal, operation, target, params, op_id, state, created_at, updated_at
		FROM provision_use_intents WHERE ref_id = ?
	`, refID)
	return scanProvisionUseIntent(row)
}

func scanProvisionUseIntent(row *sql.Row) (*types.ProvisionUseIntent, error) {
	it := &types.ProvisionUseIntent{}
	var target, params, opID, state sql.NullString
	var createdAt, updatedAt sql.NullTime
	err := row.Scan(&it.ID, &it.ProvisionRequestID, &it.RefID, &it.Principal, &it.Operation,
		&target, &params, &opID, &state, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	it.Target, it.OpID, it.State = target.String, opID.String, state.String
	if createdAt.Valid {
		it.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		it.UpdatedAt = updatedAt.Time
	}
	if params.String != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(params.String), &m); err == nil {
			it.Params = m
		}
	}
	return it, nil
}

// TakeProvisionUseIntent atomically claims a pending intent for
// submission: pending → submitted with the durable use-request ID in the
// SAME guarded UPDATE. Zero rows = the intent already advanced (a
// recovered continuation submitted it) — the caller must NOT create a
// second use request.
func (d *DB) TakeProvisionUseIntent(id, opID string) (bool, error) {
	if opID == "" {
		return false, errors.New("intent submission requires a use request ID")
	}
	res, err := d.db.Exec(`
		UPDATE provision_use_intents
		SET state = ?, op_id = ?, updated_at = ?
		WHERE id = ? AND state = ? AND op_id = ''
	`, types.ProvisionUseIntentSubmitted, opID, time.Now(), id, types.ProvisionUseIntentPending)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// AdvanceProvisionUseIntent moves a submitted intent to its terminal
// state, mirroring the use request's durable outcome. Refuses to
// overwrite a terminal state (idempotent continuation re-reports).
func (d *DB) AdvanceProvisionUseIntent(id, state string) (bool, error) {
	switch state {
	case types.ProvisionUseIntentCompleted, types.ProvisionUseIntentFailed, types.ProvisionUseIntentBlocked:
	default:
		return false, errors.New("invalid terminal intent state")
	}
	res, err := d.db.Exec(`
		UPDATE provision_use_intents
		SET state = ?, updated_at = ?
		WHERE id = ? AND state IN (?, ?)
	`, state, time.Now(), id, types.ProvisionUseIntentPending, types.ProvisionUseIntentSubmitted)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// CountUseRequestsByRef counts the durable use requests recorded against
// a secret reference. The continuation tests assert the exactly-one (or
// none) invariant of the recorded save_and_use workflow with it.
func (d *DB) CountUseRequestsByRef(refID string) (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM uses WHERE secret_ref = ?`, refID).Scan(&n)
	return n, err
}
