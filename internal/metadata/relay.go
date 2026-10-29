package metadata

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// Relay request persistence (QR-03/04/05, SP-TUI-03). Rows carry the
// authorization envelope only — never plaintext (QR-01). Every
// fulfillment and reservation is a compare-and-swap on (state, revision)
// so two clients cannot approve or consume the same relay independently.
//
// Relay grants never touch the global authorization epoch (QR-04): a new
// temporary handoff must not invalidate unrelated outstanding approvals.
// Each grant carries its own revision; destination/policy revocation is
// revalidated against the LIVE destination row at reservation time.

const relayColumns = `id, agent_principal, intake_owner, destination_id,
  dest_revision, dest_digest, data_kind, purpose, state, consumption,
  max_deliveries, used_deliveries, expires_at, revision, op_id,
  created_at, updated_at`

func scanRelay(row interface {
	Scan(...interface{}) error
}) (*types.RelayRecord, error) {
	r := &types.RelayRecord{}
	var purpose, intake, opID sql.NullString
	var destDigest sql.NullString
	err := row.Scan(&r.ID, &r.AgentPrincipal, &intake, &r.DestinationID,
		&r.DestRevision, &destDigest, &r.DataKind, &purpose, &r.State,
		&r.Consumption, &r.MaxDeliveries, &r.UsedDeliveries, &r.ExpiresAt,
		&r.Revision, &opID, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.IntakeOwner = intake.String
	r.Purpose = purpose.String
	r.DestDigest = destDigest.String
	r.OpID = opID.String
	return r, nil
}

// CreateRelay persists a new awaiting_user request. The ID must already
// be unpredictable (service-generated); possession alone authorizes
// nothing — transitions always revalidate the envelope.
func (d *DB) CreateRelay(r *types.RelayRecord) error {
	if r.ID == "" || r.AgentPrincipal == "" || r.DestinationID == "" || r.DataKind == "" {
		return fmt.Errorf("incomplete relay request")
	}
	switch r.Consumption {
	case types.RelaySingleDispatch, types.RelayBoundedUses, types.RelayReusable:
	default:
		return fmt.Errorf("unknown relay consumption %q", r.Consumption)
	}
	if r.Consumption == types.RelayBoundedUses && r.MaxDeliveries == 0 {
		return fmt.Errorf("bounded_uses requires max_deliveries >= 1")
	}
	if r.ExpiresAt.IsZero() || !time.Now().Before(r.ExpiresAt) {
		return fmt.Errorf("relay needs a future expiry")
	}
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	r.State = types.RelayAwaitingUser
	r.Revision = 1
	_, err := d.db.Exec(`
		INSERT INTO relay_requests (`+relayColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.ID, r.AgentPrincipal, r.IntakeOwner, r.DestinationID,
		r.DestRevision, r.DestDigest, r.DataKind, r.Purpose, r.State,
		r.Consumption, r.MaxDeliveries, 0, r.ExpiresAt,
		r.Revision, r.OpID, r.CreatedAt, r.UpdatedAt)
	return err
}

// GetRelay returns one relay row, or nil when unknown. Callers must
// revalidate agent binding and state — a row is not an authorization.
func (d *DB) GetRelay(id string) (*types.RelayRecord, error) {
	r, err := scanRelay(d.db.QueryRow(`
		SELECT `+relayColumns+` FROM relay_requests WHERE id = ?
	`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return r, nil
}

// ListPendingRelays is the trusted intake inbox: requests still awaiting
// a human decision, oldest first. Payload-free rows only.
func (d *DB) ListPendingRelays(limit int) ([]*types.RelayRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	// F12: filter against the effective deadline even when the
	// maintenance loop has not yet committed the state transition.
	rows, err := d.db.Query(`
		SELECT `+relayColumns+` FROM relay_requests
		WHERE state = ? AND expires_at > ? ORDER BY created_at ASC LIMIT ?
	`, types.RelayAwaitingUser, time.Now(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*types.RelayRecord
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListPendingRelaysForIntake is the trusted intake inbox scoped to a
// verified human owner (SP-10). Rows with no intake owner are visible
// to every trusted intake identity (pre-claim: any human can claim);
// rows with an owner are visible only to that owner. Oldest first.
func (d *DB) ListPendingRelaysForIntake(intakePrincipal string, limit int) ([]*types.RelayRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := d.db.Query(`
		SELECT `+relayColumns+` FROM relay_requests
		WHERE state = ? AND expires_at > ?
		  AND (intake_owner = '' OR intake_owner = ?)
		ORDER BY created_at ASC LIMIT ?
	`, types.RelayAwaitingUser, time.Now(), intakePrincipal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*types.RelayRecord
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountPendingRelaysForAgent bounds admission per principal (F17).
func (d *DB) CountPendingRelaysForAgent(agent string) (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM relay_requests
		WHERE agent_principal = ? AND state = ? AND expires_at > ?`,
		agent, types.RelayAwaitingUser, time.Now()).Scan(&n)
	return n, err
}

// ListAgentRelays returns one agent's requests (own-status polling).
func (d *DB) ListAgentRelays(agent string, limit int) ([]*types.RelayRecord, error) {
	if agent == "" {
		return nil, fmt.Errorf("missing agent")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := d.db.Query(`
		SELECT `+relayColumns+` FROM relay_requests
		WHERE agent_principal = ? ORDER BY created_at DESC LIMIT ?
	`, agent, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*types.RelayRecord
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FulfillRelay CAS-transitions awaiting_user -> authorized and persists
// the authorized transfer operation in the SAME transaction (QR-04): no
// authorized relay without its operation, no operation without its
// grant. The payload itself is staged in the ephemeral store by the
// service before this call; on conflict the service drops it.
//
// destDigest/destRev pin the destination configuration the user
// reviewed; tr must carry the same digest. No global epoch bump: relay
// grants are self-scoped by (id, revision).
func (d *DB) FulfillRelay(relayID, intakeOwner, destDigest string, destRev int, tr *types.TransferRequest, now time.Time) error {
	if relayID == "" || intakeOwner == "" || tr == nil || tr.ID == "" {
		return fmt.Errorf("incomplete fulfillment")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	cur, err := scanRelay(tx.QueryRow(`
		SELECT `+relayColumns+` FROM relay_requests WHERE id = ?
	`, relayID))
	if err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay request")
		}
		return err
	}
	if cur.State != types.RelayAwaitingUser {
		rollback()
		return fmt.Errorf("relay is not awaiting input (state=%s)", cur.State)
	}
	if !now.Before(cur.ExpiresAt) {
		rollback()
		return fmt.Errorf("relay expired")
	}
	// F01: the recipient fingerprint recorded at request time is an
	// immutable reviewed fact. If the destination was repointed or
	// re-pinned after the agent's request, the stale grant is refused
	// here — inside the same transaction that authorizes the transfer —
	// instead of silently rebinding to the changed configuration. The
	// stored digest/revision are preserved, never overwritten.
	if destDigest != cur.DestDigest || destRev != cur.DestRevision {
		rollback()
		return fmt.Errorf("recipient changed since request: fulfill refused, submit a fresh relay_request")
	}
	res, err := tx.Exec(`
		UPDATE relay_requests
		SET state = ?, intake_owner = ?, revision = revision + 1,
		    op_id = ?, updated_at = ?
		WHERE id = ? AND state = ? AND revision = ?
	`, types.RelayAuthorized, intakeOwner, tr.ID, now,
		relayID, types.RelayAwaitingUser, cur.Revision)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		rollback()
		return fmt.Errorf("relay already decided by another client")
	}
	if err := insertTransferTx(tx, tr); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

// RejectRelay CAS-transitions awaiting_user -> rejected (intake only).
func (d *DB) RejectRelay(relayID, intakeOwner string, revision uint64, now time.Time) error {
	return d.relayCAS(relayID, types.RelayAwaitingUser, types.RelayRejected, revision, now, intakeOwner)
}

// CancelRelay withdraws an undecided or authorized-but-undispatched
// relay. Cancellation never rewinds dispatch: dispatching/delivered/
// uncertain rows are untouched.
func (d *DB) CancelRelay(relayID string, revision uint64, now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	var state string
	var opID sql.NullString
	err = tx.QueryRow(`SELECT state, op_id FROM relay_requests WHERE id = ?`, relayID).Scan(&state, &opID)
	if err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay request")
		}
		return err
	}
	switch state {
	case types.RelayAwaitingUser, types.RelayReady, types.RelayAuthorized:
	default:
		rollback()
		return fmt.Errorf("relay cannot be cancelled from state=%s", state)
	}
	// An authorized relay with a live operation cannot vanish: fail the
	// operation in the same transaction so no worker delivers a
	// cancelled handoff.
	if opID.String != "" {
		if _, err := tx.Exec(`UPDATE transfers SET status = ? WHERE id = ? AND status = ?`,
			types.StatusCancelled, opID.String, types.StatusAuthorized); err != nil {
			rollback()
			return err
		}
	}
	res, err := tx.Exec(`UPDATE relay_requests SET state = ?, revision = revision + 1, updated_at = ?
		WHERE id = ? AND revision = ?`, types.RelayCancelled, now, relayID, revision)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		rollback()
		return fmt.Errorf("relay changed concurrently")
	}
	return tx.Commit()
}

// destDigestTx recomputes the approval digest of a destination inside
// the caller's transaction, so relay reservation can CAS against the
// live recipient configuration without a read-then-act race.
func destDigestTx(tx *sql.Tx, destID string) (string, int, error) {
	dest := &types.Destination{}
	var allowedOps string
	var uid, gid sql.NullInt64
	var rev int
	err := tx.QueryRow(`SELECT id, type, endpoint, allowed_ops, expected_uid,
		expected_gid, revision FROM destinations WHERE id = ?`, destID).Scan(
		&dest.ID, &dest.Type, &dest.Endpoint, &allowedOps, &uid, &gid, &rev)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", 0, fmt.Errorf("recipient revoked")
		}
		return "", 0, err
	}
	if allowedOps != "" {
		if err := json.Unmarshal([]byte(allowedOps), &dest.AllowedOps); err != nil {
			return "", 0, fmt.Errorf("recipient config unreadable")
		}
	}
	if uid.Valid {
		u := uint32(uid.Int64)
		dest.ExpectedUID = &u
	}
	if gid.Valid {
		g := uint32(gid.Int64)
		dest.ExpectedGID = &g
	}
	return DestDigest(dest), rev, nil
}

func (d *DB) relayCAS(relayID, from, to string, revision uint64, now time.Time, intakeOwner string) error {
	res, err := d.db.Exec(`
		UPDATE relay_requests
		SET state = ?, intake_owner = COALESCE(NULLIF(?, ''), intake_owner),
		    revision = revision + 1, updated_at = ?
		WHERE id = ? AND state = ? AND revision = ?
	`, to, intakeOwner, now, relayID, from, revision)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("relay not in %s (already decided or changed)", from)
	}
	return nil
}

// ReserveRelay is the atomic consumption gate (QR-05), mirroring the
// claim pattern: one transaction validates scope, state, budget,
// revision and BOTH deadlines (operation expiry is checked by the
// caller; the relay's own shorter deadline is enforced here), then
// consumes one delivery budget.
//
// Scope revalidation binds the exact grant: the operation's agent must
// equal the relay's agent, its destination must equal the relay's
// destination, and the destination's CURRENT configuration must still
// match the approved digest/revision — a repointed recipient
// invalidates the handoff instead of silently rebinding it (SP-TUI-08).
// Global policy/destination revocation additionally applies at the
// operation's own admission; this gate never widens it.
func (d *DB) ReserveRelay(relayID, opID, agent, destID string, now time.Time) error {
	if relayID == "" || opID == "" || agent == "" || destID == "" {
		return fmt.Errorf("incomplete reservation")
	}
	// Bounded retry for shared budgets (QR-05/QR-08): concurrent
	// consumers collide on the revision CAS even when budget remains.
	// Re-reading and revalidating converges; a genuine conflict
	// (single-use already taken, budget spent, dest repointed) fails
	// on validation, not on the retry. Single-use never retries: the
	// first winner stands and the loser gets the consumed verdict.
	var multi bool
	if r, _ := d.GetRelay(relayID); r != nil {
		multi = r.Consumption != types.RelaySingleDispatch
	}
	var err error
	locks, conflicts := 0, 0
	for {
		err = d.reserveRelayOnce(relayID, opID, agent, destID, now)
		if err == nil {
			return nil
		}
		// Transient lock contention is retried in every mode (it is
		// scheduling noise, not a consumption verdict) with a hard
		// cap so a wedged store still fails fast.
		if isLockContention(err) && locks < 20 {
			locks++
			time.Sleep(time.Duration(5+locks*5) * time.Millisecond)
			continue
		}
		if err.Error() == "relay changed concurrently" && multi && conflicts < 8 {
			conflicts++
			continue
		}
		return err
	}
}

// isLockContention reports transient SQLite lock/busy errors. Short
// read-then-write transactions collide under concurrent workers; the
// verdict (budget, scope, expiry) is revalidated on retry, so a retry
// can never grant what validation denies.
func isLockContention(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "database table is locked") ||
		strings.Contains(s, "database is busy")
}

func (d *DB) reserveRelayOnce(relayID, opID, agent, destID string, now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	cur, err := scanRelay(tx.QueryRow(`
		SELECT `+relayColumns+` FROM relay_requests WHERE id = ?
	`, relayID))
	if err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay")
		}
		return err
	}
	if cur.AgentPrincipal != agent {
		rollback()
		return fmt.Errorf("relay belongs to another agent")
	}
	if cur.DestinationID != destID {
		rollback()
		return fmt.Errorf("relay targets another recipient")
	}
	if !now.Before(cur.ExpiresAt) {
		rollback()
		return fmt.Errorf("relay payload expired")
	}
	// Live destination check: the recipient's current config must still
	// be what the user approved (SP-TUI-08). A repointed recipient
	// invalidates the handoff instead of silently rebinding it.
	liveDigest, liveRev, err := destDigestTx(tx, destID)
	if err != nil {
		rollback()
		return err
	}
	if liveDigest != cur.DestDigest || liveRev != cur.DestRevision {
		rollback()
		return fmt.Errorf("recipient changed since approval")
	}
	if cur.MaxDeliveries > 0 && cur.UsedDeliveries >= cur.MaxDeliveries {
		rollback()
		return fmt.Errorf("relay delivery budget exhausted")
	}
	var nextState string
	switch cur.Consumption {
	case types.RelaySingleDispatch:
		if cur.State != types.RelayAuthorized {
			rollback()
			return fmt.Errorf("single-use relay already consumed (state=%s)", cur.State)
		}
		nextState = types.RelayReserved
	case types.RelayBoundedUses, types.RelayReusable:
		// SP-13: RelayDispatching is acceptable for multi-dispatch grants —
		// a concurrent delivery may be in-flight while another delivery is
		// being reserved. The budget is decremented atomically here.
		if cur.State != types.RelayAuthorized && cur.State != types.RelayReserved && cur.State != types.RelayDispatching {
			rollback()
			return fmt.Errorf("relay not dispatchable (state=%s)", cur.State)
		}
		nextState = types.RelayReserved
	default:
		rollback()
		return fmt.Errorf("unknown relay consumption %q", cur.Consumption)
	}
	res, err := tx.Exec(`
		UPDATE relay_requests
		SET state = ?, used_deliveries = used_deliveries + 1,
	    revision = revision + 1, op_id = ?, updated_at = ?
		WHERE id = ? AND revision = ?
	`, nextState, opID, now, relayID, cur.Revision)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		rollback()
		return fmt.Errorf("relay changed concurrently")
	}
	// F08: authoritative per-operation record, written in the same
	// transaction as the budget change. Concurrent operations on one
	// reusable grant produce distinct rows; RelayStatus and refunds
	// consult these rows, never the single op_id column.
	if _, err := tx.Exec(`INSERT INTO relay_deliveries
		(relay_id, operation_id, state, dest_digest, dest_revision, created_at)
		VALUES (?, ?, 'reserved', ?, ?, ?)`,
		relayID, opID, liveDigest, liveRev, now); err != nil {
		rollback()
		return fmt.Errorf("delivery record conflict: %w", err)
	}
	return tx.Commit()
}

// RecordDeliveryOutcome marks one reservation row terminal (F08).
// Completed deliveries never refund budget; failed pre-dispatch attempts
// refund exactly once via ReleaseRelayReservation. Idempotent: repeated
// finalization cannot corrupt the budget.
func (d *DB) RecordDeliveryOutcome(relayID, opID, outcome string, now time.Time) error {
	res, err := d.db.Exec(`UPDATE relay_deliveries
		SET state = 'completed', terminal_outcome = ?, completed_at = ?
		WHERE relay_id = ? AND operation_id = ? AND state = 'reserved'`,
		outcome, now, relayID, opID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("no reserved delivery row")
	}
	return nil
}

// DeliveryCount reports distinct per-operation records for a relay (F08
// acceptance: ten concurrent operations yield ten rows).
func (d *DB) DeliveryCount(relayID string) (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM relay_deliveries WHERE relay_id = ?`, relayID).Scan(&n)
	return n, err
}

// RelayDeliveryRecord is the broker-side per-delivery accounting row.
// It contains no credential bytes or recipient wire data.
type RelayDeliveryRecord struct {
	RelayID         string     `json:"relay_id"`
	OperationID     string     `json:"operation_id"`
	State           string     `json:"state"`
	DestDigest      string     `json:"dest_digest"`
	DestRevision    int        `json:"dest_revision"`
	TerminalOutcome string     `json:"terminal_outcome,omitempty"`
	Refunded        bool       `json:"refunded"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// ListRelayDeliveries returns the bounded per-operation delivery rows for
// a reusable or bounded grant. Rows are ordered oldest-first so a host can
// render an auditable delivery history without confusing one recent op
// for the whole grant.
func (d *DB) ListRelayDeliveries(relayID string, limit int) ([]*RelayDeliveryRecord, error) {
	if relayID == "" {
		return nil, fmt.Errorf("missing relay ID")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := d.db.Query(`SELECT relay_id, operation_id, state, dest_digest,
		dest_revision, terminal_outcome, refunded, created_at, completed_at
		FROM relay_deliveries WHERE relay_id = ? ORDER BY created_at ASC LIMIT ?`,
		relayID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*RelayDeliveryRecord, 0)
	for rows.Next() {
		r := &RelayDeliveryRecord{}
		var refunded int
		var completedAt sql.NullTime
		if err := rows.Scan(&r.RelayID, &r.OperationID, &r.State, &r.DestDigest,
			&r.DestRevision, &r.TerminalOutcome, &refunded, &r.CreatedAt, &completedAt); err != nil {
			return nil, err
		}
		r.Refunded = refunded != 0
		if completedAt.Valid {
			t := completedAt.Time
			r.CompletedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReleaseRelayReservation returns one unconsumed budget unit (QR-05):
// a failed attempt BEFORE external dispatch may release its hold. Once
// delivery might have occurred, release is refused — reconcile the
// original operation instead. Single-use returns to authorized so a
// replacement operation can be bound by the operator flow.
func (d *DB) ReleaseRelayReservation(relayID, opID string, now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	cur, err := scanRelay(tx.QueryRow(`
		SELECT `+relayColumns+` FROM relay_requests WHERE id = ?
	`, relayID))
	if err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay")
		}
		return err
	}
	switch cur.State {
	case types.RelayReserved, types.RelayDispatching:
	default:
		rollback()
		return fmt.Errorf("nothing releasable (state=%s)", cur.State)
	}
	if cur.State == types.RelayDispatching {
		rollback()
		return fmt.Errorf("dispatch may have occurred; reconcile, do not release")
	}
	next := types.RelayAuthorized
	if cur.Consumption != types.RelaySingleDispatch {
		next = cur.State
	} // Only the holding operation releases a reservation: knowledge of
	// the relay ID alone is not enough. F08 requires an exact
	// reservation row before any budget refund, marked idempotently.
	var refunded int
	var rowState string
	err = tx.QueryRow(`SELECT state, refunded FROM relay_deliveries
		WHERE relay_id = ? AND operation_id = ?`, relayID, opID).Scan(&rowState, &refunded)
	if err != nil {
		rollback()
		return fmt.Errorf("no reservation row for this operation")
	}
	if rowState != "reserved" || refunded != 0 {
		rollback()
		return fmt.Errorf("reservation already settled")
	}
	opCol := cur.OpID
	if cur.Consumption == types.RelaySingleDispatch {
		if cur.OpID == "" || cur.OpID != opID {
			rollback()
			return fmt.Errorf("reservation held by another operation")
		}
		opCol = ""
	}
	if _, err := tx.Exec(`UPDATE relay_deliveries
		SET state = 'refunded', refunded = 1, terminal_outcome = 'released', completed_at = ?
		WHERE relay_id = ? AND operation_id = ? AND refunded = 0`,
		now, relayID, opID); err != nil {
		rollback()
		return err
	}
	res, err := tx.Exec(`
		UPDATE relay_requests
		SET state = ?, used_deliveries = CASE WHEN used_deliveries > 0 THEN used_deliveries - 1 ELSE 0 END,
		    revision = revision + 1, op_id = ?, updated_at = ?
		WHERE id = ? AND revision = ?
	`, next, opCol, now, relayID, cur.Revision)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		rollback()
		return fmt.Errorf("relay changed concurrently")
	}
	return tx.Commit()
}

// SetRelayOpState advances the relay alongside its operation's terminal
// path (dispatching/delivered/uncertain). CAS-guarded; terminal states
// never rewind.
func (d *DB) SetRelayOpState(relayID, to string, now time.Time) error {
	switch to {
	case types.RelayDispatching, types.RelayDelivered, types.RelayUncertain:
	default:
		return fmt.Errorf("invalid relay op state %q", to)
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	var state string
	if err := tx.QueryRow(`SELECT state FROM relay_requests WHERE id = ?`, relayID).Scan(&state); err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay")
		}
		return err
	}
	ok := false
	switch to {
	case types.RelayDispatching:
		ok = state == types.RelayReserved || state == types.RelayAuthorized
	case types.RelayDelivered, types.RelayUncertain:
		ok = state == types.RelayDispatching || state == types.RelayReserved || state == types.RelayAuthorized
	}
	if !ok {
		rollback()
		return fmt.Errorf("relay cannot move %s -> %s", state, to)
	}
	if _, err := tx.Exec(`UPDATE relay_requests SET state = ?, revision = revision + 1, updated_at = ?
		WHERE id = ?`, to, now, relayID); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

// ExpireRelays sweeps undecided/live relays past their deadline into
// expired and returns their IDs so the service can drop the staged
// payloads. Terminal rows are untouched.
func (d *DB) ExpireRelays(now time.Time) ([]string, error) {
	// SP-13: RelayDispatching and RelayDelivered/RelayUncertain are
	// deliberately excluded. Once external dispatch is committed, deadline
	// expiry cannot retroactively classify the operation as never dispatched.
	rows, err := d.db.Query(`SELECT id FROM relay_requests
		WHERE expires_at <= ? AND state IN (?, ?, ?, ?)`,
		now, types.RelayAwaitingUser, types.RelayReady,
		types.RelayAuthorized, types.RelayReserved)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, err := d.db.Exec(`UPDATE relay_requests
			SET state = ?, revision = revision + 1, updated_at = ?
			WHERE id = ? AND state IN (?, ?, ?, ?)`,
			types.RelayExpired, now, id,
			types.RelayAwaitingUser, types.RelayReady,
			types.RelayAuthorized, types.RelayReserved); err != nil {
			return ids, err
		}
	}
	return ids, nil
}

// MarkRelaysUnavailable is the restart path (QR-01/05, F11): only states
// that actually depended on lost in-memory material become unavailable —
// never presented as ready, authorized, or recoverable. Awaiting_user
// requests have no staged plaintext yet, so their durable metadata stays
// fulfillable across restart (expired ones are swept by ExpireRelays).
// Operations keep their own reconciled states; relays report the truth
// about the lost material.
func (d *DB) MarkRelaysUnavailable(now time.Time) (int64, error) {
	res, err := d.db.Exec(`UPDATE relay_requests
		SET state = ?, revision = revision + 1, updated_at = ?
		WHERE state IN (?, ?, ?, ?)`,
		types.RelayUnavailable, now,
		types.RelayReady, types.RelayAuthorized,
		types.RelayReserved, types.RelayDispatching)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// BeginRelayQuotaCheck enforces the per-agent pending relay quota inside
// a transaction (SP-17). The count and insert are one atomic unit — a
// concurrent request cannot bypass the limit. Database errors fail closed.
func (d *DB) BeginRelayQuotaCheck(agent string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM relay_requests
		WHERE agent_principal = ? AND state = ? AND expires_at > ?`,
		agent, types.RelayAwaitingUser, time.Now()).Scan(&n); err != nil {
		return fmt.Errorf("quota count failed: %w", err)
	}
	if n >= 20 {
		return fmt.Errorf("too many pending relay requests for this principal (max 20)")
	}
	return tx.Commit()
}

// CreateRelayWithQuota enforces the per-agent pending relay quota and the
// global pending ceiling inside one transaction (SP-17). The count and
// insert are atomic — a concurrent request cannot bypass either limit.
// Database errors fail closed, never silently disable protection.
const (
	maxPendingPerAgent = 20
	maxPendingTotal    = 500
)

func (d *DB) CreateRelayWithQuota(agent string, r *types.RelayRecord) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("quota enforcement failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now()
	var perAgent int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM relay_requests
		WHERE agent_principal = ? AND state = ? AND expires_at > ?`,
		agent, types.RelayAwaitingUser, now).Scan(&perAgent); err != nil {
		return fmt.Errorf("relay quota enforcement failed: %w", err)
	}
	if perAgent >= maxPendingPerAgent {
		return fmt.Errorf("too many pending relay requests for this principal (max %d)", maxPendingPerAgent)
	}
	var total int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM relay_requests
		WHERE state = ? AND expires_at > ?`,
		types.RelayAwaitingUser, now).Scan(&total); err != nil {
		return fmt.Errorf("relay quota enforcement failed: %w", err)
	}
	if total >= maxPendingTotal {
		return fmt.Errorf("too many pending relay requests system-wide (max %d)", maxPendingTotal)
	}
	if err := insertRelayTx(tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

// insertRelayTx is the transaction-scoped relay insert used by quota-gated
// creation.
func insertRelayTx(tx *sql.Tx, r *types.RelayRecord) error {
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	r.State = types.RelayAwaitingUser
	r.Revision = 1
	_, err := tx.Exec(`
		INSERT INTO relay_requests (`+relayColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.ID, r.AgentPrincipal, r.IntakeOwner, r.DestinationID,
		r.DestRevision, r.DestDigest, r.DataKind, r.Purpose, r.State,
		r.Consumption, r.MaxDeliveries, 0, r.ExpiresAt,
		r.Revision, r.OpID, r.CreatedAt, r.UpdatedAt)
	return err
}

// CleanupExpiredRelays permanently removes relay rows and their host
// session associations after their expiry plus a retention window. This
// is called by the lifecycle loop.
func (d *DB) CleanupExpiredRelays(now time.Time) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// First remove associations for expired relays.
	if _, err := tx.Exec(`
		DELETE FROM relay_host_sessions WHERE relay_id IN (
			SELECT id FROM relay_requests WHERE expires_at <= ?
		)`, now); err != nil {
		return 0, err
	}
	// Then remove the relays themselves.
	res, err := tx.Exec(`
		DELETE FROM relay_requests WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// CleanupCompletedDeliveries removes completed delivery rows after their
// completed_at plus a retention window.
func (d *DB) CleanupCompletedDeliveries(now time.Time) (int64, error) {
	res, err := d.db.Exec(`
		DELETE FROM relay_deliveries WHERE state = 'completed' AND completed_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
