package metadata

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// CreateRelayHostSession atomically attaches one pending relay to one
// exact broker-issued host session. It validates that the relay and
// session belong to the same authenticated agent, that the session is
// live and unexpired, and that the relay has not already been claimed.
// SP-12: the relay deadline is validated inside this transaction —
// an expired relay can never be bound to a host session, even when the
// lifecycle sweep has not yet run.
func (d *DB) CreateRelayHostSession(relayID, sessionID, agentPrincipal string, now time.Time) error {
	if relayID == "" || sessionID == "" || agentPrincipal == "" {
		return fmt.Errorf("missing relay, session, or agent principal")
	}
	if !strings.HasPrefix(relayID, "req-") {
		return fmt.Errorf("invalid relay ID")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }

	var relayAgent, sessionAgent, sessionHuman, hostKind, state string
	var relayExpires, sessionExpires time.Time
	err = tx.QueryRow(`
		SELECT r.agent_principal, h.agent_principal, h.human_principal, h.host_kind,
		       r.state, r.expires_at, h.expires_at
		FROM relay_requests r JOIN host_sessions h ON h.id = ?
		WHERE r.id = ?`, sessionID, relayID).Scan(
		&relayAgent, &sessionAgent, &sessionHuman, &hostKind,
		&state, &relayExpires, &sessionExpires)
	if err != nil {
		rollback()
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay or host session")
		}
		return err
	}
	if relayAgent != agentPrincipal || sessionAgent != agentPrincipal {
		rollback()
		return fmt.Errorf("relay and host session bind to different agents")
	}
	if state != types.RelayAwaitingUser {
		rollback()
		return fmt.Errorf("relay is not claimable")
	}
	// SP-12: validate both deadlines inside the association transaction.
	// A relay whose deadline has already passed must never be bound, even
	// if the lifecycle sweep has not yet processed it.
	if !now.Before(relayExpires) {
		rollback()
		return fmt.Errorf("relay expired")
	}
	if !now.Before(sessionExpires) {
		rollback()
		return fmt.Errorf("host session expired")
	}
	if _, err := tx.Exec(`
		INSERT INTO relay_host_sessions
		(relay_id, session_id, agent_principal, human_principal, host_kind, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		relayID, sessionID, agentPrincipal, sessionHuman, hostKind, now); err != nil {
		rollback()
		if isUniqueConflict(err) {
			return fmt.Errorf("relay already bound to another host session")
		}
		return err
	}
	if err := writeAuditLogTx(tx, &types.AuditLog{
		OperationID: relayID, Action: "relay_host_session_bound",
		Actor: agentPrincipal, Target: sessionID, Outcome: hostKind,
	}); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

// GetRelayHostSession returns the immutable binding for one relay, or nil.
func (d *DB) GetRelayHostSession(relayID string) (*types.RelayHostSession, error) {
	row := d.db.QueryRow(`
		SELECT relay_id, session_id, agent_principal, human_principal, host_kind, created_at
		FROM relay_host_sessions WHERE relay_id = ?`, relayID)
	b := &types.RelayHostSession{}
	err := row.Scan(&b.RelayID, &b.SessionID, &b.AgentPrincipal, &b.HumanPrincipal, &b.HostKind, &b.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

// ListPendingRelaysForHostSession returns pending relays explicitly bound
// to the exact session. There is no shared-principal fallback.
func (d *DB) ListPendingRelaysForHostSession(sessionID string, limit int) ([]*types.RelayRecord, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("missing host session")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := d.db.Query(`
		SELECT r.id, r.agent_principal, r.intake_owner, r.destination_id,
		       r.dest_revision, r.dest_digest, r.data_kind, r.purpose, r.state,
		       r.consumption, r.max_deliveries, r.used_deliveries, r.expires_at,
		       r.revision, r.op_id, r.created_at, r.updated_at
		FROM relay_requests r
		JOIN relay_host_sessions b ON b.relay_id = r.id
		WHERE b.session_id = ? AND r.state = ? AND r.expires_at > ?
		ORDER BY r.created_at ASC LIMIT ?`,
		sessionID, types.RelayAwaitingUser, time.Now(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*types.RelayRecord, 0)
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func isUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint failed") || strings.Contains(s, "constraint failed")
}

// ReassignRelayHostSession atomically moves an unclaimed relay from one
// expired or abandoned host session to a new live session with the same
// human and agent principals (SP-24). The relay must still be awaiting
// user input and must not already be bound to the new session. This is a
// deliberate operator action, not an automatic fallback.
func (d *DB) ReassignRelayHostSession(relayID, oldSessionID, newSessionID string) error {
	if relayID == "" || oldSessionID == "" || newSessionID == "" {
		return fmt.Errorf("missing relay or session ID")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now()

	// Verify the old binding exists and points to the old session.
	var boundSession, agentPrincipal string
	err = tx.QueryRow(`
		SELECT session_id, agent_principal FROM relay_host_sessions
		WHERE relay_id = ?`, relayID).Scan(&boundSession, &agentPrincipal)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("relay is not bound to any host session")
		}
		return err
	}
	if boundSession != oldSessionID {
		return fmt.Errorf("relay is not bound to the specified old session")
	}

	// Verify the new session is live, same agent, same human.
	var newAgent, newHuman, newKind string
	var newExpires time.Time
	err = tx.QueryRow(`
		SELECT agent_principal, human_principal, host_kind, expires_at
		FROM host_sessions WHERE id = ?`, newSessionID).Scan(
		&newAgent, &newHuman, &newKind, &newExpires)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("new host session not found")
		}
		return err
	}
	if !now.Before(newExpires) {
		return fmt.Errorf("new host session is expired")
	}

	// Verify the relay is still awaiting user input and not expired.
	var relayState string
	var relayExpires time.Time
	err = tx.QueryRow(`
		SELECT state, expires_at FROM relay_requests WHERE id = ?`, relayID).Scan(
		&relayState, &relayExpires)
	if err != nil {
		return err
	}
	if relayState != types.RelayAwaitingUser {
		return fmt.Errorf("relay is not reassignable (state=%s)", relayState)
	}
	if !now.Before(relayExpires) {
		return fmt.Errorf("relay has expired")
	}

	// Atomic update of the binding.
	res, err := tx.Exec(`
		UPDATE relay_host_sessions SET session_id = ?, created_at = ?
		WHERE relay_id = ? AND session_id = ?`,
		newSessionID, now, relayID, oldSessionID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("reassignment conflict")
	}
	if err := writeAuditLogTx(tx, &types.AuditLog{
		OperationID: relayID, Action: "relay_host_session_reassigned",
		Actor: agentPrincipal, Target: oldSessionID + "->" + newSessionID,
		Outcome: newKind,
	}); err != nil {
		return err
	}
	return tx.Commit()
}
