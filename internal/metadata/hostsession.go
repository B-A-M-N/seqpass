package metadata

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// HostSession persistence (HI-02). The broker issues the binding; the
// agent never supplies security claims. Thread IDs are correlation
// metadata, not authorization: every transition validates the caller's
// authenticated principal and the broker-held token.
const hostSessionColumns = `id, host_kind, agent_principal, human_principal,
  thread_id, expires_at, revision, created_at, updated_at`

func scanHostSession(row interface {
	Scan(...interface{}) error
}) (*types.HostSession, error) {
	h := &types.HostSession{}
	var thread, human sql.NullString
	err := row.Scan(&h.ID, &h.HostKind, &h.AgentPrincipal, &human, &thread,
		&h.ExpiresAt, &h.Revision, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return nil, err
	}
	h.HumanPrincipal = human.String
	h.ThreadID = thread.String
	return h, nil
}

// CreateHostSession inserts the broker-issued record. Callers establish
// the principal bindings before invoking persistence.
func (d *DB) CreateHostSession(h *types.HostSession) error {
	if h.ID == "" || h.HostKind == "" || h.AgentPrincipal == "" {
		return fmt.Errorf("incomplete host session")
	}
	if h.HumanPrincipal == "" {
		return fmt.Errorf("host session needs an authorized human principal")
	}
	if h.ExpiresAt.IsZero() || !time.Now().Before(h.ExpiresAt) {
		return fmt.Errorf("host session needs a future expiry")
	}
	now := time.Now()
	if h.CreatedAt.IsZero() {
		h.CreatedAt = now
	}
	h.UpdatedAt = now
	h.Revision = 1
	_, err := d.db.Exec(`
		INSERT INTO host_sessions (`+hostSessionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, h.ID, h.HostKind, h.AgentPrincipal, h.HumanPrincipal, h.ThreadID,
		h.ExpiresAt, h.Revision, h.CreatedAt, h.UpdatedAt)
	return err
}

// GetHostSession returns one live-looking session or nil. It does not
// enforce expiry; dispatch must validate both identity and deadline.
func (d *DB) GetHostSession(id string) (*types.HostSession, error) {
	h, err := scanHostSession(d.db.QueryRow(`
		SELECT `+hostSessionColumns+` FROM host_sessions WHERE id = ?
	`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return h, nil
}

// RotateHostSessionToken atomically replaces the bearer token held by
// the trusted native-host adapter. Only the current token can rotate.
func (d *DB) RotateHostSessionToken(sessionID, oldToken, newTokenHash string, expiresAt time.Time) error {
	if sessionID == "" || oldToken == "" || newTokenHash == "" {
		return fmt.Errorf("missing session or token")
	}
	if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
		return fmt.Errorf("host session token needs a future expiry")
	}
	res, err := d.db.Exec(`UPDATE host_session_tokens
		SET token_hash = ?, expires_at = ?, updated_at = ?
		WHERE session_id = ? AND token_hash = ?`,
		newTokenHash, expiresAt, time.Now(), sessionID, oldToken)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("host session token invalid")
	}
	return nil
}

// HostSessionTokenFor returns the active token binding for validation.
func (d *DB) HostSessionTokenFor(sessionID string) (string, time.Time, error) {
	var hash string
	var exp sql.NullTime
	err := d.db.QueryRow(`SELECT token_hash, expires_at FROM host_session_tokens
		WHERE session_id = ?`, sessionID).Scan(&hash, &exp)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", time.Time{}, fmt.Errorf("host session token invalid")
		}
		return "", time.Time{}, err
	}
	if !exp.Valid {
		return "", time.Time{}, fmt.Errorf("host session token expiry missing")
	}
	return hash, exp.Time, nil
}

// CreateHostSessionToken persists the first broker-minted token binding.
// Callers pass only a hash; plaintext never reaches persistence.
func (d *DB) CreateHostSessionToken(sessionID, tokenHash string, expiresAt time.Time) error {
	if sessionID == "" || tokenHash == "" {
		return fmt.Errorf("missing session or token")
	}
	if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
		return fmt.Errorf("host session token needs a future expiry")
	}
	now := time.Now()
	_, err := d.db.Exec(`INSERT INTO host_session_tokens
		(session_id, token_hash, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, sessionID, tokenHash, expiresAt, now, now)
	return err
}

// BindRelayToHostSession enforces that the authenticated agent owns both
// the relay and the host session before attaching public presentation
// metadata to it. It does not alter the relay authorization envelope.
func (d *DB) BindRelayToHostSession(relayID, sessionID, agentPrincipal string) error {
	if relayID == "" || sessionID == "" || agentPrincipal == "" {
		return fmt.Errorf("missing relay, session, or agent principal")
	}
	if !strings.HasPrefix(relayID, "req-") {
		return fmt.Errorf("invalid relay ID")
	}
	var relayAgent, sessionAgent string
	err := d.db.QueryRow(`
		SELECT r.agent_principal, h.agent_principal
		FROM relay_requests r
		JOIN host_sessions h ON h.id = ?
		WHERE r.id = ?`, sessionID, relayID).Scan(&relayAgent, &sessionAgent)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown relay or host session")
		}
		return err
	}
	if relayAgent != agentPrincipal || sessionAgent != agentPrincipal {
		return fmt.Errorf("relay and host session bind to different agents")
	}
	return nil
}
