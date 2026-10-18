package metadata

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// CreateHostPrincipalBinding atomically provisions a trusted human-to-agent
// association. HostKind scopes the binding so a qualification for one adapter
// kind cannot authorize another. Expiry is mandatory for durable associations.
// SP-09: only one active binding per (human, host_kind) — a second is refused
// so resolution can never be ambiguous.
func (d *DB) CreateHostPrincipalBinding(b *types.HostPrincipalBinding) error {
	if b == nil || b.HumanPrincipal == "" || b.AgentPrincipal == "" || b.HostKind == "" {
		return fmt.Errorf("incomplete host principal binding")
	}
	if b.HumanPrincipal == b.AgentPrincipal {
		return fmt.Errorf("host principal binding must use distinct identities")
	}
	if b.ExpiresAt.IsZero() || !time.Now().Before(b.ExpiresAt) {
		return fmt.Errorf("host principal binding needs a future expiry")
	}
	if b.ExpiresAt.Sub(time.Now()) > 24*time.Hour {
		return fmt.Errorf("host principal binding expiry too far ahead")
	}
	now := time.Now()
	b.Revision = 1
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// SP-09: refuse a second active binding for the same (human, host_kind)
	// so resolution can never be ambiguous. The caller must explicitly
	// revoke the old binding before provisioning a replacement.
	var count int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM host_principal_bindings
		WHERE human_principal = ? AND host_kind = ? AND expires_at > ?`,
		b.HumanPrincipal, b.HostKind, now).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("an active binding already exists for this human and host kind; revoke it first")
	}
	if _, err := tx.Exec(`
		INSERT INTO host_principal_bindings
		(human_principal, agent_principal, host_kind, expires_at, revision, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		b.HumanPrincipal, b.AgentPrincipal, b.HostKind, b.ExpiresAt, b.Revision, now, now); err != nil {
		return err
	}
	if err := writeAuditLogTx(tx, &types.AuditLog{
		OperationID: "", Action: "host_binding_created",
		Actor: "broker", Target: b.HumanPrincipal + "|" + b.AgentPrincipal,
		Outcome: b.HostKind,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveHostPrincipalBinding returns the active agent principal authorized
// for this exact human and host kind, or nil when no valid binding exists.
// SP-09: only one active binding can exist per (human, host_kind) — the
// caller must explicitly renew or replace before another becomes active.
func (d *DB) ResolveHostPrincipalBinding(human, hostKind string, now time.Time) (*types.HostPrincipalBinding, error) {
	if human == "" || hostKind == "" {
		return nil, nil
	}
	row := d.db.QueryRow(`
		SELECT human_principal, agent_principal, host_kind, expires_at, revision
		FROM host_principal_bindings
		WHERE human_principal = ? AND host_kind = ? AND expires_at > ?
		ORDER BY revision DESC LIMIT 1`, human, hostKind, now)
	b := &types.HostPrincipalBinding{}
	err := row.Scan(&b.HumanPrincipal, &b.AgentPrincipal, &b.HostKind, &b.ExpiresAt, &b.Revision)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

// RenewHostPrincipalBinding atomically extends an existing binding's
// expiry. The binding must still be active (not expired) to renew.
func (d *DB) RenewHostPrincipalBinding(human, agent, hostKind string, expiresAt time.Time) error {
	if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
		return fmt.Errorf("renewal needs a future expiry")
	}
	if expiresAt.Sub(time.Now()) > 24*time.Hour {
		return fmt.Errorf("renewal expiry too far ahead")
	}
	now := time.Now()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`
		UPDATE host_principal_bindings
		SET expires_at = ?, updated_at = ?
		WHERE human_principal = ? AND agent_principal = ? AND host_kind = ? AND expires_at > ?`,
		expiresAt, now, human, agent, hostKind, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("active host principal binding not found")
	}
	if err := writeAuditLogTx(tx, &types.AuditLog{
		OperationID: "", Action: "host_binding_renewed",
		Actor: "broker", Target: human + "|" + agent,
		Outcome: hostKind,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeHostPrincipalBinding sets the binding's expiry to the given time
// (normally now), making it immediately inactive. SP-10: revocation takes
// effect for new registrations and for existing sessions on the next auth.
func (d *DB) RevokeHostPrincipalBinding(human, agent, hostKind string) error {
	now := time.Now()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`
		UPDATE host_principal_bindings
		SET expires_at = ?, updated_at = ?
		WHERE human_principal = ? AND agent_principal = ? AND host_kind = ? AND expires_at > ?`,
		now, now, human, agent, hostKind, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("active host principal binding not found")
	}
	if err := writeAuditLogTx(tx, &types.AuditLog{
		OperationID: "", Action: "host_binding_revoked",
		Actor: "broker", Target: human + "|" + agent,
		Outcome: hostKind,
	}); err != nil {
		return err
	}
	return tx.Commit()
}
