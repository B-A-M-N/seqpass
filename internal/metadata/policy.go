package metadata

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func (d *DB) CreatePolicy(p *types.Policy) error {
	if p.ID == "" {
		p.ID = generateID()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.Revision == 0 {
		p.Revision = 1
	}

	for _, r := range p.Rules {
		if err := types.ValidateRule(r); err != nil {
			return fmt.Errorf("invalid rule: %w", err)
		}
	}
	rules, _ := json.Marshal(p.Rules)

	// Mutation + epoch bump commit atomically (C03).
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO policies (id, name, rules, priority, enabled, revision, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, p.ID, p.Name, string(rules), p.Priority, p.Enabled, p.Revision, p.CreatedAt, p.UpdatedAt)
		return err
	})
	return err
}

// SetPolicyEnabled enables/disables a policy and bumps the epoch, revoking
// outstanding approvals bound to the prior epoch.
func (d *DB) SetPolicyEnabled(id string, enabled bool) error {
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		res, err := tx.Exec(`
			UPDATE policies SET enabled = ?, revision = revision + 1, updated_at = ? WHERE id = ?
		`, enabled, time.Now(), id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("policy not found")
		}
		return nil
	})
	return err
}

func (d *DB) ListPolicies() ([]*types.Policy, error) {
	rows, err := d.db.Query(`
		SELECT id, name, rules, priority, enabled, revision, created_at, updated_at
		FROM policies ORDER BY priority DESC, created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*types.Policy
	for rows.Next() {
		p := &types.Policy{}
		var rules string
		if err := rows.Scan(&p.ID, &p.Name, &rules, &p.Priority, &p.Enabled, &p.Revision, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		// Load-time validation (SC-10): evaluated rules must satisfy the
		// same schema as creation. Malformed JSON or a rule the current
		// schema rejects fails the whole load (fail closed) rather than
		// being evaluated under legacy wildcard semantics.
		if err := json.Unmarshal([]byte(rules), &p.Rules); err != nil {
			return nil, fmt.Errorf("policy %s has malformed rules: %w", p.ID, err)
		}
		for _, r := range p.Rules {
			if err := types.ValidateRule(r); err != nil {
				return nil, fmt.Errorf("policy %s has invalid rule: %w", p.ID, err)
			}
		}
		policies = append(policies, p)
	}
	return policies, nil
}
