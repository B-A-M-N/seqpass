package metadata

import (
	"database/sql"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func (d *DB) CreateSecretRef(sr *types.SecretReference) error {
	if sr.ID == "" {
		sr.ID = generateID()
	}
	now := time.Now()
	if sr.CreatedAt.IsZero() {
		sr.CreatedAt = now
	}
	sr.UpdatedAt = now

	// Mutation + epoch bump commit atomically (C03).
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO secret_refs (id, name, description, owner, binding, created_at, updated_at,
				provision_request_id, record_id, binding_id, reconcile_status, use_once)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, sr.ID, sr.Name, sr.Description, sr.Owner, sr.Binding, sr.CreatedAt, sr.UpdatedAt,
			sr.ProvisionRequestID, sr.RecordID, sr.BindingID, sr.ReconcileStatus, sr.UseOnce)
		return err
	})
	return err
}

// GetSecretRef scans one reference. Legacy databases (schema v4 repair
// path) carry empty provisioning columns: readers stay strict, repaired
// rows read back as plain references (no reconcile status), never as
// unrestricted.
func (d *DB) GetSecretRef(id string) (*types.SecretReference, error) {
	sr := &types.SecretReference{}
	var binding, provisionRequestID, recordID, bindingID, reconcileStatus sql.NullString
	var useOnce sql.NullBool
	err := d.db.QueryRow(`
		SELECT id, name, description, owner, binding, created_at, updated_at,
			provision_request_id, record_id, binding_id, reconcile_status, use_once
		FROM secret_refs WHERE id = ?
	`, id).Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt,
		&provisionRequestID, &recordID, &bindingID, &reconcileStatus, &useOnce)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if binding.Valid {
		sr.Binding = binding.String
	}
	if provisionRequestID.Valid {
		sr.ProvisionRequestID = provisionRequestID.String
	}
	if recordID.Valid {
		sr.RecordID = recordID.String
	}
	if bindingID.Valid {
		sr.BindingID = bindingID.String
	}
	if reconcileStatus.Valid {
		sr.ReconcileStatus = reconcileStatus.String
	}
	if useOnce.Valid {
		sr.UseOnce = useOnce.Bool
	}
	return sr, nil
}

func (d *DB) ListSecretRefs() ([]*types.SecretReference, error) {
	rows, err := d.db.Query(`
		SELECT id, name, description, owner, binding, created_at, updated_at,
			provision_request_id, record_id, binding_id, reconcile_status, use_once
		FROM secret_refs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []*types.SecretReference
	for rows.Next() {
		sr := &types.SecretReference{}
		var binding, provisionRequestID, recordID, bindingID, reconcileStatus sql.NullString
		var useOnce sql.NullBool
		if err := rows.Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt,
			&provisionRequestID, &recordID, &bindingID, &reconcileStatus, &useOnce); err != nil {
			return nil, err
		}
		if binding.Valid {
			sr.Binding = binding.String
		}
		if provisionRequestID.Valid {
			sr.ProvisionRequestID = provisionRequestID.String
		}
		if recordID.Valid {
			sr.RecordID = recordID.String
		}
		if bindingID.Valid {
			sr.BindingID = bindingID.String
		}
		if reconcileStatus.Valid {
			sr.ReconcileStatus = reconcileStatus.String
		}
		if useOnce.Valid {
			sr.UseOnce = useOnce.Bool
		}
		refs = append(refs, sr)
	}
	return refs, rows.Err()
}

// GetSecretRefByProvisionRequest resolves one reference by its durable
// provider request ID (reconciliation lookup).
func (d *DB) GetSecretRefByProvisionRequest(requestID string) (*types.SecretReference, error) {
	var id string
	err := d.db.QueryRow(`SELECT id FROM secret_refs WHERE provision_request_id = ?`, requestID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d.GetSecretRef(id)
}

// UpdateSecretRefProvisionState advances the durable provisioning state of
// one reference (reconcile status, provider identities). Epoch-neutral:
// the provisioning lifecycle is credential-state, not an authorization
// mutation — the resolve grant approval flow (which IS authorization)
// lives on the provider side.
func (d *DB) UpdateSecretRefProvisionState(id, reconcileStatus, recordID, bindingID string) error {
	_, err := d.db.Exec(`
		UPDATE secret_refs
		SET reconcile_status = ?, record_id = ?, binding_id = ?, updated_at = ?
		WHERE id = ?
	`, reconcileStatus, recordID, bindingID, time.Now(), id)
	return err
}

// ConsumeUseOnceSecretRef marks a use-once reference consumed in the SAME
// guarded transaction that returns it for execution: the WHERE clause
// refuses already-consumed refs, so a concurrent second dispatch gets
// zero rows and fails closed.
func (d *DB) ConsumeUseOnceSecretRef(id string) error {
	res, err := d.db.Exec(`UPDATE secret_refs SET reconcile_status = ?, updated_at = ?
		WHERE id = ? AND use_once = 1 AND reconcile_status != ?`,
		types.ProvisionReconcileConsumed, time.Now(), id, types.ProvisionReconcileConsumed)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
