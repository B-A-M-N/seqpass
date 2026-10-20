package metadata

import (
	"database/sql"
	"fmt"
	"strings"
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
				provision_request_id, record_id, binding_id, reconcile_status, use_once, request_commitment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, sr.ID, sr.Name, sr.Description, sr.Owner, sr.Binding, sr.CreatedAt, sr.UpdatedAt,
			sr.ProvisionRequestID, sr.RecordID, sr.BindingID, sr.ReconcileStatus, sr.UseOnce, sr.RequestCommitment)
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
	var binding, provisionRequestID, recordID, bindingID, reconcileStatus, requestCommitment sql.NullString
	var useOnce sql.NullBool
	err := d.db.QueryRow(`
		SELECT id, name, description, owner, binding, created_at, updated_at,
			provision_request_id, record_id, binding_id, reconcile_status, use_once, request_commitment
		FROM secret_refs WHERE id = ?
	`, id).Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt,
		&provisionRequestID, &recordID, &bindingID, &reconcileStatus, &useOnce, &requestCommitment)
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
	if requestCommitment.Valid {
		sr.RequestCommitment = requestCommitment.String
	}
	if useOnce.Valid {
		sr.UseOnce = useOnce.Bool
	}
	return sr, nil
}

func (d *DB) ListSecretRefs() ([]*types.SecretReference, error) {
	rows, err := d.db.Query(`
		SELECT id, name, description, owner, binding, created_at, updated_at,
			provision_request_id, record_id, binding_id, reconcile_status, use_once, request_commitment
		FROM secret_refs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []*types.SecretReference
	for rows.Next() {
		sr := &types.SecretReference{}
		var binding, provisionRequestID, recordID, bindingID, reconcileStatus, requestCommitment sql.NullString
		var useOnce sql.NullBool
		if err := rows.Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt,
			&provisionRequestID, &recordID, &bindingID, &reconcileStatus, &useOnce, &requestCommitment); err != nil {
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
		if requestCommitment.Valid {
			sr.RequestCommitment = requestCommitment.String
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
//
// Identity safety: this unconditional form is valid ONLY for callers that
// have verified the reference has no stable provider identity yet. Once
// RecordID/BindingID are established they are immutable — use
// TransitionSecretRefProvisionState, whose atomic WHERE clause enforces
// the expected prior state and identity, or MarkSecretRefIdentityConflict
// for divergences.
func (d *DB) UpdateSecretRefProvisionState(id, reconcileStatus, recordID, bindingID string) error {
	_, err := d.db.Exec(`
		UPDATE secret_refs
		SET reconcile_status = ?, record_id = ?, binding_id = ?, updated_at = ?
		WHERE id = ?
	`, reconcileStatus, recordID, bindingID, time.Now(), id)
	return err
}

// TransitionSecretRefProvisionState is the expected-state atomic
// transition for the provisioning lifecycle. It moves reconcile_status to
// newStatus ONLY when:
//   - the stored reconcile_status is one of expectedStatuses, and
//   - the identity clause holds:
//     requireEmptyIdentity=true → the stable identity columns are still
//     empty (FIRST assignment only), or
//     requireEmptyIdentity=false → the stored identity equals the
//     caller-provided recordID/bindingID (an identity CAS: a concurrent
//     or divergent identity yields zero rows).
//
// Zero rows is a definitive "transition refused" — the caller must re-read
// the durable state and treat an identity mismatch as a conflict, never
// overwrite. This is what makes concurrent status updates unable to
// replace a committed identity.
func (d *DB) TransitionSecretRefProvisionState(id, newStatus, recordID, bindingID string, requireEmptyIdentity bool, expectedStatuses ...string) (bool, error) {
	if len(expectedStatuses) == 0 {
		return false, fmt.Errorf("transition requires at least one expected status")
	}
	placeholders := strings.Repeat("?,", len(expectedStatuses))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]interface{}, 0, len(expectedStatuses)+5)
	args = append(args, newStatus, time.Now(), id)
	for _, st := range expectedStatuses {
		args = append(args, st)
	}
	identityClause := `(record_id IS NULL OR record_id = '') AND (binding_id IS NULL OR binding_id = '')`
	if !requireEmptyIdentity {
		identityClause = `IFNULL(record_id, '') = ? AND IFNULL(binding_id, '') = ?`
	}
	args = args[:0]
	args = append(args, newStatus, recordID, bindingID, time.Now(), id)
	for _, st := range expectedStatuses {
		args = append(args, st)
	}
	if !requireEmptyIdentity {
		args = append(args, recordID, bindingID)
	}
	q := `UPDATE secret_refs SET reconcile_status = ?, record_id = ?, binding_id = ?, updated_at = ?
		WHERE id = ? AND reconcile_status IN (` + placeholders + `) AND ` + identityClause
	res, err := d.db.Exec(q, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// MarkSecretRefIdentityConflict records a durable identity divergence
// WITHOUT touching the stable identity columns: the original pins are
// preserved as the anchor the operator reconciles against. Refuses to
// downgrade a reference that is already consumed (its lifecycle ended
// decisively; the audit trail holds the outcome).
func (d *DB) MarkSecretRefIdentityConflict(id string) (bool, error) {
	res, err := d.db.Exec(`
		UPDATE secret_refs
		SET reconcile_status = ?, updated_at = ?
		WHERE id = ? AND reconcile_status != ?
	`, types.ProvisionReconcileIdentityConflict, time.Now(), id, types.ProvisionReconcileConsumed)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
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
