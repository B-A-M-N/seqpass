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
			INSERT INTO secret_refs (id, name, description, owner, binding, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, sr.ID, sr.Name, sr.Description, sr.Owner, sr.Binding, sr.CreatedAt, sr.UpdatedAt)
		return err
	})
	return err
}

func (d *DB) GetSecretRef(id string) (*types.SecretReference, error) {
	sr := &types.SecretReference{}
	var binding sql.NullString
	err := d.db.QueryRow(`
		SELECT id, name, description, owner, binding, created_at, updated_at
		FROM secret_refs WHERE id = ?
	`, id).Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if binding.Valid {
		sr.Binding = binding.String
	}
	return sr, nil
}

func (d *DB) ListSecretRefs() ([]*types.SecretReference, error) {
	rows, err := d.db.Query(`
		SELECT id, name, description, owner, binding, created_at, updated_at
		FROM secret_refs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []*types.SecretReference
	for rows.Next() {
		sr := &types.SecretReference{}
		var binding sql.NullString
		if err := rows.Scan(&sr.ID, &sr.Name, &sr.Description, &sr.Owner, &binding, &sr.CreatedAt, &sr.UpdatedAt); err != nil {
			return nil, err
		}
		if binding.Valid {
			sr.Binding = binding.String
		}
		refs = append(refs, sr)
	}
	return refs, nil
}
