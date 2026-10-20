package metadata

import "time"

// SetSecretRefRequestCommitment writes the keyed request-identity
// commitment directly (P0-D). Production code sets it via
// CreateSecretRef; the test layer uses it to simulate legacy rows.
func (d *DB) SetSecretRefRequestCommitment(id, commitment string) error {
	_, err := d.db.Exec(`UPDATE secret_refs SET request_commitment = ?, updated_at = ? WHERE id = ?`,
		commitment, time.Now(), id)
	return err
}
