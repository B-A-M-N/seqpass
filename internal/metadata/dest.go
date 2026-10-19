package metadata

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// DestDigest binds an approval to the exact destination configuration,
// including the pinned recipient identity (C05): changing the expected UID
// or endpoint invalidates outstanding approvals.
func DestDigest(dest *types.Destination) string {
	if dest == nil {
		return ""
	}
	allowedOps, _ := json.Marshal(dest.AllowedOps)
	var uid, gid string
	if dest.ExpectedUID != nil {
		uid = fmt.Sprintf("%d", *dest.ExpectedUID)
	}
	if dest.ExpectedGID != nil {
		gid = fmt.Sprintf("%d", *dest.ExpectedGID)
	}
	h := sha256.Sum256([]byte(dest.ID + "\x00" + dest.Type + "\x00" + dest.Endpoint + "\x00" + dest.SourceRepo + "\x00" + string(allowedOps) + "\x00" + uid + "\x00" + gid))
	return hex.EncodeToString(h[:])
}

func (d *DB) CreateDestination(dest *types.Destination) error {
	if dest.ID == "" {
		dest.ID = generateID()
	}
	now := time.Now()
	if dest.CreatedAt.IsZero() {
		dest.CreatedAt = now
	}
	dest.UpdatedAt = now
	if dest.Revision == 0 {
		dest.Revision = 1
	}

	if dest.Type == "recipient-socket" && dest.ExpectedUID == nil {
		return fmt.Errorf("recipient-socket requires an expected recipient UID")
	}

	allowedOps, _ := json.Marshal(dest.AllowedOps)

	// Mutation + epoch bump commit atomically (C03).
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO destinations (id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, dest.ID, dest.Name, dest.Type, dest.Endpoint, dest.SourceRepo, dest.AuthMethod, string(allowedOps), dest.RequiresApproval, dest.ApprovedBy, dest.Revision, nullableUID(dest.ExpectedUID), nullableUID(dest.ExpectedGID), dest.CreatedAt, dest.UpdatedAt)
		return err
	})
	return err
}

// UpdateDestinationEndpoint changes a destination's endpoint, bumps its
// revision and the global epoch. Outstanding approvals bound to the old
// digest/epoch fail admission (T07).
func (d *DB) UpdateDestinationEndpoint(id, endpoint, approver string) error {
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		res, err := tx.Exec(`
			UPDATE destinations SET endpoint = ?, revision = revision + 1, updated_at = ?, approved_by = ? WHERE id = ?
		`, endpoint, time.Now(), approver, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("destination not found")
		}
		return nil
	})
	return err
}

// UpdateDestinationRecipient re-pins a destination's endpoint and recipient
// identity. Identity changes bump revision + epoch like any other mutation so
// outstanding approvals bound to the old digest fail admission (C05).
func (d *DB) UpdateDestinationRecipient(id, endpoint string, uid, gid *uint32, approver string) error {
	_, err := d.withAuthMutation(func(tx *sql.Tx) error {
		res, err := tx.Exec(`
			UPDATE destinations SET endpoint = ?, expected_uid = ?, expected_gid = ?, revision = revision + 1, updated_at = ?, approved_by = ? WHERE id = ?
		`, endpoint, nullableUID(uid), nullableUID(gid), time.Now(), approver, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("destination not found")
		}
		return nil
	})
	return err
}

func nullableUID(v *uint32) interface{} {
	if v == nil {
		return nil
	}
	return int64(*v)
}

func scanDestination(scan func(...interface{}) error) (*types.Destination, error) {
	dest := &types.Destination{}
	var allowedOps string
	var uid, gid sql.NullInt64
	err := scan(&dest.ID, &dest.Name, &dest.Type, &dest.Endpoint, &dest.SourceRepo, &dest.AuthMethod, &allowedOps, &dest.RequiresApproval, &dest.ApprovedBy, &dest.Revision, &uid, &gid, &dest.CreatedAt, &dest.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		u := uint32(uid.Int64)
		dest.ExpectedUID = &u
	}
	if gid.Valid {
		g := uint32(gid.Int64)
		dest.ExpectedGID = &g
	}
	_ = json.Unmarshal([]byte(allowedOps), &dest.AllowedOps)
	return dest, nil
}

func (d *DB) GetDestination(id string) (*types.Destination, error) {
	return scanDestination(func(args ...interface{}) error {
		return d.db.QueryRow(`
			SELECT id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, created_at, updated_at
			FROM destinations WHERE id = ?
		`, id).Scan(args...)
	})
}

func (d *DB) ListDestinations() ([]*types.Destination, error) {
	rows, err := d.db.Query(`
		SELECT id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, created_at, updated_at
		FROM destinations ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dests []*types.Destination
	for rows.Next() {
		dest, err := scanDestination(func(args ...interface{}) error { return rows.Scan(args...) })
		if err != nil {
			return nil, err
		}
		dests = append(dests, dest)
	}
	return dests, nil
}
