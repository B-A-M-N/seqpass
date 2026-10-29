package metadata

import (
	"bytes"
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
	target, _ := json.Marshal(dest.CredentialTarget)
	h := sha256.Sum256([]byte(dest.ID + "\x00" + dest.Type + "\x00" + dest.Endpoint + "\x00" + dest.SourceRepo + "\x00" + string(dest.HandoffMode) + "\x00" + string(allowedOps) + "\x00" + uid + "\x00" + gid + "\x00" + dest.RecipientKeyID + "\x00" + string(dest.RecipientPublicKey) + "\x00" + dest.ReceiptKeyID + "\x00" + string(dest.ReceiptPublicKey) + "\x00" + dest.IssuerKeyID + "\x00" + string(dest.IssuerPublicKey) + "\x00" + string(target)))
	return hex.EncodeToString(h[:])
}

func validateAppCredentialTarget(target *types.AppCredentialTarget) error {
	if target == nil || target.Validate() != nil {
		return fmt.Errorf("unsupported or incomplete registered application credential target")
	}
	return nil
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

	if dest.HandoffMode == "" {
		dest.HandoffMode = types.HandoffDirectSocket
	}
	if dest.HandoffMode != types.HandoffDirectSocket && dest.HandoffMode != types.HandoffRecipientPull && dest.HandoffMode != types.HandoffSealedCapsule {
		return fmt.Errorf("unknown handoff mode")
	}
	if dest.HandoffMode == types.HandoffRecipientPull && (dest.Type != "recipient-socket" || dest.ExpectedUID == nil || dest.CredentialTarget == nil) {
		return fmt.Errorf("recipient-pull requires a recipient-socket identity and registered app credential target")
	}
	if dest.HandoffMode == types.HandoffRecipientPull || dest.HandoffMode == types.HandoffSealedCapsule {
		if err := validateAppCredentialTarget(dest.CredentialTarget); err != nil {
			return err
		}
	}
	if dest.HandoffMode == types.HandoffSealedCapsule {
		if dest.ExpectedUID == nil || dest.RecipientKeyID == "" || len(dest.RecipientPublicKey) != 32 || dest.ReceiptKeyID == "" || len(dest.ReceiptPublicKey) != 32 || dest.IssuerKeyID == "" || len(dest.IssuerPublicKey) != 32 {
			return fmt.Errorf("sealed-capsule requires recipient UID and pinned HPKE, receipt, and issuer keys")
		}
		if dest.RecipientKeyID == dest.ReceiptKeyID || dest.RecipientKeyID == dest.IssuerKeyID || dest.ReceiptKeyID == dest.IssuerKeyID ||
			bytes.Equal(dest.RecipientPublicKey, dest.ReceiptPublicKey) || bytes.Equal(dest.RecipientPublicKey, dest.IssuerPublicKey) || bytes.Equal(dest.ReceiptPublicKey, dest.IssuerPublicKey) {
			return fmt.Errorf("sealed-capsule key roles must use distinct IDs and key material")
		}
	} else if dest.RecipientKeyID != "" || len(dest.RecipientPublicKey) != 0 || dest.ReceiptKeyID != "" || len(dest.ReceiptPublicKey) != 0 || dest.IssuerKeyID != "" || len(dest.IssuerPublicKey) != 0 {
		return fmt.Errorf("recipient and issuer keys are only valid for sealed-capsule")
	}
	if dest.Type == "recipient-socket" && dest.ExpectedUID == nil {
		return fmt.Errorf("recipient-socket requires an expected recipient UID")
	}

	allowedOps, _ := json.Marshal(dest.AllowedOps)
	targetJSON, err := json.Marshal(dest.CredentialTarget)
	if err != nil {
		return err
	}

	// Mutation + epoch bump commit atomically (C03).
	_, err = d.withAuthMutation(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO destinations (id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, handoff_mode, recipient_key_id, recipient_public_key, receipt_key_id, receipt_public_key, issuer_key_id, issuer_public_key, credential_target, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, dest.ID, dest.Name, dest.Type, dest.Endpoint, dest.SourceRepo, dest.AuthMethod, string(allowedOps), dest.RequiresApproval, dest.ApprovedBy, dest.Revision, nullableUID(dest.ExpectedUID), nullableUID(dest.ExpectedGID), dest.HandoffMode, dest.RecipientKeyID, dest.RecipientPublicKey, dest.ReceiptKeyID, dest.ReceiptPublicKey, dest.IssuerKeyID, dest.IssuerPublicKey, string(targetJSON), dest.CreatedAt, dest.UpdatedAt)
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

// UpdateDestinationHandoffIdentity changes the application target or recipient
// encryption key. The revision and global auth epoch move in the same
// transaction, invalidating every approval made against the old identity.
func (d *DB) UpdateDestinationHandoffIdentity(id string, mode types.HandoffMode, keyID string, publicKey []byte, receiptKeyID string, receiptPublicKey []byte, issuerKeyID string, issuerPublicKey []byte, uid, gid *uint32, target *types.AppCredentialTarget, approver string) error {
	if mode != types.HandoffDirectSocket && mode != types.HandoffRecipientPull && mode != types.HandoffSealedCapsule {
		return fmt.Errorf("unknown handoff mode")
	}
	if mode == types.HandoffRecipientPull || mode == types.HandoffSealedCapsule {
		if err := validateAppCredentialTarget(target); err != nil {
			return err
		}
	}
	if mode == types.HandoffSealedCapsule && (keyID == "" || len(publicKey) != 32 || receiptKeyID == "" || len(receiptPublicKey) != 32 || issuerKeyID == "" || len(issuerPublicKey) != 32) {
		return fmt.Errorf("sealed-capsule requires pinned HPKE, receipt, and issuer public keys")
	}
	if mode == types.HandoffSealedCapsule && (keyID == receiptKeyID || keyID == issuerKeyID || receiptKeyID == issuerKeyID ||
		bytes.Equal(publicKey, receiptPublicKey) || bytes.Equal(publicKey, issuerPublicKey) || bytes.Equal(receiptPublicKey, issuerPublicKey)) {
		return fmt.Errorf("sealed-capsule key roles must use distinct IDs and key material")
	}
	if mode != types.HandoffSealedCapsule && (keyID != "" || len(publicKey) != 0 || receiptKeyID != "" || len(receiptPublicKey) != 0 || issuerKeyID != "" || len(issuerPublicKey) != 0) {
		return fmt.Errorf("recipient encryption key is only valid for sealed-capsule")
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return err
	}
	_, err = d.withAuthMutation(func(tx *sql.Tx) error {
		var typ string
		var existingUID sql.NullInt64
		if err := tx.QueryRow(`SELECT type,expected_uid FROM destinations WHERE id=?`, id).Scan(&typ, &existingUID); err != nil {
			return fmt.Errorf("destination not found")
		}
		hasUID := uid != nil || existingUID.Valid
		if mode == types.HandoffRecipientPull && (typ != "recipient-socket" || !hasUID) || mode == types.HandoffSealedCapsule && (typ != "sealed-capsule" && typ != "recipient-socket" || !hasUID) {
			return fmt.Errorf("recipient handoff requires a pinned recipient identity")
		}
		res, err := tx.Exec(`UPDATE destinations SET handoff_mode=?,recipient_key_id=?,recipient_public_key=?,receipt_key_id=?,receipt_public_key=?,issuer_key_id=?,issuer_public_key=?,expected_uid=COALESCE(?,expected_uid),expected_gid=COALESCE(?,expected_gid),credential_target=?,revision=revision+1,updated_at=?,approved_by=? WHERE id=?`, mode, keyID, publicKey, receiptKeyID, receiptPublicKey, issuerKeyID, issuerPublicKey, nullableUID(uid), nullableUID(gid), string(targetJSON), time.Now(), approver, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
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
	var allowedOps, targetJSON string
	var uid, gid sql.NullInt64
	err := scan(&dest.ID, &dest.Name, &dest.Type, &dest.Endpoint, &dest.SourceRepo, &dest.AuthMethod, &allowedOps, &dest.RequiresApproval, &dest.ApprovedBy, &dest.Revision, &uid, &gid, &dest.HandoffMode, &dest.RecipientKeyID, &dest.RecipientPublicKey, &dest.ReceiptKeyID, &dest.ReceiptPublicKey, &dest.IssuerKeyID, &dest.IssuerPublicKey, &targetJSON, &dest.CreatedAt, &dest.UpdatedAt)
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
	if allowedOps != "" {
		if err := json.Unmarshal([]byte(allowedOps), &dest.AllowedOps); err != nil {
			return nil, fmt.Errorf("invalid destination allowed_ops: %w", err)
		}
	}
	if targetJSON != "" && targetJSON != "null" {
		if err := json.Unmarshal([]byte(targetJSON), &dest.CredentialTarget); err != nil {
			return nil, fmt.Errorf("invalid destination credential target: %w", err)
		}
	}
	return dest, nil
}

func (d *DB) GetDestination(id string) (*types.Destination, error) {
	return scanDestination(func(args ...interface{}) error {
		return d.db.QueryRow(`
			SELECT id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, handoff_mode, recipient_key_id, recipient_public_key, receipt_key_id, receipt_public_key, issuer_key_id, issuer_public_key, credential_target, created_at, updated_at
			FROM destinations WHERE id = ?
		`, id).Scan(args...)
	})
}

func (d *DB) ListDestinations() ([]*types.Destination, error) {
	rows, err := d.db.Query(`
		SELECT id, name, type, endpoint, source_repo, auth_method, allowed_ops, requires_approval, approved_by, revision, expected_uid, expected_gid, handoff_mode, recipient_key_id, recipient_public_key, receipt_key_id, receipt_public_key, issuer_key_id, issuer_public_key, credential_target, created_at, updated_at
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
