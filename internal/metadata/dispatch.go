package metadata

import (
	"database/sql"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// DispatchRecord is the broker-private immutable delivery fact for one
// dispatched transfer (G02). It snapshots the EXACT destination identity
// and payload digest that crossed the dispatch barrier, so later
// reconciliation consults the original delivery — never the destination's
// current configuration, which may have been repointed since.
//
// The payload digest lives ONLY here (and transiently inside the trusted
// delivery protocol): it is never copied into receipts, status responses,
// or audit logs (G01).
type DispatchRecord struct {
	OpID             string
	AttemptID        string
	DestID           string
	DestEndpoint     string
	DestExpectedUID  *uint32
	DestExpectedGID  *uint32
	DestConfigDigest string
	PayloadDigest    string
	PayloadBytes     int
	// CapsuleBytes stores only bounded recipient-encrypted ciphertext so an
	// authenticated requester can recover the exact issuance after a lost IPC
	// reply. It is cleared after expiry or final settlement; digest, length,
	// destination, and handoff identity remain for receipt reconciliation.
	CapsuleBytes []byte
	HandoffMode  types.HandoffMode
	HandoffID    string
	RecordedAt   time.Time
}

// RecordDispatch persists the dispatch facts. It must be called after a
// successful BeginDispatch and before any payload byte moves; callers
// must not ignore the error.
//
// The insert is guarded, not blind (P2-7): the operation must be in
// dispatching status bound to the live attempt, and a conflicting
// preexisting record is an explicit error — never silently accepted.
// A byte-equivalent record for the same attempt is idempotent (safe
// retry of the recording step itself).
func (d *DB) RecordDispatch(r *DispatchRecord) error {
	if r == nil || r.OpID == "" || r.AttemptID == "" || r.DestID == "" ||
		(r.DestEndpoint == "" && r.HandoffMode != types.HandoffSealedCapsule) || r.DestExpectedUID == nil || r.PayloadDigest == "" ||
		(r.HandoffMode == types.HandoffSealedCapsule && (len(r.CapsuleBytes) == 0 || len(r.CapsuleBytes) > 1<<20)) ||
		(r.HandoffMode != types.HandoffSealedCapsule && len(r.CapsuleBytes) != 0) {
		return errDispatch("incomplete dispatch record")
	}
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now()
	}
	// Lock-contention retry (QR-08): concurrent deliveries collide on
	// short read-then-write transactions. Retries revalidate every
	// guard, so a retry can never record what validation denies.
	var err error
	for lockTry := 0; ; lockTry++ {
		err = d.recordDispatchOnce(r)
		if err == nil || !isLockContention(err) || lockTry >= 20 {
			return err
		}
		time.Sleep(time.Duration(5+lockTry*5) * time.Millisecond)
	}
}

// RecordSealedCapsuleDispatch atomically persists the exact encrypted capsule
// and marks its transfer uncertain. This closes the crash window between
// recording an issued capsule and publishing its uncertain state.
func (d *DB) RecordSealedCapsuleDispatch(r *DispatchRecord) error {
	if r == nil || r.OpID == "" || r.AttemptID == "" || r.DestID == "" ||
		r.DestExpectedUID == nil || r.PayloadDigest == "" || r.HandoffMode != types.HandoffSealedCapsule ||
		r.HandoffID == "" || len(r.CapsuleBytes) == 0 || len(r.CapsuleBytes) > 1<<20 ||
		r.PayloadBytes != len(r.CapsuleBytes) {
		return errDispatch("incomplete sealed capsule dispatch")
	}
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now()
	}
	return d.recordSealedCapsuleDispatchOnce(r)
}

func (d *DB) recordSealedCapsuleDispatchOnce(r *DispatchRecord) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	var status string
	if err := tx.QueryRow(`SELECT status FROM transfers WHERE id=?`, r.OpID).Scan(&status); err != nil || status != types.StatusDispatching {
		rollback()
		return errDispatch("capsule operation is not dispatching")
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM execution_attempts WHERE id=? AND op_id=? AND op_type='transfer' AND outcome='started'`, r.AttemptID, r.OpID).Scan(&n); err != nil || n != 1 {
		rollback()
		return errDispatch("capsule attempt is not the live owner")
	}
	var uid uint32 = *r.DestExpectedUID
	var gid interface{}
	if r.DestExpectedGID != nil {
		gid = *r.DestExpectedGID
	}
	if _, err := tx.Exec(`INSERT INTO dispatch_records
		(op_id,attempt_id,dest_id,dest_endpoint,dest_expected_uid,dest_expected_gid,dest_config_digest,payload_digest,payload_bytes,capsule_bytes,handoff_mode,handoff_id,recorded_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.OpID, r.AttemptID, r.DestID, r.DestEndpoint, uid, gid,
		r.DestConfigDigest, r.PayloadDigest, r.PayloadBytes, r.CapsuleBytes, r.HandoffMode, r.HandoffID, r.RecordedAt); err != nil {
		rollback()
		return err
	}
	now := time.Now()
	attemptResult, err := tx.Exec(`UPDATE execution_attempts SET outcome='uncertain',finished_at=? WHERE id=? AND op_id=? AND op_type='transfer' AND outcome='started'`, now, r.AttemptID, r.OpID)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := attemptResult.RowsAffected(); n != 1 {
		rollback()
		return errDispatch("capsule attempt finalization lost ownership")
	}
	transferResult, err := tx.Exec(`UPDATE transfers SET status=?,completed_at=?,revision=revision+1 WHERE id=? AND status=?`, types.StatusUncertain, now, r.OpID, types.StatusDispatching)
	if err != nil {
		rollback()
		return err
	}
	if n, _ := transferResult.RowsAffected(); n != 1 {
		rollback()
		return errDispatch("capsule operation finalization failed")
	}
	return tx.Commit()
}

func (d *DB) recordDispatchOnce(r *DispatchRecord) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	var status string
	if err := tx.QueryRow(`SELECT status FROM transfers WHERE id = ?`, r.OpID).Scan(&status); err != nil {
		rollback()
		return errDispatch("dispatched operation not found")
	}
	if status != types.StatusDispatching {
		rollback()
		return errDispatch("operation is not dispatching")
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM execution_attempts
		WHERE id = ? AND op_id = ? AND op_type = 'transfer' AND outcome = 'started'`,
		r.AttemptID, r.OpID).Scan(&n); err != nil || n != 1 {
		rollback()
		return errDispatch("attempt is not the live owner")
	}
	var uid uint32 = *r.DestExpectedUID
	var gid interface{}
	capsuleBytes := r.CapsuleBytes
	if capsuleBytes == nil {
		capsuleBytes = []byte{}
	}
	if r.DestExpectedGID != nil {
		gid = *r.DestExpectedGID
	}
	existing, err := d.getDispatchTx(tx, r.OpID)
	if err != nil {
		rollback()
		return err
	}
	if existing != nil {
		if dispatchEqual(existing, r) {
			_ = tx.Commit()
			return nil
		}
		rollback()
		return errDispatch("conflicting dispatch record already exists")
	}
	if _, err := tx.Exec(`
		INSERT INTO dispatch_records
		  (op_id, attempt_id, dest_id, dest_endpoint, dest_expected_uid,
		   dest_expected_gid, dest_config_digest, payload_digest, payload_bytes, capsule_bytes, handoff_mode, handoff_id, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.OpID, r.AttemptID, r.DestID, r.DestEndpoint, uid, gid,
		r.DestConfigDigest, r.PayloadDigest, r.PayloadBytes, capsuleBytes, r.HandoffMode, r.HandoffID, r.RecordedAt); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

func dispatchEqual(a, b *DispatchRecord) bool {
	if a.AttemptID != b.AttemptID || a.DestID != b.DestID ||
		a.DestEndpoint != b.DestEndpoint || a.DestConfigDigest != b.DestConfigDigest ||
		a.PayloadDigest != b.PayloadDigest || a.PayloadBytes != b.PayloadBytes ||
		string(a.CapsuleBytes) != string(b.CapsuleBytes) || a.HandoffMode != b.HandoffMode ||
		a.HandoffID != b.HandoffID || *a.DestExpectedUID != *b.DestExpectedUID {
		return false
	}
	if (a.DestExpectedGID == nil) != (b.DestExpectedGID == nil) {
		return false
	}
	if a.DestExpectedGID != nil && *a.DestExpectedGID != *b.DestExpectedGID {
		return false
	}
	return true
}

func (d *DB) getDispatchTx(tx *sql.Tx, opID string) (*DispatchRecord, error) {
	r := &DispatchRecord{OpID: opID}
	var uid uint32
	var gid sql.NullInt64
	err := tx.QueryRow(`
		SELECT op_id, attempt_id, dest_id, dest_endpoint, dest_expected_uid,
		       dest_expected_gid, dest_config_digest, payload_digest, payload_bytes, capsule_bytes, handoff_mode, handoff_id, recorded_at
		FROM dispatch_records WHERE op_id = ?
	`, opID).Scan(&r.OpID, &r.AttemptID, &r.DestID, &r.DestEndpoint,
		&uid, &gid, &r.DestConfigDigest, &r.PayloadDigest, &r.PayloadBytes, &r.CapsuleBytes, &r.HandoffMode, &r.HandoffID, &r.RecordedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.DestExpectedUID = &uid
	if gid.Valid {
		g := uint32(gid.Int64)
		r.DestExpectedGID = &g
	}
	return r, nil
}

// GetDispatch returns the immutable dispatch facts for an op, or nil when
// the op never crossed the dispatch barrier. Reconciliation without a
// record is unavailable — never guessed from current configuration.
func (d *DB) GetDispatch(opID string) (*DispatchRecord, error) {
	r := &DispatchRecord{OpID: opID}
	var uid uint32
	var gid sql.NullInt64
	err := d.db.QueryRow(`
		SELECT op_id, attempt_id, dest_id, dest_endpoint, dest_expected_uid,
		       dest_expected_gid, dest_config_digest, payload_digest, payload_bytes, capsule_bytes, handoff_mode, handoff_id, recorded_at
		FROM dispatch_records WHERE op_id = ?
	`, opID).Scan(&r.OpID, &r.AttemptID, &r.DestID, &r.DestEndpoint,
		&uid, &gid, &r.DestConfigDigest, &r.PayloadDigest, &r.PayloadBytes, &r.CapsuleBytes, &r.HandoffMode, &r.HandoffID, &r.RecordedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.DestExpectedUID = &uid
	if gid.Valid {
		g := uint32(gid.Int64)
		r.DestExpectedGID = &g
	}
	return r, nil
}

// GetRetrievableSealedCapsule returns the immutable ciphertext only while the
// original requester, operation authorization epoch, and approved destination
// snapshot are still current. The transfer became uncertain when the capsule
// was persisted, so this check is the retrieval-time revocation barrier for a
// response that may have been lost before reaching the requester.
func (d *DB) GetRetrievableSealedCapsule(opID, requester string, now time.Time) (*DispatchRecord, error) {
	if opID == "" || requester == "" {
		return nil, errDispatch("capsule retrieval unavailable")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r := &DispatchRecord{}
	var uid uint32
	var gid sql.NullInt64
	err = tx.QueryRow(`
		SELECT d.op_id, d.attempt_id, d.dest_id, d.dest_endpoint,
		       d.dest_expected_uid, d.dest_expected_gid, d.dest_config_digest,
		       d.payload_digest, d.payload_bytes, d.capsule_bytes,
		       d.handoff_mode, d.handoff_id, d.recorded_at
		FROM dispatch_records d
		JOIN transfers t ON t.id=d.op_id
		JOIN authorization_state a ON a.id=1
		WHERE d.op_id=? AND t.requested_by=? AND t.status='uncertain'
		  AND t.expires_at>? AND t.auth_epoch=a.epoch
		  AND t.destination_id=d.dest_id AND t.dest_digest=d.dest_config_digest
		  AND d.handoff_mode=?
	`, opID, requester, now, types.HandoffSealedCapsule).Scan(
		&r.OpID, &r.AttemptID, &r.DestID, &r.DestEndpoint,
		&uid, &gid, &r.DestConfigDigest, &r.PayloadDigest, &r.PayloadBytes,
		&r.CapsuleBytes, &r.HandoffMode, &r.HandoffID, &r.RecordedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errDispatch("capsule retrieval unavailable")
		}
		return nil, err
	}
	r.DestExpectedUID = &uid
	if gid.Valid {
		g := uint32(gid.Int64)
		r.DestExpectedGID = &g
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func errDispatch(msg string) error {
	return dispatchError(msg)
}

type dispatchError string

func (e dispatchError) Error() string { return "dispatch record: " + string(e) }
