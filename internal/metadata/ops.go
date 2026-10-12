package metadata

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// CanonicalOpHash binds an approval to the exact requested action.
// Every part is length-framed (8-byte big-endian) under a domain separator
// so distinct field sequences can never collide: no delimiter ambiguity
// (SC-01). Kept for backward-compatible contexts; new approvals use the
// versioned envelope hashes below.
func CanonicalOpHash(parts ...string) string {
	h := sha256.New()
	h.Write([]byte("seqpass-op/"))
	for _, p := range parts {
		var lb [8]byte
		binary.BigEndian.PutUint64(lb[:], uint64(len(p)))
		h.Write(lb[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalParamsJSON serializes params with sorted keys so the persisted
// envelope is immutable and comparable at approval and execution.
func CanonicalParamsJSON(params map[string]string) string {
	if len(params) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(params[k])
		b.Write(kb)
		b.WriteString(":")
		b.Write(vb)
	}
	b.WriteString("}")
	return b.String()
}

// UseOpHash binds principal+credential+operation+destination+resource+params
// in one versioned envelope (SC-01). CanonicalParamsJSON is injective JSON;
// resource pins the exact authorized resource. Any execution-affecting field
// change alters the digest.
func UseOpHash(principal, secretRef, op, target string, params map[string]string, resource types.ResourceDescriptor) string {
	return CanonicalOpHash("v1", "use", principal, secretRef, op, target,
		resource.Kind, resource.Identifier, CanonicalParamsJSON(params))
}

// TransferOpHash binds principal+credential+destination+component selector
// (SC-01). PayloadRef chooses the transferred component; omitting it from
// the digest would let approval cover a different payload.
func TransferOpHash(principal, secretRef, destID, payloadRef string) string {
	return CanonicalOpHash("v1", "transfer", principal, secretRef, destID, payloadRef)
}

// ApprovedOperationEnvelope (CV-08) names every field capable of affecting
// the external operation and the single authoritative mechanism that
// protects it. The approval digest alone does not pin everything — the
// envelope is the digest PLUS the transactionally enforced guards, and
// this contract states which is which so no field is protected twice or
// not at all:
//
//   - requested action (principal, secret ref, operation, target, params,
//     resource, payload component): pinned by the op digest (UseOpHash /
//     TransferOpHash). Any change alters the digest and the approval CAS
//     fails closed.
//   - authorization rules in force: pinned by auth_epoch, compared
//     against the LIVE authorization_state row inside the approval and
//     claim statements. Policy/destination/binding edits bump the epoch
//     in the same transaction, so a committed change always defeats a
//     racing approval or claim.
//   - destination configuration: pinned by dest_digest + dest_revision.
//     Endpoint or recipient-identity edits change the digest and bump
//     the epoch; stale approvals cannot dispatch to the new endpoint.
//   - exact reviewed version: pinned by revision, CAS-checked at approve
//     and claim. Concurrent edits serialize: exactly one winner.
//   - credential generation: the approval binds the BINDING identity
//     (source_binding snapshotted into the op row), never a credential
//     version. At execution the broker resolves the CURRENT authorized
//     value of that binding (latest-authorized-at-resolution, SC-13).
//     Three cases, three outcomes:
//     (a) SeqPass binding changed (ref re-pointed): a SeqPass metadata
//     mutation that bumps the epoch in the same transaction, so
//     outstanding approvals bound to the old epoch fail admission.
//     (b) Credential rotated inside AegisKeys under the SAME binding:
//     touches no SeqPass metadata and bumps no epoch; the next
//     resolution returns the new value by design. Already-resolved
//     plaintext is not retracted (Lock() stops future resolutions).
//     (c) Exact-generation pinning (executing against a named credential
//     version) is NOT implemented: the AegisKeys resolver interface
//     exposes no generation identifier, so there is nothing to pin to.
//     If that interface gains generations, add the generation id to
//     the digest inputs above. Until then, never claim a transfer
//     carries the reviewed byte value — only the reviewed binding.
//
// Do not add duplicate hashes for fields already protected
// transactionally unless the threat model requires it: one authority per
// field, stated here.
type ApprovalEnvelope struct {
	OpHash       string
	DestDigest   string
	DestRevision int
	AuthEpoch    int64
	Revision     int
}

func (d *DB) CreateTransfer(tr *types.TransferRequest) error {
	if tr.ID == "" {
		tr.ID = generateID()
	}
	now := time.Now()
	if tr.CreatedAt.IsZero() {
		tr.CreatedAt = now
	}
	if tr.Status == "" {
		tr.Status = types.StatusRequested
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	if err := insertTransferTx(tx, tr); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// insertTransferTx persists one transfer row inside the caller's
// transaction (shared by CreateTransfer and relay fulfillment, so the
// relay grant and its authorized operation commit atomically — QR-04).
func insertTransferTx(tx *sql.Tx, tr *types.TransferRequest) error {
	_, err := tx.Exec(`
		INSERT INTO transfers (id, secret_ref, source_kind, source_binding, source_ref, destination_id, payload_ref, expires_at, status, requested_by, approved_by, revision, auth_epoch, dest_digest, dest_revision, op_hash, created_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, tr.ID, tr.SecretRef, string(tr.Source.Kind), tr.Source.Binding, tr.Source.Ref, tr.DestinationID, tr.PayloadRef, tr.ExpiresAt, tr.Status, tr.RequestedBy, tr.ApprovedBy, tr.Revision, tr.AuthEpoch, tr.DestDigest, tr.DestRevision, tr.OpHash, tr.CreatedAt, tr.CompletedAt)
	return err
}

func (d *DB) GetTransfer(id string) (*types.TransferRequest, error) {
	tr := &types.TransferRequest{}
	var completedAt sql.NullTime
	var sourceKind sql.NullString
	var sourceBinding sql.NullString
	var sourceRef sql.NullString
	var opHash sql.NullString
	var destDigest sql.NullString
	err := d.db.QueryRow(`
		SELECT id, secret_ref, source_kind, source_binding, source_ref, destination_id, payload_ref, expires_at, status, requested_by, approved_by, revision, auth_epoch, dest_digest, dest_revision, op_hash, created_at, completed_at
		FROM transfers WHERE id = ?
	`, id).Scan(&tr.ID, &tr.SecretRef, &sourceKind, &sourceBinding, &sourceRef, &tr.DestinationID, &tr.PayloadRef, &tr.ExpiresAt, &tr.Status, &tr.RequestedBy, &tr.ApprovedBy, &tr.Revision, &tr.AuthEpoch, &destDigest, &tr.DestRevision, &opHash, &tr.CreatedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if completedAt.Valid {
		tr.CompletedAt = &completedAt.Time
	}
	if sourceKind.Valid {
		tr.Source.Kind = types.SourceKind(sourceKind.String)
	}
	if sourceBinding.Valid {
		tr.Source.Binding = sourceBinding.String
	}
	if sourceRef.Valid {
		tr.Source.Ref = sourceRef.String
	}
	if opHash.Valid {
		tr.OpHash = opHash.String
	}
	if destDigest.Valid {
		tr.DestDigest = destDigest.String
	}
	return tr, nil
}

// ApproveTransfer moves requested/pending_approval -> authorized, binding the
// op hash, destination digest and current epoch.
// ApproveTransfer is a compare-and-swap against the reviewed decision
// artifact (SC-02): it succeeds only when the stored envelope hash, the
// caller-observed revision, and the LIVE authorization epoch all match in
// one statement. The stored hash is compared, never rewritten: approval
// cannot silently rebind to a different action. A stale review (edited
// destination, changed policy, tampered envelope) fails closed.
func (d *DB) ApproveTransfer(id, approver, opHash string, epoch int64, revision int) error {
	res, err := d.db.Exec(`
		UPDATE transfers SET status = ?, approved_by = ?, auth_epoch = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval')
		  AND op_hash = ? AND revision = ? AND expires_at > ?
		  AND ? = (SELECT epoch FROM authorization_state WHERE id = 1)
	`, types.StatusAuthorized, approver, epoch, id, opHash, revision, time.Now(), epoch)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("transfer not approvable: stale review, changed operation, or revoked authorization")
	}
	return nil
}

// RejectTransfer is a terminal path before execution.
func (d *DB) RejectTransfer(id, approver string) error {
	res, err := d.db.Exec(`
		UPDATE transfers SET status = ?, approved_by = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval')
	`, types.StatusRejected, approver, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("transfer not in approvable state")
	}
	return nil
}

// ClaimTransfer atomically moves authorized -> executing. The epoch is
// compared against the LIVE authorization_state row inside the same
// statement (C04): a committed revocation always defeats a racing claim.
// The expected revision pins the exact approved row version. A durable
// execution-attempt record commits in the same transaction (C07).
func (d *DB) ClaimTransfer(id, opHash, destDigest string, revision int, worker string, now time.Time) (attemptID string, claimed bool, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return "", false, err
	}
	rollback := func() { _ = tx.Rollback() }
	res, err := tx.Exec(`
		UPDATE transfers SET status = 'executing', revision = revision + 1
		WHERE id = ? AND status = 'authorized' AND expires_at > ?
		  AND auth_epoch = (SELECT epoch FROM authorization_state WHERE id = 1)
		  AND op_hash = ? AND dest_digest = ? AND revision = ?
	`, id, now, opHash, destDigest, revision)
	if err != nil {
		rollback()
		return "", false, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		rollback()
		return "", false, nil
	}
	attemptID = "att-" + generateID()[:12]
	if _, err := tx.Exec(`
		INSERT INTO execution_attempts (id, op_type, op_id, worker, started_at, outcome)
		VALUES (?, 'transfer', ?, ?, ?, 'started')
	`, attemptID, id, worker, now); err != nil {
		rollback()
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return attemptID, true, nil
}

// MarkTransferPreClaim records expiry/revocation before execution.
func (d *DB) MarkTransferPreClaim(id, status string) error {
	now := time.Now()
	res, err := d.db.Exec(`
		UPDATE transfers SET status = ?, completed_at = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval', 'authorized')
	`, status, &now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("transfer not in pre-execution state")
	}
	return nil
}

func (d *DB) CreateUse(ur *types.UseRequest) error {
	if ur.ID == "" {
		ur.ID = generateID()
	}
	now := time.Now()
	if ur.CreatedAt.IsZero() {
		ur.CreatedAt = now
	}
	if ur.Status == "" {
		ur.Status = types.StatusRequested
	}

	params := CanonicalParamsJSON(ur.Params)

	_, err := d.db.Exec(`
		INSERT INTO uses (id, secret_ref, source_kind, source_binding, source_ref, operation, target, params, expires_at, status, requested_by, approved_by, revision, auth_epoch, dest_digest, dest_revision, op_hash, created_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ur.ID, ur.SecretRef, string(ur.Source.Kind), ur.Source.Binding, ur.Source.Ref, ur.Operation, ur.Target, params, ur.ExpiresAt, ur.Status, ur.RequestedBy, ur.ApprovedBy, ur.Revision, ur.AuthEpoch, ur.DestDigest, ur.DestRevision, ur.OpHash, ur.CreatedAt, ur.CompletedAt)
	return err
}

func (d *DB) GetUse(id string) (*types.UseRequest, error) {
	ur := &types.UseRequest{}
	var completedAt sql.NullTime
	var sourceKind sql.NullString
	var sourceBinding sql.NullString
	var sourceRef sql.NullString
	var opHash sql.NullString
	var destDigest sql.NullString
	var params string
	err := d.db.QueryRow(`
		SELECT id, secret_ref, source_kind, source_binding, source_ref, operation, target, params, expires_at, status, requested_by, approved_by, revision, auth_epoch, dest_digest, dest_revision, op_hash, created_at, completed_at
		FROM uses WHERE id = ?
	`, id).Scan(&ur.ID, &ur.SecretRef, &sourceKind, &sourceBinding, &sourceRef, &ur.Operation, &ur.Target, &params, &ur.ExpiresAt, &ur.Status, &ur.RequestedBy, &ur.ApprovedBy, &ur.Revision, &ur.AuthEpoch, &destDigest, &ur.DestRevision, &opHash, &ur.CreatedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if completedAt.Valid {
		ur.CompletedAt = &completedAt.Time
	}
	if sourceKind.Valid {
		ur.Source.Kind = types.SourceKind(sourceKind.String)
	}
	if sourceBinding.Valid {
		ur.Source.Binding = sourceBinding.String
	}
	if sourceRef.Valid {
		ur.Source.Ref = sourceRef.String
	}
	if opHash.Valid {
		ur.OpHash = opHash.String
	}
	if destDigest.Valid {
		ur.DestDigest = destDigest.String
	}
	_ = json.Unmarshal([]byte(params), &ur.Params)
	return ur, nil
}

// ApproveUse moves requested/pending_approval -> authorized as a
// compare-and-swap against the reviewed artifact (SC-02): stored envelope
// hash, observed revision, and live authorization epoch must all match in
// one statement. The hash is compared, never rewritten.
func (d *DB) ApproveUse(id, approver, opHash string, epoch int64, revision int) error {
	res, err := d.db.Exec(`
		UPDATE uses SET status = ?, approved_by = ?, auth_epoch = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval')
		  AND op_hash = ? AND revision = ? AND expires_at > ?
		  AND ? = (SELECT epoch FROM authorization_state WHERE id = 1)
	`, types.StatusAuthorized, approver, epoch, id, opHash, revision, time.Now(), epoch)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("use not approvable: stale review, changed operation, or revoked authorization")
	}
	return nil
}

// RejectUse is a terminal path before execution.
func (d *DB) RejectUse(id, approver string) error {
	res, err := d.db.Exec(`
		UPDATE uses SET status = ?, approved_by = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval')
	`, types.StatusRejected, approver, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("use not in approvable state")
	}
	return nil
}

// ClaimUse atomically moves authorized -> executing against the live epoch
// (C04) with revision pinning and a durable attempt record (C07).
func (d *DB) ClaimUse(id, opHash, destDigest string, revision int, worker string, now time.Time) (attemptID string, claimed bool, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return "", false, err
	}
	rollback := func() { _ = tx.Rollback() }
	res, err := tx.Exec(`
		UPDATE uses SET status = 'executing', revision = revision + 1
		WHERE id = ? AND status = 'authorized' AND expires_at > ?
		  AND auth_epoch = (SELECT epoch FROM authorization_state WHERE id = 1)
		  AND op_hash = ? AND dest_digest = ? AND revision = ?
	`, id, now, opHash, destDigest, revision)
	if err != nil {
		rollback()
		return "", false, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		rollback()
		return "", false, nil
	}
	attemptID = "att-" + generateID()[:12]
	if _, err := tx.Exec(`
		INSERT INTO execution_attempts (id, op_type, op_id, worker, started_at, outcome)
		VALUES (?, 'use', ?, ?, ?, 'started')
	`, attemptID, id, worker, now); err != nil {
		rollback()
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return attemptID, true, nil
}

// MarkUsePreClaim records expiry/revocation before execution.
func (d *DB) MarkUsePreClaim(id, status string) error {
	now := time.Now()
	res, err := d.db.Exec(`
		UPDATE uses SET status = ?, completed_at = ?, revision = revision + 1
		WHERE id = ? AND status IN ('requested', 'pending_approval', 'authorized')
	`, status, &now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("use not in pre-execution state")
	}
	return nil
}

// ExpireOpenOperations is the single lifecycle transition for expiry
// (G04): expired, not-yet-dispatched operations become expired in one
// guarded transaction. Expired work can never look actionable again and
// can never execute without a fresh authorization cycle — admission and
// claim re-check expiry independently, so this is a visibility and
// hygiene transition, not the security boundary itself. Returns the
// number of operations expired.
func (d *DB) ExpireOpenOperations(now time.Time) (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	rollback := func() { _ = tx.Rollback() }
	total := 0
	for _, tbl := range []string{"transfers", "uses"} {
		res, err := tx.Exec(`UPDATE `+tbl+` SET status = 'expired', completed_at = ?, revision = revision + 1
			WHERE status IN ('requested', 'pending_approval', 'authorized') AND expires_at <= ?`, &now, &now)
		if err != nil {
			rollback()
			return 0, err
		}
		n, _ := res.RowsAffected()
		total += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// FinishAttempt records the attempt outcome for paths that do not go
// through FinalizeOp (kept for compatibility; execution paths use the
// atomic finalizer so receipt, status and outcome commit together).
func (d *DB) FinishAttempt(attemptID, outcome string) error {
	_, err := d.db.Exec(`UPDATE execution_attempts SET outcome = ?, finished_at = ? WHERE id = ?`, outcome, time.Now(), attemptID)
	return err
}

// OpenAttempt returns the open (started, unfinished) attempt for an op, if
// any. Used by recovery paths and tests to identify the owning attempt.
func (d *DB) OpenAttempt(opID string) (attemptID, worker string, err error) {
	err = d.db.QueryRow(`SELECT id, worker FROM execution_attempts WHERE op_id = ? AND outcome = 'started' ORDER BY started_at DESC LIMIT 1`, opID).Scan(&attemptID, &worker)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return attemptID, worker, err
}

// ListAuthorizedOps returns ops approved but not yet executed. The trusted
// auto worker (C13) consumes only this set through the same atomic claim
// path as manual execution; pending/requested ops still need approval.
func (d *DB) ListAuthorizedOps() (uses []*types.UseRequest, transfers []*types.TransferRequest, err error) {
	now := time.Now()
	urows, err := d.db.Query(`SELECT id FROM uses WHERE status = 'authorized' AND expires_at > ? ORDER BY created_at ASC`, now)
	if err != nil {
		return nil, nil, err
	}
	defer urows.Close()
	for urows.Next() {
		var id string
		if err := urows.Scan(&id); err != nil {
			return nil, nil, err
		}
		ur, err := d.GetUse(id)
		if err != nil {
			return nil, nil, err
		}
		uses = append(uses, ur)
	}
	trows, err := d.db.Query(`SELECT id FROM transfers WHERE status = 'authorized' AND expires_at > ? ORDER BY created_at ASC`, now)
	if err != nil {
		return nil, nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var id string
		if err := trows.Scan(&id); err != nil {
			return nil, nil, err
		}
		tr, err := d.GetTransfer(id)
		if err != nil {
			return nil, nil, err
		}
		transfers = append(transfers, tr)
	}
	return uses, transfers, nil
}

// ListPendingOps returns ops awaiting operator approval (for admin CLI + harness-visible status).
func (d *DB) ListPendingOps() (uses []*types.UseRequest, transfers []*types.TransferRequest, err error) {
	// Expired rows are never actionable pending work (G04): the queue
	// shows only live requests. Expiry itself is swept by
	// ExpireOpenOperations and surfaced by effectiveStatus.
	now := time.Now()
	urows, err := d.db.Query(`SELECT id FROM uses WHERE status IN ('requested','pending_approval') AND expires_at > ? ORDER BY created_at ASC`, now)
	if err != nil {
		return nil, nil, err
	}
	defer urows.Close()
	for urows.Next() {
		var id string
		if err := urows.Scan(&id); err != nil {
			return nil, nil, err
		}
		ur, err := d.GetUse(id)
		if err != nil {
			return nil, nil, err
		}
		uses = append(uses, ur)
	}
	trows, err := d.db.Query(`SELECT id FROM transfers WHERE status IN ('requested','pending_approval') AND expires_at > ? ORDER BY created_at ASC`, now)
	if err != nil {
		return nil, nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var id string
		if err := trows.Scan(&id); err != nil {
			return nil, nil, err
		}
		tr, err := d.GetTransfer(id)
		if err != nil {
			return nil, nil, err
		}
		transfers = append(transfers, tr)
	}
	return uses, transfers, nil
}
