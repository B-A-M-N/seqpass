package metadata

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func opTable(opType string) (string, error) {
	switch opType {
	case "use":
		return "uses", nil
	case "transfer":
		return "transfers", nil
	default:
		return "", fmt.Errorf("unknown op type %q", opType)
	}
}

// BeginDispatch is the atomic dispatch barrier (SC-03). Its successful
// commit is the defined point authorizing external I/O; the executor must
// not touch the network or recipient socket without it. In one transaction
// it verifies: the op is still executing under the winning attempt, the
// envelope hash and destination digest are unchanged, the live
// authorization epoch still matches, and the authorization deadline has
// not passed. A revocation committed before this point defeats dispatch;
// one committed after meets an in-flight op. The expiry check binds the
// CURRENT time at the dispatch authorization point (P0): an op claimed
// just before its deadline that spends its window resolving credentials
// cannot begin I/O after expiry.
//
// It replaces read-then-act revocation checks at the dispatch boundary.
func (d *DB) BeginDispatch(opType, id, attemptID, opHash, destDigest, worker string, now time.Time) error {
	tbl, err := opTable(opType)
	if err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	res, err := tx.Exec(`
		UPDATE `+tbl+` SET status = 'dispatching', revision = revision + 1
		WHERE id = ? AND status = 'executing'
		  AND op_hash = ? AND dest_digest = ?
		  AND expires_at > ?
		  AND auth_epoch = (SELECT epoch FROM authorization_state WHERE id = 1)
		  AND EXISTS (SELECT 1 FROM execution_attempts
		              WHERE id = ? AND op_id = ? AND worker = ? AND outcome = 'started')
	`, id, opHash, destDigest, now, attemptID, id, worker)
	if err != nil {
		rollback()
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		rollback()
		return fmt.Errorf("dispatch denied: revoked, superseded, or not owned by attempt")
	}
	return tx.Commit()
}

// FinalizeOp commits receipt, terminal operation status, and attempt
// outcome together in one transaction (SC-07). Either all three persist or
// none do: a successful external operation can never lose its evidence, and
// a persisted receipt always has a matching terminal state. Terminal states
// are reachable only from executing (pre-dispatch failure) or dispatching
// (post-dispatch outcome), so stale workers cannot overwrite outcomes.
//
// Pass resultType "" to record a non-completed terminal state without a
// result receipt. Callers must not ignore the returned error.
func (d *DB) FinalizeOp(opType, id, attemptID, status, resultType string, result interface{}) error {
	tbl, err := opTable(opType)
	if err != nil {
		return err
	}
	// Semantic preconditions are enforced inside the transaction's
	// authority, not assumed from the caller (G09):
	//   - completed requires a safe receipt; a receipt requires
	//     completed status (no completed-without-evidence, no
	//     evidence-paired-with-failure).
	//   - the attempt must be the operation's live attempt: matching
	//     id, operation, type, and still-started state. A stale worker
	//     or caller error can never terminalize another attempt's op.
	if status == types.StatusCompleted && resultType == "" {
		return fmt.Errorf("completed status requires a result receipt")
	}
	if resultType != "" && status != types.StatusCompleted {
		return fmt.Errorf("result receipt requires completed status")
	}
	if attemptID == "" {
		return fmt.Errorf("finalization requires the owning attempt")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	now := time.Now()
	// Claim attempt ownership first: exactly one live attempt row must
	// transition. A wrong ID, a finished attempt, or a concurrent
	// finalizer racing us matches zero rows and rolls back.
	ares, err := tx.Exec(`
		UPDATE execution_attempts SET outcome = ?, finished_at = ?
		WHERE id = ? AND op_id = ? AND op_type = ? AND outcome = 'started'
	`, finalizeOutcome(status, resultType), &now, attemptID, id, opType)
	if err != nil {
		rollback()
		return err
	}
	an, _ := ares.RowsAffected()
	if an != 1 {
		rollback()
		return fmt.Errorf("finalization denied: attempt is not the live owner of this operation")
	}
	if resultType != "" {
		raw, err := json.Marshal(result)
		if err != nil {
			rollback()
			return err
		}
		if len(raw) > maxReceiptBytes {
			rollback()
			return errors.New("receipt too large")
		}
		if _, err := tx.Exec(`
			INSERT INTO op_receipts (op_id, op_type, status, result_type, result_json, completed_at)
			VALUES (?, ?, 'completed', ?, ?, ?)
			ON CONFLICT(op_id) DO UPDATE SET status='completed', result_type=?, result_json=?, completed_at=?
		`, id, opType, resultType, string(raw), now, resultType, string(raw), now); err != nil {
			rollback()
			return err
		}
	}
	res, err := tx.Exec(`
		UPDATE `+tbl+` SET status = ?, completed_at = ?, revision = revision + 1
		WHERE id = ? AND status IN ('executing', 'dispatching')
	`, status, &now, id)
	if err != nil {
		rollback()
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		rollback()
		return fmt.Errorf("operation not in finalizable state")
	}
	return tx.Commit()
}

func finalizeOutcome(status, resultType string) string {
	if status == types.StatusCompleted && resultType != "" {
		return "completed"
	}
	return status
}

// ReconcileExecuting runs at startup before any new execution work (SC-07).
// Stage-aware: ops still in executing never crossed the dispatch barrier,
// so no side effect could have started and they close as failed; ops in
// dispatching may have caused an external effect and become uncertain with
// a documented reconciliation path. Orphaned open attempts are closed.
// Returns counts of (failed, uncertain).
func (d *DB) ReconcileExecuting() (failed, uncertain int, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	rollback := func() { _ = tx.Rollback() }
	now := time.Now()
	var f1, u1, f2, u2 int64
	if n, err := d.reconcileTable(tx, "uses", now); err != nil {
		rollback()
		return 0, 0, err
	} else {
		f1, u1 = n[0], n[1]
	}
	// A recipient-pull dispatch record is committed before delivery bytes
	// are returned. A claimed ticket whose transfer reached dispatching but
	// has no record therefore provably did not release credential material.
	// Close it as a pre-dispatch failure so handoff reconciliation may safely
	// restore the original, unexpired authorization.
	preDispatchHandoff, err := tx.Exec(`UPDATE transfers SET status='failed',completed_at=?,revision=revision+1
		WHERE status='dispatching'
		AND EXISTS(SELECT 1 FROM handoff_tickets h WHERE h.operation_id=transfers.id AND h.state='claimed')
		AND NOT EXISTS(SELECT 1 FROM dispatch_records d WHERE d.op_id=transfers.id)`, now)
	if err != nil {
		rollback()
		return 0, 0, err
	}
	f2, _ = preDispatchHandoff.RowsAffected()
	if n, err := d.reconcileTable(tx, "transfers", now); err != nil {
		rollback()
		return 0, 0, err
	} else {
		f2 += n[0]
		u2 = n[1]
	}
	if _, err := tx.Exec(`
		UPDATE execution_attempts SET outcome = 'orphaned', finished_at = ?
		WHERE outcome = 'started' AND op_id IN (
			SELECT id FROM uses WHERE status IN ('failed', 'uncertain')
			UNION ALL
			SELECT id FROM transfers WHERE status IN ('failed', 'uncertain'))
	`, &now); err != nil {
		rollback()
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return int(f1 + f2), int(u1 + u2), nil
}

func (d *DB) reconcileTable(tx *sql.Tx, tbl string, now time.Time) ([2]int64, error) {
	r1, err := tx.Exec(`UPDATE `+tbl+` SET status = 'failed', completed_at = ?, revision = revision + 1 WHERE status = 'executing'`, &now)
	if err != nil {
		return [2]int64{}, err
	}
	r2, err := tx.Exec(`UPDATE `+tbl+` SET status = 'uncertain', completed_at = ?, revision = revision + 1 WHERE status = 'dispatching'`, &now)
	if err != nil {
		return [2]int64{}, err
	}
	f, _ := r1.RowsAffected()
	u, _ := r2.RowsAffected()
	return [2]int64{f, u}, nil
}
