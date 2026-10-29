package metadata

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

const (
	capsuleCleanupGenerationKey = "sealed_capsule_cleanup_generation"
	capsuleCleanupCheckpointKey = "sealed_capsule_cleanup_checkpointed"
)

// PruneSealedCapsuleBytes removes cached recipient-encrypted packages once
// their operation expires or reaches a final state. It preserves the dispatch
// digest, byte count, handoff ID, and transfer state needed to reconcile a
// receipt after a lost acknowledgment. secure_delete zeros freed database
// pages; the durable generation marker retries a WAL truncate checkpoint if a
// concurrent reader temporarily prevents it.
func (d *DB) PruneSealedCapsuleBytes(now time.Time) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`UPDATE dispatch_records SET capsule_bytes=X''
		WHERE handoff_mode=? AND length(capsule_bytes)>0 AND EXISTS(
			SELECT 1 FROM transfers t WHERE t.id=dispatch_records.op_id
			AND (t.expires_at<=? OR t.status IN ('completed','failed','rejected','expired','cancelled'))
		)`, types.HandoffSealedCapsule, now)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	pruned, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if pruned > 0 {
		generation, err := readCleanupGeneration(tx, capsuleCleanupGenerationKey)
		if err != nil {
			_ = tx.Rollback()
			return pruned, err
		}
		if _, err := tx.Exec(`INSERT INTO broker_state(key,value,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
			capsuleCleanupGenerationKey, strconv.FormatInt(generation+1, 10), now); err != nil {
			_ = tx.Rollback()
			return pruned, err
		}
	}
	generation, err := readCleanupGeneration(tx, capsuleCleanupGenerationKey)
	if err != nil {
		_ = tx.Rollback()
		return pruned, err
	}
	checkpointed, err := readCleanupGeneration(tx, capsuleCleanupCheckpointKey)
	if err != nil {
		_ = tx.Rollback()
		return pruned, err
	}
	if err := tx.Commit(); err != nil {
		return pruned, err
	}
	if generation <= checkpointed {
		return pruned, nil
	}

	var busy, logPages, checkpointedPages int
	if err := d.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &checkpointedPages); err != nil {
		return pruned, err
	}
	if busy != 0 || (logPages >= 0 && checkpointedPages < logPages) {
		return pruned, fmt.Errorf("capsule WAL cleanup checkpoint is busy")
	}

	tx, err = d.db.Begin()
	if err != nil {
		return pruned, err
	}
	_, err = tx.Exec(`INSERT INTO broker_state(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET
		value=CASE WHEN CAST(broker_state.value AS INTEGER)<CAST(excluded.value AS INTEGER)
			THEN excluded.value ELSE broker_state.value END,
		updated_at=excluded.updated_at`, capsuleCleanupCheckpointKey, strconv.FormatInt(generation, 10), now)
	if err != nil {
		_ = tx.Rollback()
		return pruned, err
	}
	if err := tx.Commit(); err != nil {
		return pruned, err
	}
	return pruned, nil
}

func readCleanupGeneration(tx *sql.Tx, key string) (int64, error) {
	var value string
	err := tx.QueryRow(`SELECT value FROM broker_state WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	generation, err := strconv.ParseInt(value, 10, 64)
	if err != nil || generation < 0 {
		return 0, fmt.Errorf("invalid sealed capsule cleanup generation")
	}
	return generation, nil
}
