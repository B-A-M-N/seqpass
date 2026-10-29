package metadata

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func insertRetentionCapsule(t *testing.T, db *DB, opID, status string, expires time.Time, capsule []byte) (string, int) {
	t.Helper()
	digest := fmt.Sprintf("%x", sha256.Sum256(capsule))
	if _, err := db.db.Exec(`INSERT INTO transfers(id,destination_id,expires_at,status,requested_by,dest_digest,revision,auth_epoch,dest_revision,op_hash,created_at)
		VALUES(?,?,?,?,?, 'destination-digest', 1,1,1,'op-hash',?)`, opID, "dest-"+opID, expires, status, "uid:1000", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO execution_attempts(id,op_type,op_id,worker,started_at,finished_at,outcome)
		VALUES(?, 'transfer', ?, 'test', ?, ?, 'uncertain')`, "attempt-"+opID, opID, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO dispatch_records(op_id,attempt_id,dest_id,dest_endpoint,dest_expected_uid,dest_config_digest,payload_digest,payload_bytes,capsule_bytes,handoff_mode,handoff_id,recorded_at)
		VALUES(?,?,?,'',1000,'destination-digest',?,?,?,?,?,?)`, opID, "attempt-"+opID, "dest-"+opID, digest, len(capsule), capsule, types.HandoffSealedCapsule, "handoff-"+opID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return digest, len(capsule)
}

func TestPruneSealedCapsulesByExpiryAndSettlementPreservesReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	live := []byte("synthetic-live-ciphertext-marker")
	expired := []byte("synthetic-expired-ciphertext-marker")
	settled := []byte("synthetic-settled-ciphertext-marker")
	insertRetentionCapsule(t, db, "live", types.StatusUncertain, now.Add(time.Hour), live)
	expiredDigest, expiredBytes := insertRetentionCapsule(t, db, "expired", types.StatusUncertain, now.Add(-time.Minute), expired)
	insertRetentionCapsule(t, db, "settled", types.StatusCompleted, now.Add(time.Hour), settled)
	var secureDelete int
	if err := db.db.QueryRow(`PRAGMA secure_delete`).Scan(&secureDelete); err != nil || secureDelete != 1 {
		t.Fatalf("SQLite secure_delete=%d err=%v, want enabled", secureDelete, err)
	}
	pruned, err := db.PruneSealedCapsuleBytes(now)
	if err != nil || pruned != 2 {
		t.Fatalf("pruned=%d err=%v, want two expired/final capsules", pruned, err)
	}
	for _, tc := range []struct {
		opID       string
		wantLength int
	}{
		{"live", len(live)}, {"expired", 0}, {"settled", 0},
	} {
		var gotLength, gotPayloadBytes int
		var gotDigest string
		if err := db.db.QueryRow(`SELECT length(capsule_bytes),payload_bytes,payload_digest FROM dispatch_records WHERE op_id=?`, tc.opID).Scan(&gotLength, &gotPayloadBytes, &gotDigest); err != nil {
			t.Fatal(err)
		}
		if gotLength != tc.wantLength {
			t.Fatalf("%s capsule length=%d, want %d", tc.opID, gotLength, tc.wantLength)
		}
		if tc.opID == "expired" && (gotDigest != expiredDigest || gotPayloadBytes != expiredBytes) {
			t.Fatalf("expired dispatch evidence changed: digest=%q bytes=%d", gotDigest, gotPayloadBytes)
		}
	}
	// Expiry deletes only the cached package. The immutable digest and byte
	// count still allow an already-applied recipient result to reconcile.
	if err := db.ReconcileHandoff("expired", 1000, expiredDigest, "applied", expiredBytes, now, nil); err != nil {
		t.Fatalf("receipt reconciliation after capsule pruning failed: %v", err)
	}
	var status string
	if err := db.db.QueryRow(`SELECT status FROM transfers WHERE id='expired'`).Scan(&status); err != nil || status != types.StatusCompleted {
		t.Fatalf("reconciled status=%q err=%v", status, err)
	}
	if n, err := db.PruneSealedCapsuleBytes(now); err != nil || n != 0 {
		t.Fatalf("repeat cleanup pruned=%d err=%v, want idempotent no-op", n, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{path, path + "-wal"} {
		contents, err := os.ReadFile(filename)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, marker := range [][]byte{expired, settled} {
			if bytes.Contains(contents, marker) {
				t.Fatalf("pruned ciphertext remains in %s", filename)
			}
		}
	}
}

func TestPruneSealedCapsulesRetriesBlockedWALCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	marker := []byte("synthetic-checkpoint-retry-ciphertext")
	insertRetentionCapsule(t, db, "retry", types.StatusCompleted, now.Add(time.Hour), marker)
	reader, err := sql.Open("sqlite3", path+"?mode=rw&_journal_mode=WAL&_busy_timeout=100&_txlock=deferred")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	readTx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := readTx.QueryRow(`SELECT COUNT(*) FROM dispatch_records`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	pruned, err := db.PruneSealedCapsuleBytes(now)
	if pruned != 1 {
		t.Fatalf("pruned=%d, want 1", pruned)
	}
	var generation, checkpointed string
	if err := db.db.QueryRow(`SELECT value FROM broker_state WHERE key=?`, capsuleCleanupGenerationKey).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT value FROM broker_state WHERE key=?`, capsuleCleanupCheckpointKey).Scan(&checkpointed); err == nil {
		gen, _ := strconv.Atoi(generation)
		clean, _ := strconv.Atoi(checkpointed)
		if clean >= gen {
			t.Fatalf("checkpoint state advanced while an older reader pinned the WAL: generation=%s checkpointed=%s", generation, checkpointed)
		}
	} else if err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if pruned, err := db.PruneSealedCapsuleBytes(now); err != nil || pruned != 0 {
		t.Fatalf("retry cleanup pruned=%d err=%v", pruned, err)
	}
	if err := db.db.QueryRow(`SELECT value FROM broker_state WHERE key=?`, capsuleCleanupGenerationKey).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT value FROM broker_state WHERE key=?`, capsuleCleanupCheckpointKey).Scan(&checkpointed); err != nil {
		t.Fatal(err)
	}
	if generation != checkpointed {
		t.Fatalf("cleanup checkpoint remains pending after reader exit: generation=%s checkpointed=%s", generation, checkpointed)
	}
}
