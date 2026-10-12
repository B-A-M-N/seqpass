package metadata

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// SC-12: a database newer than the supported schema must be rejected, never
// silently interpreted as current state.
func TestFutureVersionRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := NewDB(path); err == nil {
		t.Fatal("future schema version accepted (SC-12)")
	}
}

// SC-12: a database already at the current version skips repair entirely
// (no backup artifact, no rewrite).
func TestCurrentVersionSkipsRepair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := NewDB(path); err != nil {
		t.Fatal(err)
	}
	// WAL sidecars are normal; a repair backup is not.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".bak" {
				t.Fatalf("current-version open wrote a repair backup: %v", entries)
			}
		}
	}
}

// SC-12: a legacy (user_version 0) database takes the repair path: missing
// columns are added, unprovable live approvals are quarantined as failed,
// a recoverable backup is preserved, and the version is stamped.
func TestLegacyRepairQuarantineAndBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the transfers table in a legacy shape (no approval bindings).
	if _, err := db.db.Exec(`DROP TABLE transfers`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TABLE transfers (
	  id TEXT PRIMARY KEY, secret_ref TEXT, destination_id TEXT,
	  status TEXT, requested_by TEXT, revision INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO transfers (id, secret_ref, destination_id, status, requested_by)
	  VALUES ('legacy-op', 's', 'd', 'authorized', 'uid:1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	db2, err := NewDB(path)
	if err != nil {
		t.Fatalf("legacy migration failed: %v", err)
	}
	defer db2.Close()

	var v int
	if err := db2.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("version not stamped: v=%d err=%v", v, err)
	}
	tr, err := db2.GetTransfer("legacy-op")
	if err != nil || tr == nil {
		t.Fatalf("legacy op missing: tr=%v err=%v", tr, err)
	}
	if tr.Status != "failed" {
		t.Fatalf("unprovable legacy approval not quarantined: %s", tr.Status)
	}
	backup := fmt.Sprintf("%s.pre-v%d.bak", path, schemaVersion)
	st, err := os.Stat(backup)
	if err != nil || st.Size() == 0 {
		t.Fatalf("pre-migration backup missing: %v", err)
	}
}
