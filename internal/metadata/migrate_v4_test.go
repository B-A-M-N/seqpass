package metadata

import (
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

// v3 -> v4 repair: destinations gains source_repo (the git.push pinned
// source repository, part of the destination digest). A database written
// by a v3 build lacks the column; the repair path must add it with its
// non-null default and stamp version 4.
func TestV3DestinationsRepairAddsSourceRepo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a real destination row at the current version, then degrade the
	// table to the v3 shape (drop the new column) and stamp v3.
	if err := db.CreateDestination(&types.Destination{
		ID: "d1", Name: "n", Type: "git-pinned", Endpoint: "https://git.example.com/o/r.git",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`ALTER TABLE destinations DROP COLUMN source_repo`); err != nil {
		t.Fatalf("degrade to v3 shape: %v", err)
	}
	if _, err := db.db.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	db2, err := NewDB(path)
	if err != nil {
		t.Fatalf("v3 migration failed: %v", err)
	}
	defer db2.Close()

	var v int
	if err := db2.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("version not stamped: v=%d err=%v", v, err)
	}
	dest, err := db2.GetDestination("d1")
	if err != nil || dest == nil {
		t.Fatalf("repaired destination unreadable: %v", err)
	}
	if dest.SourceRepo != "" {
		t.Fatalf("repaired column must carry the empty default, got %q", dest.SourceRepo)
	}
}
