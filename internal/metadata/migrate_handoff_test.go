package metadata

import (
	"path/filepath"
	"testing"
)

func TestV7MigrationAddsHandoffAndCapsuleSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"ALTER TABLE destinations DROP COLUMN handoff_mode",
		"ALTER TABLE destinations DROP COLUMN issuer_key_id",
		"ALTER TABLE destinations DROP COLUMN issuer_public_key",
		"ALTER TABLE destinations DROP COLUMN receipt_key_id",
		"ALTER TABLE destinations DROP COLUMN receipt_public_key",
		"ALTER TABLE dispatch_records DROP COLUMN payload_bytes",
		"ALTER TABLE dispatch_records DROP COLUMN handoff_mode",
		"ALTER TABLE dispatch_records DROP COLUMN handoff_id",
		"DROP TABLE handoff_tickets",
		"PRAGMA user_version=7",
	} {
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.verifySchema(); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"recipient_key_id", "recipient_public_key", "receipt_key_id", "receipt_public_key", "issuer_key_id", "issuer_public_key", "credential_target"} {
		var count int
		if err := db.db.QueryRow(`SELECT count(*) FROM pragma_table_info('destinations') WHERE name=?`, column).Scan(&count); err != nil || count != 1 {
			t.Fatalf("destination column %s missing: count=%d err=%v", column, count, err)
		}
	}
	var handoffIDColumn int
	if err := db.db.QueryRow(`SELECT count(*) FROM pragma_table_info('dispatch_records') WHERE name='handoff_id'`).Scan(&handoffIDColumn); err != nil || handoffIDColumn != 1 {
		t.Fatalf("dispatch handoff_id missing: count=%d err=%v", handoffIDColumn, err)
	}
	v, err := db.currentVersion()
	if err != nil || v != schemaVersion {
		t.Fatalf("schema version=%d err=%v", v, err)
	}
}
