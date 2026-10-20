package metadata

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db   *sql.DB
	path string
}

func NewDB(path string) (*DB, error) {
	// The connection string matters for correctness, not just performance.
	//
	// cache=shared is deliberately NOT used: with a shared page cache SQLite
	// takes table-level locks, and a conflict between two connections in the
	// same process is reported as SQLITE_LOCKED, which the busy handler does
	// not retry. Combined with a deferred transaction that reads before it
	// writes, that produced an immediate, intermittent "database is locked"
	// right after broker start.
	//
	// _txlock=immediate makes every database/sql transaction BEGIN IMMEDIATE,
	// so a writer takes the write lock up front instead of upgrading from
	// SHARED to RESERVED mid-transaction. SQLite refuses that upgrade
	// immediately when another connection in the same process holds SHARED,
	// again bypassing the busy handler. With an immediate begin the busy
	// timeout applies and the writer waits its turn.
	db, err := sql.Open("sqlite3", path+"?mode=rwc&_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	d := &DB{db: db, path: path}
	if err := d.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// The database holds protected metadata, and its permissions are a
	// security property: the isolation doctor refuses to verify a topology in
	// which an agent identity can read it. SQLite creates the file with the
	// process umask, so the mode is tightened explicitly, including the WAL
	// sidecars that exist at this point. A file that cannot be restricted is
	// fatal: the broker must not serve from a readable store.
	if err := restrictDatabaseFiles(path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return d, nil
}

// restrictDatabaseFiles forces the SQLite database and its sidecars to owner
// only. It is called after the schema exists so every sidecar that can be
// created eagerly has been created and is covered.
func restrictDatabaseFiles(path string) error {
	if path == "" || path == ":memory:" {
		return nil
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("cannot inspect database file %s: %w", p, err)
		}
		if err := os.Chmod(p, 0600); err != nil {
			return fmt.Errorf("cannot restrict database file %s to 0600: %w", p, err)
		}
	}
	return nil
}

func (d *DB) initSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS authorization_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch INTEGER NOT NULL
);
INSERT OR IGNORE INTO authorization_state (id, epoch) VALUES (1, 1);

CREATE TABLE IF NOT EXISTS secret_refs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  owner TEXT,
  binding TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS destinations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  source_repo TEXT NOT NULL DEFAULT '',
  auth_method TEXT,
  allowed_ops TEXT,
  requires_approval BOOLEAN,
  approved_by TEXT,
  revision INTEGER NOT NULL DEFAULT 1,
  expected_uid INTEGER,
  expected_gid INTEGER,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  rules TEXT,
  priority INTEGER,
  enabled BOOLEAN,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  operation_id TEXT,
  action TEXT,
  actor TEXT,
  target TEXT,
  outcome TEXT,
  metadata TEXT,
  created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY,
  secret_ref TEXT,
  source_kind TEXT,
  source_binding TEXT,
  source_ref TEXT,
  destination_id TEXT,
  payload_ref TEXT,
  expires_at TIMESTAMP,
  status TEXT,
  requested_by TEXT,
  approved_by TEXT,
  revision INTEGER NOT NULL DEFAULT 0,
  auth_epoch INTEGER NOT NULL DEFAULT 1,
  dest_digest TEXT,
  dest_revision INTEGER NOT NULL DEFAULT 0,
  op_hash TEXT,
  created_at TIMESTAMP,
  completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS uses (
  id TEXT PRIMARY KEY,
  secret_ref TEXT,
  source_kind TEXT,
  source_binding TEXT,
  source_ref TEXT,
  operation TEXT,
  target TEXT,
  params TEXT,
  expires_at TIMESTAMP,
  status TEXT,
  requested_by TEXT,
  approved_by TEXT,
  revision INTEGER NOT NULL DEFAULT 0,
  auth_epoch INTEGER NOT NULL DEFAULT 1,
  dest_digest TEXT,
  dest_revision INTEGER NOT NULL DEFAULT 0,
  op_hash TEXT,
  created_at TIMESTAMP,
  completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS execution_attempts (
  id TEXT PRIMARY KEY,
  op_type TEXT NOT NULL,
  op_id TEXT NOT NULL,
  worker TEXT NOT NULL,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  outcome TEXT NOT NULL DEFAULT 'started'
);
CREATE INDEX IF NOT EXISTS attempt_op_idx ON execution_attempts(op_id);

CREATE TABLE IF NOT EXISTS op_receipts (
  op_id TEXT PRIMARY KEY,
  op_type TEXT NOT NULL,
  status TEXT NOT NULL,
  result_type TEXT NOT NULL,
  result_json TEXT NOT NULL,
  completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS relay_requests (
  id TEXT PRIMARY KEY,
  agent_principal TEXT NOT NULL,
  intake_owner TEXT NOT NULL DEFAULT '',
  destination_id TEXT NOT NULL,
  dest_revision INTEGER NOT NULL DEFAULT 0,
  dest_digest TEXT NOT NULL DEFAULT '',
  data_kind TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  consumption TEXT NOT NULL,
  max_deliveries INTEGER NOT NULL DEFAULT 1,
  used_deliveries INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMP,
  revision INTEGER NOT NULL DEFAULT 1,
  op_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS relay_state_idx ON relay_requests(state, created_at);
CREATE INDEX IF NOT EXISTS relay_agent_idx ON relay_requests(agent_principal, created_at);

-- F08: per-operation delivery accounting for concurrent reusable relays.
-- One row per (relay, operation) reservation; the budget refund requires
-- an exact reservation row, marked idempotently so repeated finalization
-- cannot decrement the same allocation twice.
CREATE TABLE IF NOT EXISTS relay_deliveries (
  relay_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'reserved',
  dest_digest TEXT NOT NULL DEFAULT '',
  dest_revision INTEGER NOT NULL DEFAULT 0,
  terminal_outcome TEXT NOT NULL DEFAULT '',
  refunded INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP,
  completed_at TIMESTAMP,
  PRIMARY KEY (relay_id, operation_id)
);
CREATE INDEX IF NOT EXISTS relay_deliveries_relay_idx ON relay_deliveries(relay_id, state);

CREATE TABLE IF NOT EXISTS host_sessions (
  id TEXT PRIMARY KEY,
  host_kind TEXT NOT NULL,
  agent_principal TEXT NOT NULL,
  human_principal TEXT NOT NULL,
  thread_id TEXT,
  expires_at TIMESTAMP,
  revision INTEGER NOT NULL DEFAULT 1,
  input_mode TEXT NOT NULL DEFAULT '',
  input_assurance TEXT NOT NULL DEFAULT '',
  input_reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS host_session_agent_idx ON host_sessions(agent_principal, expires_at);

CREATE TABLE IF NOT EXISTS host_principal_bindings (
  human_principal TEXT NOT NULL,
  agent_principal TEXT NOT NULL,
  host_kind TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  PRIMARY KEY (human_principal, agent_principal, host_kind)
);
CREATE INDEX IF NOT EXISTS host_binding_lookup_idx ON host_principal_bindings(human_principal, host_kind, expires_at);

CREATE TABLE IF NOT EXISTS relay_host_sessions (
  relay_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  agent_principal TEXT NOT NULL,
  human_principal TEXT NOT NULL,
  host_kind TEXT NOT NULL,
  created_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS relay_host_session_idx ON relay_host_sessions(session_id);

CREATE TABLE IF NOT EXISTS host_session_tokens (
  session_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMP,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  FOREIGN KEY(session_id) REFERENCES host_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ephemeral_payloads (
  ref TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  expires_at TIMESTAMP,
  created_by TEXT,
  created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outcome_observations (
  observation_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL DEFAULT '',
  verifier_id TEXT NOT NULL,
  verifier_version TEXT NOT NULL,
  state TEXT NOT NULL,
  observed_at TIMESTAMP,
  recorded_at TIMESTAMP,
  evidence_digest TEXT NOT NULL,
  evidence_kind TEXT NOT NULL DEFAULT 'assertion',
  observation_source TEXT NOT NULL,
  details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS obs_op_idx ON outcome_observations(operation_id, observed_at);

CREATE TABLE IF NOT EXISTS dispatch_records (
  op_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  dest_id TEXT NOT NULL,
  dest_endpoint TEXT NOT NULL,
  dest_expected_uid INTEGER NOT NULL,
  dest_expected_gid INTEGER,
  dest_config_digest TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  recorded_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outcome_observations (
  observation_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL DEFAULT '',
  verifier_id TEXT NOT NULL,
  verifier_version TEXT NOT NULL,
  state TEXT NOT NULL,
  observed_at TIMESTAMP,
  evidence_digest TEXT NOT NULL,
  observation_source TEXT NOT NULL,
  details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS obs_op_idx ON outcome_observations(operation_id, observed_at);
`
	if _, err := d.db.Exec(schema); err != nil {
		return err
	}
	// Numbered repair migration for DBs created by older builds (C08).
	// Every column is added only after inspecting the live schema; any
	// unexpected SQL error is fatal instead of silently ignored. Legacy
	// live operations whose approval bindings cannot be proven are
	// quarantined (marked failed) so they can never execute under the new
	// authorization model with defaulted epoch/digest semantics.
	if err := d.migrate(); err != nil {
		return err
	}
	return d.verifySchema()
}

// schemaVersion is the current numbered schema version. Version 1 added
// the approval-binding repair columns; version 2 adds the trusted
// dispatch record, observation record/commit timestamps, and evidence
// kinds (G02/G07); version 3 added the auth-epoch and destination-digest
// binding columns; version 4 adds the git.push pinned source repository
// (a security binding: it participates in the destination digest); version
// 5 adds broker_state (the persisted executor ATTEST PUBLIC key half for
// restart rotation detection — the private key never leaves non-dumpable
// memory). Older databases take the repair path below.
const schemaVersion = 5

func (d *DB) currentVersion() (int, error) {
	var v int
	if err := d.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// migrate is the version-aware migration dispatch (SC-12). Databases newer
// than the supported version are rejected outright — newer state must never
// be silently interpreted as current state. Databases already at the current
// version skip the repair logic entirely; only older databases take the
// repair + quarantine path, after a recoverable file backup.
func (d *DB) migrate() error {
	v, err := d.currentVersion()
	if err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("unsupported database schema version %d (broker supports %d): refusing to interpret newer state", v, schemaVersion)
	}
	if v == schemaVersion {
		return nil
	}
	if err := d.backupPreMigration(v); err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	cols := func(table string) (map[string]bool, error) {
		rows, err := tx.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, err
			}
			out[name] = true
		}
		return out, rows.Err()
	}
	ensureColumn := func(table, column, ddl string) error {
		have, err := cols(table)
		if err != nil {
			return err
		}
		if have[column] {
			return nil
		}
		// policy_revision -> auth_epoch rename from early builds: rename
		// instead of adding a defaulted column when the old name exists.
		if column == "auth_epoch" {
			if have["policy_revision"] {
				if _, err := tx.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN policy_revision TO auth_epoch`); err != nil {
					return err
				}
				return nil
			}
		}
		if _, err := tx.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + ddl); err != nil {
			return err
		}
		return nil
	}
	repairs := []struct{ table, column, ddl string }{
		{"destinations", "revision", "revision INTEGER NOT NULL DEFAULT 1"},
		{"policies", "revision", "revision INTEGER NOT NULL DEFAULT 1"},
		{"transfers", "source_kind", "source_kind TEXT"},
		{"transfers", "source_binding", "source_binding TEXT"},
		{"transfers", "source_ref", "source_ref TEXT"},
		{"transfers", "revision", "revision INTEGER NOT NULL DEFAULT 0"},
		{"transfers", "op_hash", "op_hash TEXT"},
		{"uses", "source_kind", "source_kind TEXT"},
		{"uses", "source_binding", "source_binding TEXT"},
		{"uses", "source_ref", "source_ref TEXT"},
		{"uses", "revision", "revision INTEGER NOT NULL DEFAULT 0"},
		{"uses", "op_hash", "op_hash TEXT"},
		{"secret_refs", "binding", "binding TEXT"},
		{"transfers", "auth_epoch", "auth_epoch INTEGER NOT NULL DEFAULT 1"},
		{"uses", "auth_epoch", "auth_epoch INTEGER NOT NULL DEFAULT 1"},
		{"transfers", "dest_digest", "dest_digest TEXT"},
		{"transfers", "dest_revision", "dest_revision INTEGER NOT NULL DEFAULT 0"},
		{"uses", "dest_digest", "dest_digest TEXT"},
		{"uses", "dest_revision", "dest_revision INTEGER NOT NULL DEFAULT 0"},
		{"destinations", "expected_uid", "expected_uid INTEGER"},
		{"destinations", "expected_gid", "expected_gid INTEGER"},
		{"destinations", "source_repo", "source_repo TEXT NOT NULL DEFAULT ''"},
		// Full read/write shape: the code SELECTs and INSERTs every
		// column below, so a legacy table missing any of them is
		// unusable until repaired — not just the security bindings.
		// Repaired columns carry non-null defaults (readers stay strict
		// by design); repaired rows are quarantined below when their
		// approval bindings cannot be proven.
		{"transfers", "payload_ref", "payload_ref TEXT NOT NULL DEFAULT ''"},
		{"transfers", "expires_at", "expires_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00'"},
		{"transfers", "approved_by", "approved_by TEXT NOT NULL DEFAULT ''"},
		{"transfers", "created_at", "created_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00'"},
		{"transfers", "completed_at", "completed_at TIMESTAMP"},
		{"uses", "operation", "operation TEXT NOT NULL DEFAULT ''"},
		{"uses", "target", "target TEXT NOT NULL DEFAULT ''"},
		{"uses", "params", "params TEXT NOT NULL DEFAULT ''"},
		{"uses", "payload_ref", "payload_ref TEXT NOT NULL DEFAULT ''"},
		{"uses", "expires_at", "expires_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00'"},
		{"uses", "approved_by", "approved_by TEXT NOT NULL DEFAULT ''"},
		{"uses", "created_at", "created_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00'"},
		{"uses", "completed_at", "completed_at TIMESTAMP"},
	}
	for _, r := range repairs {
		if err := ensureColumn(r.table, r.column, r.ddl); err != nil {
			rollback()
			return err
		}
	}
	// Version 2 ensures (G02/G07): the trusted dispatch record and the
	// observation provenance columns. CREATE IF NOT EXISTS covers legacy
	// databases that predate the tables; ensureColumn backfills columns
	// on tables created by intermediate builds.
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS dispatch_records (
	  op_id TEXT PRIMARY KEY,
	  attempt_id TEXT NOT NULL,
	  dest_id TEXT NOT NULL,
	  dest_endpoint TEXT NOT NULL,
	  dest_expected_uid INTEGER NOT NULL,
	  dest_expected_gid INTEGER,
	  dest_config_digest TEXT NOT NULL,
	  payload_digest TEXT NOT NULL,
	  recorded_at TIMESTAMP
	)`); err != nil {
		rollback()
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS relay_deliveries (
	  relay_id TEXT NOT NULL,
	  operation_id TEXT NOT NULL,
	  state TEXT NOT NULL DEFAULT 'reserved',
	  dest_digest TEXT NOT NULL DEFAULT '',
	  dest_revision INTEGER NOT NULL DEFAULT 0,
	  terminal_outcome TEXT NOT NULL DEFAULT '',
	  refunded INTEGER NOT NULL DEFAULT 0,
	  created_at TIMESTAMP,
	  completed_at TIMESTAMP,
	  PRIMARY KEY (relay_id, operation_id)
	)`); err != nil {
		rollback()
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS outcome_observations (
	  observation_id TEXT PRIMARY KEY,
	  operation_id TEXT NOT NULL,
	  attempt_id TEXT NOT NULL DEFAULT '',
	  verifier_id TEXT NOT NULL,
	  verifier_version TEXT NOT NULL,
	  state TEXT NOT NULL,
	  observed_at TIMESTAMP,
	  recorded_at TIMESTAMP,
	  evidence_digest TEXT NOT NULL,
	  evidence_kind TEXT NOT NULL DEFAULT 'assertion',
	  observation_source TEXT NOT NULL,
	  details TEXT NOT NULL
	)`); err != nil {
		rollback()
		return err
	}
	for _, r := range []struct{ table, column, ddl string }{
		{"outcome_observations", "recorded_at", "recorded_at TIMESTAMP"},
		{"outcome_observations", "evidence_kind", "evidence_kind TEXT NOT NULL DEFAULT 'assertion'"},
	} {
		if err := ensureColumn(r.table, r.column, r.ddl); err != nil {
			rollback()
			return err
		}
	}
	// Version 5 ensure (P0-1 restart strategy): broker_state persists the
	// executor's attest PUBLIC key half so a restart can detect rotation.
	// The PRIVATE key is never persisted — it lives only in the broker's
	// non-dumpable memory, which is the same-UID-unreadable store the
	// attestation scheme's security rests on. A restart regenerates it;
	// the persisted public half lets the broker tell the operator exactly
	// which grant pin needs re-enrollment.
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS broker_state (
	  key TEXT PRIMARY KEY,
	  value TEXT NOT NULL,
	  updated_at TIMESTAMP
	)`); err != nil {
		rollback()
		return err
	}
	// Quarantine: live legacy operations missing any approval binding
	// (epoch, hash or digest) can never be proven valid. Mark them failed
	// inside the same transaction so no restart can resurrect them.
	for _, tbl := range []string{"transfers", "uses"} {
		if _, err := tx.Exec(`UPDATE ` + tbl + ` SET status = 'failed'
			WHERE status IN ('requested', 'pending_approval', 'authorized', 'claimed', 'executing')
		  AND (auth_epoch IS NULL OR op_hash IS NULL OR dest_digest IS NULL)`); err != nil {
			rollback()
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

// backupPreMigration preserves a recoverable copy before any destructive
// migration step (the quarantine UPDATEs below). VACUUM INTO cannot run
// inside a transaction, so it happens before the migration transaction
// begins; any backup failure aborts the migration fail-closed with the
// original database untouched. Non-file databases (empty/:memory:) skip the
// file backup — they hold no durable state worth preserving.
func (d *DB) backupPreMigration(from int) error {
	if d.path == "" || d.path == ":memory:" {
		return nil
	}
	// Nothing durable to preserve in a fresh database: skip the backup
	// so normal first startups (user_version 0, no rows) stay quiet.
	var rows int
	for _, tbl := range []string{"transfers", "uses", "policies", "destinations", "secret_refs"} {
		var n int
		if err := d.db.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil {
			return err
		}
		rows += n
	}
	if rows == 0 {
		return nil
	}
	// VACUUM INTO takes no bound parameters; refuse quote-bearing paths
	// rather than interpolating them into SQL.
	if strings.Contains(d.path, "'") {
		return fmt.Errorf("refusing migration backup for quoted db path")
	}
	backup := fmt.Sprintf("%s.pre-v%d.bak", d.path, schemaVersion)
	// VACUUM INTO refuses to overwrite; a stale backup from an earlier
	// attempt must not block recovery — replace it.
	_ = os.Remove(backup)
	if _, err := d.db.Exec(`VACUUM INTO '` + backup + `'`); err != nil {
		return fmt.Errorf("pre-migration backup failed: %w", err)
	}
	return nil
}

// verifySchema asserts the post-migration shape: every expected table and
// security-critical column present, exactly one authorization row.
func (d *DB) verifySchema() error {
	expected := map[string][]string{
		"authorization_state":     {"id", "epoch"},
		"secret_refs":             {"id", "name", "binding"},
		"destinations":            {"id", "endpoint", "source_repo", "revision", "expected_uid", "expected_gid"},
		"policies":                {"id", "rules", "revision"},
		"transfers":               {"id", "status", "revision", "auth_epoch", "dest_digest", "dest_revision", "op_hash"},
		"uses":                    {"id", "status", "revision", "auth_epoch", "dest_digest", "dest_revision", "op_hash"},
		"execution_attempts":      {"id", "op_id", "worker", "outcome"},
		"op_receipts":             {"op_id", "status", "result_json"},
		"outcome_observations":    {"observation_id", "operation_id", "state", "recorded_at", "evidence_kind"},
		"dispatch_records":        {"op_id", "payload_digest", "dest_endpoint"},
		"relay_requests":          {"id", "agent_principal", "destination_id", "state", "consumption", "expires_at", "revision"},
		"host_principal_bindings": {"human_principal", "agent_principal", "host_kind", "expires_at", "revision"},
		"relay_host_sessions":     {"relay_id", "session_id", "agent_principal", "human_principal", "host_kind"},
		"host_sessions":           {"id", "host_kind", "agent_principal", "human_principal", "expires_at", "revision", "input_mode", "input_assurance", "input_reason"},
	}
	for table, columns := range expected {
		rows, err := d.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			have[name] = true
		}
		rows.Close()
		for _, c := range columns {
			if !have[c] {
				return fmt.Errorf("schema verification failed: %s.%s missing", table, c)
			}
		}
	}
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM authorization_state WHERE id = 1`).Scan(&n); err != nil || n != 1 {
		return fmt.Errorf("schema verification failed: authorization_state corrupt")
	}
	return nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

// CurrentEpoch returns the global authorization epoch. Any change to policy
// rules/enablement, destinations, or secret bindings bumps it; approvals and
// claims are bound to the epoch they were evaluated under.
func (d *DB) CurrentEpoch() (int64, error) {
	var epoch int64
	err := d.db.QueryRow(`SELECT epoch FROM authorization_state WHERE id = 1`).Scan(&epoch)
	return epoch, err
}

// GetBrokerState reads one persisted broker_state value ("", nil) when
// absent. Used for the attest public key half (restart rotation
// detection) and future broker-level durable state.
func (d *DB) GetBrokerState(key string) (string, bool, error) {
	var value string
	err := d.db.QueryRow(`SELECT value FROM broker_state WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetBrokerState upserts one broker_state value. It deliberately does NOT
// bump the authorization epoch: this is broker-local identity state, not
// an authorization-relevant mutation.
func (d *DB) SetBrokerState(key, value string) error {
	_, err := d.db.Exec(`INSERT INTO broker_state (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now())
	return err
}

// withAuthMutation runs fn inside a single IMMEDIATE transaction and bumps
// the global authorization epoch in the same transaction. Either both the
// mutation and the epoch increment commit, or both roll back: a committed
// policy/destination/binding change can never leave outstanding approvals
// valid under a stale epoch (C03). All authorization-relevant mutations
// must go through this helper.
func (d *DB) withAuthMutation(fn func(tx *sql.Tx) error) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	// IMMEDIATE reserves the write lock up front so the mutation and the
	// epoch bump serialize against concurrent claims.
	if _, err := tx.Exec(`SELECT epoch FROM authorization_state WHERE id = 1`); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE authorization_state SET epoch = epoch + 1 WHERE id = 1`); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	var epoch int64
	if err := tx.QueryRow(`SELECT epoch FROM authorization_state WHERE id = 1`).Scan(&epoch); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return epoch, nil
}
