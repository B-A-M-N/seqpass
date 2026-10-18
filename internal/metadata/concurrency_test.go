package metadata

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The database carries protected metadata; a world-readable store would be a
// boundary failure, so the file (and any sidecar present) must be owner-only
// as soon as the schema exists, whatever the process umask was.
func TestNewDBRestrictsDatabaseFilePermissions(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	path := filepath.Join(t.TempDir(), "meta.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		t.Fatalf("database mode = %v, want owner-only", perm)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		st, err := os.Stat(sidecar)
		if err != nil {
			continue // not created yet; SQLite inherits the database mode
		}
		if perm := st.Mode().Perm(); perm&0077 != 0 {
			t.Fatalf("%s mode = %v, want owner-only", sidecar, perm)
		}
	}
}

// must not fail immediately with "database is locked".
//
// SQLite detects the shared-to-reserved lock upgrade conflict within one
// process and returns SQLITE_BUSY without invoking the busy handler, so a 5s
// busy timeout does not help. That is the intermittent flake the socket
// suites used to hit right after broker start, and it must not come back:
// the production connection string avoids the upgrade with _txlock=immediate
// and avoids non-retried table locks by not using a shared cache.
func TestConcurrentReadThenWriteTransactionsDoNotLockUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	a, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	handles := []*sql.DB{a.db, b.db}
	const (
		workers    = 6
		iterations = 30
	)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	// Alternate handles so both connections hold SHARED and want RESERVED
	// at the same time.
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			h := handles[worker%len(handles)]
			for i := 0; i < iterations; i++ {
				err := func() error {
					tx, err := h.Begin()
					if err != nil {
						return err
					}
					var n int
					if err := tx.QueryRow(`SELECT COUNT(*) FROM secret_refs`).Scan(&n); err != nil {
						_ = tx.Rollback()
						return err
					}
					id := fmt.Sprintf("w%d-%d", worker, i)
					if _, err := tx.Exec(`INSERT INTO secret_refs (id, name, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, id, "n"); err != nil {
						_ = tx.Rollback()
						return err
					}
					return tx.Commit()
				}()
				if err != nil {
					mu.Lock()
					errs = append(errs, err.Error())
					mu.Unlock()
					return
				}
			}
		}(worker)
	}
	wg.Wait()

	locked := 0
	for _, e := range errs {
		if strings.Contains(strings.ToLower(e), "locked") {
			locked++
		}
	}
	if len(errs) != 0 {
		t.Fatalf("%d concurrent transactions failed (%d of them 'locked'): %v", len(errs), locked, errs[:min(5, len(errs))])
	}
	// Every transaction committed exactly once: no silent data loss behind
	// a retry.
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM secret_refs`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != workers*iterations {
		t.Fatalf("expected %d committed rows, found %d", workers*iterations, total)
	}
}
