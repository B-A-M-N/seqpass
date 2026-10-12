package metadata

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// DBLock is a process-lifetime exclusive ownership lease on one state
// store (G05). Startup crash recovery assumes every executing operation
// belongs to a dead process; without a lease, a second broker opening
// the same database would "recover" the first broker's LIVE operations
// into failed/uncertain.
//
// The lease guards the database FILE ITSELF, not a caller-selected
// pathname (P1-2): the path is canonicalized before anything opens it,
// and the flock is taken on an fd of that canonical file — so a symlink
// alias, a hard link, or a ".."-ladder to the same store contends on the
// same lock instead of acquiring a second, independent ownership.
type DBLock struct {
	f    *os.File
	path string
}

// CanonicalDBPath resolves the real database location before the lease
// or SQLite opens it. An existing database resolves through symlinks to
// its real path; a new database canonicalizes its parent directory, so
// creation lands where the operator's path actually points. The result
// identifies the store — never the spelling the caller used.
func CanonicalDBPath(dbPath string) (string, error) {
	if dbPath == "" || dbPath == ":memory:" {
		return dbPath, nil
	}
	if _, err := os.Lstat(dbPath); err == nil {
		real, err := filepath.EvalSymlinks(dbPath)
		if err != nil {
			return "", fmt.Errorf("cannot resolve database path %s: %w", dbPath, err)
		}
		abs, err := filepath.Abs(real)
		if err != nil {
			return "", fmt.Errorf("cannot absolutize database path %s: %w", dbPath, err)
		}
		return abs, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot stat database path %s: %w", dbPath, err)
	}
	parent := filepath.Dir(dbPath)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("cannot resolve database directory for %s: %w", dbPath, err)
	}
	absParent, err := filepath.Abs(realParent)
	if err != nil {
		return "", fmt.Errorf("cannot absolutize database directory for %s: %w", dbPath, err)
	}
	return filepath.Join(absParent, filepath.Base(dbPath)), nil
}

// CanonicalPath is the resolved store this lease actually guards. The
// service must open THIS path — never the caller's original spelling —
// so the guarded file and the live database cannot diverge.
func (l *DBLock) CanonicalPath() string {
	if l == nil {
		return ""
	}
	return l.path
}

// AcquireDBLock takes an exclusive, non-blocking flock on the canonical
// database file itself (creating it 0600 when new). A second broker gets
// a clear diagnostic instead of a shared database — whatever pathname
// spelling it used. Empty and :memory: paths need no lease (no durable
// shared state).
func AcquireDBLock(dbPath string) (*DBLock, error) {
	if dbPath == "" || dbPath == ":memory:" {
		return &DBLock{}, nil
	}
	canon, err := CanonicalDBPath(dbPath)
	if err != nil {
		return nil, err
	}
	// O_NOFOLLOW refuses a last-minute symlink planted at the final
	// component after canonicalization: an untrusted existing symlink
	// is an error, never followed.
	f, err := os.OpenFile(canon, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open broker database %s: %w", canon, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another broker owns this database (%s): %w", canon, err)
	}
	// Confirm the locked fd is still the canonical path's file: a
	// rename swap between open and lock would otherwise guard a
	// detached inode while SQLite opens the replacement.
	var locked, current syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &locked); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot identify locked database %s: %w", canon, err)
	}
	if err := syscall.Stat(canon, &current); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot confirm database identity %s: %w", canon, err)
	}
	if locked.Dev != current.Dev || locked.Ino != current.Ino {
		_ = f.Close()
		return nil, fmt.Errorf("database %s was replaced during lock acquisition", canon)
	}
	return &DBLock{f: f, path: canon}, nil
}

// Release drops the lease. Call after execution workers stop and the
// database is closed — never while live work may still write.
func (l *DBLock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
