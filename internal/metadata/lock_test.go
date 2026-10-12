package metadata

import (
	"os"
	"path/filepath"
	"testing"
)

// P1-2: one store, many spellings — a symlink alias, a hard link, and a
// ".."-ladder to the same database all contend on the same lease. A
// second broker through any of them is refused while the first is live.
func TestLockRefusesPathAliases(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "m.db")
	a, err := AcquireDBLock(real)
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	defer a.Release()

	alias := filepath.Join(dir, "alias.db")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireDBLock(alias); err == nil {
		t.Fatal("symlink alias acquired a second ownership")
	}

	hard := filepath.Join(dir, "hard.db")
	if err := os.Link(real, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireDBLock(hard); err == nil {
		t.Fatal("hard-link alias acquired a second ownership")
	}

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireDBLock(filepath.Join(sub, "..", "m.db")); err == nil {
		t.Fatal("\"..\"-ladder alias acquired a second ownership")
	}

	a.Release()
	// After release the store is acquirable again — through the alias —
	// and the lease reports the canonical store, not the spelling.
	b, err := AcquireDBLock(alias)
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	defer b.Release()
	if b.CanonicalPath() != real {
		t.Fatalf("canonical path = %q, want %q", b.CanonicalPath(), real)
	}
}

// Two genuinely different databases stay independent.
func TestLockIndependentDatabases(t *testing.T) {
	dir := t.TempDir()
	a, err := AcquireDBLock(filepath.Join(dir, "one.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := AcquireDBLock(filepath.Join(dir, "two.db"))
	if err != nil {
		t.Fatalf("independent database refused: %v", err)
	}
	defer b.Release()
}

// A new database under a symlinked parent is created — and guarded —
// at the resolved location.
func TestCanonicalNewDBUnderSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	l, err := AcquireDBLock(filepath.Join(linkDir, "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	want := filepath.Join(realDir, "new.db")
	if l.CanonicalPath() != want {
		t.Fatalf("canonical path = %q, want %q", l.CanonicalPath(), want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("database not created at canonical location: %v", err)
	}
}
