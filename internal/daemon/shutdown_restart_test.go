package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// SP-20: daemon shutdown and restart under an active database must preserve
// the authoritative state — a new broker cannot start while the old lease
// is held, and after the old broker shuts down, the new broker reconciles
// correctly.
func TestDaemonShutdownRestartCycle(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Skipf("sandbox does not support trusted socket dir: %v", err)
	}
	cfg := Config{
		DBPath:      filepath.Join(dir, "restart.db"),
		SocketPath:  filepath.Join(dir, "a.sock"),
		AdminSocket: filepath.Join(dir, "a.sock.admin"),
		VaultType:   "memory-test",
	}
	d1, err := New(cfg)
	if err != nil {
		t.Fatalf("first broker: %v", err)
	}
	if err := d1.Shutdown(); err != nil {
		t.Fatalf("first broker shutdown: %v", err)
	}
	d2, err := New(cfg)
	if err != nil {
		t.Fatalf("second broker: %v", err)
	}
	defer d2.Shutdown()
}

// SP-20: two simultaneous brokers on the same DB are refused — the first
// broker's lease prevents a successor from reconciling live work.
func TestDaemonSimultaneousStartupRefused(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Skipf("sandbox does not support trusted socket dir: %v", err)
	}
	cfg := Config{
		DBPath:      filepath.Join(dir, "simultaneous.db"),
		SocketPath:  filepath.Join(dir, "a.sock"),
		AdminSocket: filepath.Join(dir, "a.sock.admin"),
		VaultType:   "memory-test",
	}
	d1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d1.Shutdown()
	if _, err := New(cfg); err == nil {
		t.Fatal("second broker started while the first was live")
	}
}
