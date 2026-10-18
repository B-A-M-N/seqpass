package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// SP-01: daemon startup must succeed with no HostSocket configured.
func TestDaemonStartupWithoutHostSocket(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Skipf("sandbox does not support trusted socket dir: %v", err)
	}
	d, err := New(Config{
		DBPath:       filepath.Join(dir, "m.db"),
		SocketPath:   filepath.Join(dir, "a.sock"),
		AdminSocket:  filepath.Join(dir, "a.sock.admin"),
		IntakeSocket: filepath.Join(dir, "a.sock.intake"),
		VaultType:    "memory-test",
	})
	if err != nil {
		t.Fatalf("startup without host socket failed: %v", err)
	}
	defer d.Shutdown()
	if _, err := os.Stat(filepath.Join(dir, "a.sock.intake")); err != nil {
		t.Fatalf("intake socket missing: %v", err)
	}
}

// SP-01: a configured but nonexistent host socket must fail startup.
func TestDaemonStartupWithInvalidHostSocket(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Skipf("sandbox does not support trusted socket dir: %v", err)
	}
	_, err := New(Config{
		DBPath:       filepath.Join(dir, "m.db"),
		SocketPath:   filepath.Join(dir, "a.sock"),
		AdminSocket:  filepath.Join(dir, "a.sock.admin"),
		IntakeSocket: filepath.Join(dir, "a.sock.intake"),
		HostSocket:   filepath.Join(dir, "nonexistent", "host.sock"),
		VaultType:    "memory-test",
	})
	if err == nil {
		t.Fatal("startup accepted a configured but nonexistent host socket")
	}
}
