package security

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/daemon"
)

// T03: preplaced filesystem objects must not be deleted or taken over.
func TestSocketPathAttacks(t *testing.T) {
	newCfg := func(dir string) daemon.Config {
		return daemon.Config{
			DBPath: filepath.Join(dir, "m.db"), VaultType: "memory-test",
			SocketPath: filepath.Join(dir, "b.sock"),
			AdminSocket: filepath.Join(dir, "b.admin"),
		}
	}

	t.Run("regular file", func(t *testing.T) {
		dir := secureDir(t, t.TempDir())
		cfg := newCfg(dir)
		if err := os.WriteFile(cfg.SocketPath, []byte("victim"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := daemon.New(cfg); err == nil {
			t.Fatal("broker replaced a regular file")
		}
		if b, _ := os.ReadFile(cfg.SocketPath); string(b) != "victim" {
			t.Fatal("regular file was modified")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := secureDir(t, t.TempDir())
		cfg := newCfg(dir)
		target := filepath.Join(dir, "target")
		_ = os.WriteFile(target, []byte("x"), 0600)
		if err := os.Symlink(target, cfg.SocketPath); err != nil {
			t.Fatal(err)
		}
		if _, err := daemon.New(cfg); err == nil {
			t.Fatal("broker followed a symlink socket path")
		}
	})

	t.Run("live socket", func(t *testing.T) {
		dir := secureDir(t, t.TempDir())
		cfg := newCfg(dir)
		l, err := net.Listen("unix", cfg.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if _, err := daemon.New(cfg); err == nil {
			t.Fatal("broker replaced a live socket")
		}
	})
}
