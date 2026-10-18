// Package security is the adversarial regression suite. Each test simulates
// a hostile agent action and asserts denial or safe handling. Tests use fake
// secrets with distinctive markers and verify markers never leak.
package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/daemon"
	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

const marker = "SECRET-MARKER-adv-9f8e7d6c5b4a"

type env struct {
	dir   string
	sock  string
	admin string
	db    string
	d     *daemon.Daemon
}

// secureDir enforces the production runtime-dir contract (0700, broker-owned)
// on a temp dir. Go temp dirs inherit the process umask (often 775), which a
// fail-closed broker must refuse; tests establish the secured dir explicitly.
func secureDir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func startBroker(t *testing.T, cfgMut func(*daemon.Config)) *env {
	t.Helper()
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return nil
	}
	dir = secureDir(t, dir)
	e := &env{
		dir:   dir,
		sock:  filepath.Join(dir, "broker.sock"),
		admin: filepath.Join(dir, "admin.sock"),
		db:    filepath.Join(dir, "meta.db"),
	}
	cfg := daemon.Config{
		DBPath: e.db, VaultType: "memory-test",
		SocketPath: e.sock, AdminSocket: e.admin,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	d, err := daemon.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.d = d
	t.Cleanup(func() { _ = d.Shutdown() })
	return e
}

func (e *env) agent(t *testing.T) *ipc.Client {
	t.Helper()
	c, err := ipc.Dial(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (e *env) operator(t *testing.T) *ipc.Client {
	t.Helper()
	c, err := ipc.Dial(e.admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func opID(t *testing.T, data interface{}) string {
	t.Helper()
	m, ok := data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected response shape %T", data)
	}
	id, _ := m["op_id"].(string)
	if id == "" {
		t.Fatal("no op_id in response")
	}
	return id
}

func refID(t *testing.T, data interface{}) string {
	t.Helper()
	m, ok := data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected response shape %T", data)
	}
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatal("no id in response")
	}
	return id
}
