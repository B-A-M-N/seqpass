package secretbridge_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	secretbridge "github.com/secretbridge/secretbridge"
	"github.com/secretbridge/secretbridge/internal/daemon"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

// Fail-closed over real Unix sockets: with no policy, the harness client is
// denied and no secret material appears in any agent-visible output.
func TestE2EBlindTransfer(t *testing.T) {
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	if fi, err := os.Lstat("/home"); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 && fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "broker.sock")
	admin := filepath.Join(dir, "admin.sock")
	db := filepath.Join(dir, "meta.db")

	d, err := daemon.New(daemon.Config{
		DBPath: db, VaultType: "memory-test",
		SocketPath: sock, AdminSocket: admin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()

	acli, err := ipc.Dial(admin)
	if err != nil {
		t.Fatal(err)
	}
	defer acli.Close()

	refData, err := acli.Call(ipc.MethodSecretAdd, map[string]interface{}{"name": "e2e-cert"})
	if err != nil {
		t.Fatal(err)
	}
	refID := refData.(map[string]interface{})["id"].(string)

	recipient := filepath.Join(dir, "recipient.sock")
	destData, err := acli.Call(ipc.MethodDestAdd, map[string]interface{}{
		"name": "e2e-recipient", "type": "recipient-socket", "endpoint": recipient,
		"expected_uid": os.Geteuid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	destID := destData.(map[string]interface{})["id"].(string)

	harness, err := secretbridge.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer harness.Close()

	_, err = harness.Transfer(refID, destID)
	if err == nil {
		t.Fatal("expected default-deny without policy")
	}

	entries, _ := harness.Catalog()
	for _, e := range entries {
		blob := e.Ref.ID + e.Ref.Name + e.Ref.Description + e.Ref.Binding
		if strings.Contains(blob, "SECRET") {
			t.Fatal("secret material in catalog")
		}
	}
	if len(entries) != 0 {
		t.Fatal("unpermitted principal sees references")
	}
}
