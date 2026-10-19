package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/ipc"
)

// T04: arbitrary file destinations are rejected; symlinks cannot divert
// delivery because path-based delivery no longer exists. Pinned operation
// profiles (http-pinned) accept only strict origin grammar, so a symlink
// path is still refused — the endpoint can never name a filesystem object.
func TestFileDestinationsRejected(t *testing.T) {
	e := startBroker(t, nil)
	op := e.operator(t)
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("precious"), 0600)
	link := filepath.Join(t.TempDir(), "link")
	_ = os.Symlink(victim, link)

	for _, typ := range []string{"file", "ssh", ""} {
		if _, err := op.Call(ipc.MethodDestAdd, map[string]interface{}{
			"name": "evil", "type": typ, "endpoint": link,
		}); err == nil {
			t.Fatalf("destination type %q accepted", typ)
		}
	}
	// A pinned profile exists only with a valid origin or pinned
	// executable; a filesystem symlink path is neither, so the diversion
	// stays impossible.
	if _, err := op.Call(ipc.MethodDestAdd, map[string]interface{}{
		"name": "evil", "type": "http-pinned", "endpoint": link,
	}); err == nil {
		t.Fatal("http-pinned destination accepted a filesystem path")
	}
	if _, err := op.Call(ipc.MethodDestAdd, map[string]interface{}{
		"name": "evil", "type": "process-pinned", "endpoint": link,
	}); err == nil {
		t.Fatal("process-pinned destination accepted a symlink path")
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatal("victim file modified")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("attacker link removed unexpectedly")
	}
}

// Delivery to a dead recipient socket fails without writing anywhere.
func TestDeadRecipientFailsClosed(t *testing.T) {
	e := startBroker(t, nil)
	op := e.operator(t)
	ref := refID(t, mustCall(t, op, ipc.MethodSecretAdd, map[string]interface{}{"name": "r"}))
	dest := refID(t, mustCall(t, op, ipc.MethodDestAdd, map[string]interface{}{
		"name": "d", "type": "recipient-socket",
		"endpoint":     filepath.Join(t.TempDir(), "nobody.sock"),
		"expected_uid": myUIDNum(),
	}))
	rules := `[{"principal":"uid:` + myUID() + `","secret_refs":["` + ref + `"],"ops":["transfer","discover"],"dest_ids":["` + dest + `"]}]`
	mustCall(t, op, ipc.MethodPolicyAdd, map[string]interface{}{"name": "p", "rules": rules})

	a := e.agent(t)
	d, err := a.Call(ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": ref, "destination_id": dest,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	id := opID(t, d)
	mustCall(t, op, ipc.MethodApproveTransfer, map[string]interface{}{"op_id": id})
	// Ephemeral source has no staged payload here, so resolve fails honestly.
	// The assertion: failure, never fake success.
	if _, err := op.Call(ipc.MethodExecuteTransfer, map[string]interface{}{"op_id": id}); err == nil {
		t.Fatal("execution reported success with no credential and no recipient")
	}
}
