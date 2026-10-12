package security

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

func submitTransfer(t *testing.T, e *env, ref, dest string) string {
	t.Helper()
	a := e.agent(t)
	d, err := a.Call(ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": ref, "destination_id": dest,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return opID(t, d)
}

func approveTransfer(t *testing.T, e *env, id string) {
	t.Helper()
	op := e.operator(t)
	if _, err := op.Call(ipc.MethodApproveTransfer, map[string]interface{}{"op_id": id}); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func executeTransferErr(t *testing.T, e *env, id string) error {
	t.Helper()
	op := e.operator(t)
	_, err := op.Call(ipc.MethodExecuteTransfer, map[string]interface{}{"op_id": id})
	return err
}

// T06: disabling the policy after approval revokes execution.
func TestPolicyRevocationAfterApproval(t *testing.T) {
	e := startBroker(t, nil)
	ref, dest := setupTransferEnv(t, e, `["*"]`)
	id := submitTransfer(t, e, ref, dest)
	approveTransfer(t, e, id)

	op := e.operator(t)
	// Find policy ID via pending? Policies aren't listed over IPC; disable
	// via direct epoch-relevant path: set-policy needs the ID. Fetch from DB.
	db, err := sql.Open("sqlite3", e.db+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var polID string
	if err := db.QueryRow(`SELECT id FROM policies LIMIT 1`).Scan(&polID); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Call(ipc.MethodPolicySet, map[string]interface{}{"id": polID, "enabled": false}); err != nil {
		t.Fatalf("set-policy: %v", err)
	}
	if err := executeTransferErr(t, e, id); err == nil {
		t.Fatal("revoked operation executed (T06)")
	}
}

// T07: changing the destination endpoint after approval invalidates it.
func TestDestinationChangeInvalidatesApproval(t *testing.T) {
	e := startBroker(t, nil)
	ref, dest := setupTransferEnv(t, e, `["*"]`)
	id := submitTransfer(t, e, ref, dest)
	approveTransfer(t, e, id)

	op := e.operator(t)
	if _, err := op.Call(ipc.MethodDestUpdate, map[string]interface{}{
		"id": dest, "endpoint": "/tmp/attacker-recipient.sock",
	}); err != nil {
		t.Fatalf("update-dest: %v", err)
	}
	if err := executeTransferErr(t, e, id); err == nil {
		t.Fatal("operation executed after destination change (T07)")
	}
}

// T08: tampering with persisted params invalidates the approval hash.
func TestParamTamperDenied(t *testing.T) {
	e := startBroker(t, nil)
	op := e.operator(t)
	ref := refID(t, mustCall(t, op, ipc.MethodSecretAdd, map[string]interface{}{"name": "r"}))
	rules := `[{"principal":"uid:` + myUID() + `","secret_refs":["` + ref + `"],"ops":["github.get_repo","discover"],"dest_ids":[],"resources":["*"]}]`
	mustCall(t, op, ipc.MethodPolicyAdd, map[string]interface{}{"name": "p", "rules": rules})

	a := e.agent(t)
	d, err := a.Call(ipc.MethodUseSubmit, map[string]interface{}{
		"secret_ref": ref, "operation": "github.get_repo",
		"params": map[string]interface{}{"repo": "o/r"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	id := opID(t, d)
	if _, err := op.Call(ipc.MethodApproveUse, map[string]interface{}{"op_id": id}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Attacker with DB write tampers the envelope post-approval.
	db, err := sql.Open("sqlite3", e.db+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE uses SET params = '{"repo":"victim/admin"}' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Call(ipc.MethodExecuteUse, map[string]interface{}{"op_id": id}); err == nil {
		t.Fatal("tampered operation executed (T08)")
	}
}

// T09 is covered in secureops unit tests; T17 double-claim in service tests.
