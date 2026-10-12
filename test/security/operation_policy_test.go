package security

import (
	"testing"

	"github.com/secretbridge/secretbridge/internal/ipc"
)

// setupTransferEnv registers a ref + recipient-socket dest + allow policy.
func setupTransferEnv(t *testing.T, e *env, destIDs string) (ref, dest string) {
	t.Helper()
	op := e.operator(t)
	ref = refID(t, mustCall(t, op, ipc.MethodSecretAdd, map[string]interface{}{"name": "r"}))
	dest = refID(t, mustCall(t, op, ipc.MethodDestAdd, map[string]interface{}{
		"name": "d", "type": "recipient-socket", "endpoint": "/tmp/nonexistent-recipient.sock",
		"expected_uid": myUIDNum(),
	}))
	uid := myUID()
	rules := `[{"principal":"uid:` + uid + `","secret_refs":["` + ref + `"],"ops":["transfer","discover"],"dest_ids":` + destIDs + `}]`
	mustCall(t, op, ipc.MethodPolicyAdd, map[string]interface{}{"name": "p", "rules": rules})
	return ref, dest
}

func mustCall(t *testing.T, c *ipc.Client, m string, p map[string]interface{}) interface{} {
	t.Helper()
	d, err := c.Call(m, p)
	if err != nil {
		t.Fatalf("%s: %v", m, err)
	}
	return d
}

// T05: destination-scoped rule must not match an operation that resolves a
// different (or no) destination; unknown destinations denied.
func TestDestinationScoping(t *testing.T) {
	e := startBroker(t, nil)
	ref, dest := setupTransferEnv(t, e, `["`+`PLACEHOLDER`+`"]`)
	_ = dest
	_ = ref
	a := e.agent(t)
	// The policy scopes dest_ids to a non-existent ID: transfer to the real
	// dest must be denied.
	if _, err := a.Call(ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": ref, "destination_id": dest,
	}); err == nil {
		t.Fatal("scoped policy allowed out-of-scope destination")
	}
	// Unknown destination denied even before policy.
	if _, err := a.Call(ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": ref, "destination_id": "nope",
	}); err == nil {
		t.Fatal("unknown destination allowed")
	}
}

// T05b: empty destination against destination-scoped use rule denied.
func TestEmptyDestinationDenied(t *testing.T) {
	e := startBroker(t, nil)
	op := e.operator(t)
	ref := refID(t, mustCall(t, op, ipc.MethodSecretAdd, map[string]interface{}{"name": "r"}))
	rules := `[{"principal":"uid:` + myUID() + `","secret_refs":["` + ref + `"],"ops":["github.get_repo"],"dest_ids":["some-dest"],"resources":["*"]}]`
	mustCall(t, op, ipc.MethodPolicyAdd, map[string]interface{}{"name": "p", "rules": rules})
	a := e.agent(t)
	// github.get_repo is destinationless, but the rule scopes a concrete
	// destination: must deny rather than ignore the constraint.
	if _, err := a.Call(ipc.MethodUseSubmit, map[string]interface{}{
		"secret_ref": ref, "operation": "github.get_repo",
		"params": map[string]interface{}{"repo": "o/r"},
	}); err == nil {
		t.Fatal("destination-scoped rule matched destinationless request")
	}
}
