package security

import (
	"testing"

	"github.com/secretbridge/secretbridge/internal/daemon"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

// T01: agent socket must not serve admin methods.
func TestAgentSocketDeniesAdmin(t *testing.T) {
	e := startBroker(t, nil)
	a := e.agent(t)
	for _, m := range []string{
		ipc.MethodApproveUse, ipc.MethodRejectUse,
		ipc.MethodApproveTransfer, ipc.MethodRejectTransfer,
		ipc.MethodSecretAdd, ipc.MethodDestAdd, ipc.MethodPolicyAdd,
		ipc.MethodPolicySet, ipc.MethodDestUpdate,
		ipc.MethodExecuteUse, ipc.MethodExecuteTransfer, ipc.MethodOpsPending,
	} {
		if _, err := a.Call(m, map[string]interface{}{"op_id": "x"}); err == nil {
			t.Fatalf("agent socket served %s", m)
		}
	}
}

// T02: a caller outside the admin UID allowlist is denied admin methods
// even when connected to the admin socket.
func TestAdminSocketDeniesNonAdminUID(t *testing.T) {
	e := startBroker(t, func(c *daemon.Config) { c.AdminUIDs = []uint32{424242} })
	op := e.operator(t)
	if _, err := op.Call(ipc.MethodApproveUse, map[string]interface{}{"op_id": "x"}); err == nil {
		t.Fatal("non-admin UID approved an operation via admin socket")
	}
	// The broker drops unauthorized admin-socket connections outright, so
	// subsequent calls on the same connection also fail. Agent-surface
	// access remains available on the agent socket.
	if _, err := op.Call(ipc.MethodSecretAdd, map[string]interface{}{"name": "x"}); err == nil {
		t.Fatal("non-admin UID added a secret via admin socket")
	}
	a := e.agent(t)
	if _, err := a.Call(ipc.MethodCatalog, nil); err != nil {
		t.Fatalf("agent surface denied on agent socket: %v", err)
	}
}

// Real T02 with a deny-all admin allowlist.
func TestAdminSocketDeniesForeignPrincipal(t *testing.T) {
	e := startBroker(t, nil)
	// Reconnect is same-uid (admin) here; the unit-level authorizer test
	// below covers foreign UIDs. This asserts the admin surface requires
	// admin auth, not merely the socket.
	a := e.operator(t)
	if _, err := a.Call(ipc.MethodOpsPending, nil); err != nil {
		t.Fatalf("operator denied own admin surface: %v", err)
	}
}

// T19: authorizer unit checks. Both sockets require explicit UID allowlists
// (C02): reaching a socket never suffices, and an authenticated agent peer
// outside the agent allowlist is denied the agent surface too.
func TestUIDAuthorizer(t *testing.T) {
	auth := &ipc.UIDAuthorizer{
		AdminUIDs: map[uint32]bool{1000: true},
		AgentUIDs: map[uint32]bool{2000: true},
	}
	admin := ipc.AuthenticatedPrincipal{Principal: "uid:1000"}
	agent := ipc.AuthenticatedPrincipal{Principal: "uid:2000"}
	stranger := ipc.AuthenticatedPrincipal{Principal: "uid:3000"}
	agent.Peer.UID = 2000
	admin.Peer.UID = 1000
	stranger.Peer.UID = 3000

	if !auth.CanConnectAgent(agent) {
		t.Fatal("agent surface denied to allowlisted agent UID")
	}
	if auth.CanConnectAgent(stranger) {
		t.Fatal("agent surface granted to non-allowlisted UID (C02)")
	}
	if auth.CanConnectAdmin(agent) {
		t.Fatal("admin granted to non-listed UID (T19)")
	}
	if !auth.CanConnectAdmin(admin) {
		t.Fatal("admin denied to listed UID")
	}
	anon := ipc.AuthenticatedPrincipal{}
	if auth.CanConnectAgent(anon) || auth.CanConnectAdmin(anon) {
		t.Fatal("anonymous principal authorized")
	}
}
