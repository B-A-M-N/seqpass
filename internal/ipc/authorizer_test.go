package ipc

import (
	"os"
	"testing"
)

// C02: the agent socket requires an explicit UID allowlist. A valid,
// peer-credentialed principal from a non-allowlisted UID is denied.
func TestAgentAuthorizerExplicitAllowlist(t *testing.T) {
	euid := uint32(os.Geteuid())
	auth := &UIDAuthorizer{
		AdminUIDs: map[uint32]bool{euid: true},
		AgentUIDs: map[uint32]bool{euid: true},
	}
	ok := AuthenticatedPrincipal{Peer: Peer{UID: euid}, Principal: "uid:1"}
	if !auth.CanConnectAgent(ok) {
		t.Fatal("allowlisted agent UID denied")
	}
	foreign := AuthenticatedPrincipal{Peer: Peer{UID: euid + 100000}, Principal: "uid:2"}
	if auth.CanConnectAgent(foreign) {
		t.Fatal("non-allowlisted UID reached the agent surface (C02)")
	}
	if auth.CanConnectAdmin(foreign) {
		t.Fatal("non-admin UID reached the admin surface")
	}
	// Nil agent map is the fail-closed default: broker euid only.
	def := &UIDAuthorizer{AdminUIDs: map[uint32]bool{euid: true}}
	if !def.CanConnectAgent(ok) {
		t.Fatal("default authorizer denied broker euid")
	}
	if def.CanConnectAgent(foreign) {
		t.Fatal("default authorizer allowed a foreign UID (C02)")
	}
	if def.CanConnectAgent(AuthenticatedPrincipal{}) {
		t.Fatal("empty principal allowed")
	}
}
