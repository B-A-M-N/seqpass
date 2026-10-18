package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/testruntime"
)

// SP-02: admin.host_binding_create is reachable through the admin socket
// with an authorized administrative identity. Unauthorized identities
// and agent-domain calls are denied.
func TestAdminHostBindingCreate(t *testing.T) {
	dir, err := testruntime.Dir(t)
	if err != nil {
		t.Skipf("socket fixture unavailable: %v", err)
		return
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Config{
		DBPath:    filepath.Join(dir, "hostbinding-rpc.db"),
		VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	adminSock := filepath.Join(dir, "admin.sock")
	agentSock := filepath.Join(dir, "agent.sock")
	euid := uint32(os.Geteuid())
	auth := &UIDAuthorizer{
		AdminUIDs:      map[uint32]bool{euid: true},
		AgentUIDs:      map[uint32]bool{euid: true},
		IntakeUIDs:     map[uint32]bool{euid: true},
		PrincipalAdmin: map[string]bool{fmt.Sprintf("uid:%d", euid): true},
	}
	srv := NewServer(svc, agentSock, adminSock, nil, auth)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	admin, err := Dial(adminSock)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	data, err := admin.Call(MethodHostBindingCreate, map[string]interface{}{
		"action":          "create",
		"human_principal": "uid:1000",
		"agent_principal": "uid:2001",
		"host_kind":       "codex",
		"ttl_seconds":     uint64(3600),
	})
	if err != nil {
		t.Fatalf("admin host_binding_create: %v", err)
	}
	m := data.(map[string]interface{})
	if m["human_principal"] != "uid:1000" || m["agent_principal"] != "uid:2001" || m["host_kind"] != "codex" {
		t.Fatalf("unexpected binding: %+v", data)
	}

	inspect, err := admin.Call(MethodHostBindingCreate, map[string]interface{}{
		"action":          "inspect",
		"human_principal": "uid:1000",
		"host_kind":       "codex",
	})
	if err != nil {
		t.Fatalf("admin host_binding_inspect: %v", err)
	}
	im := inspect.(map[string]interface{})
	if im["agent_principal"] != "uid:2001" {
		t.Fatalf("unexpected inspect: %+v", inspect)
	}

	if _, err := admin.Call(MethodHostBindingCreate, map[string]interface{}{
		"action":          "revoke",
		"human_principal": "uid:1000",
		"agent_principal": "uid:2001",
		"host_kind":       "codex",
	}); err != nil {
		t.Fatalf("admin host_binding_revoke: %v", err)
	}

	if _, err := admin.Call(MethodHostBindingCreate, map[string]interface{}{
		"action":          "inspect",
		"human_principal": "uid:1000",
		"host_kind":       "codex",
	}); err == nil {
		t.Fatal("revoked binding still active")
	}
}

// SP-02: an agent-domain call to admin.host_binding_create is denied.
func TestHostBindingAgentDomainDenied(t *testing.T) {
	svc, err := service.New(service.Config{
		DBPath:    filepath.Join(t.TempDir(), "agent-denied.db"),
		VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	// The socket fixture needs a trusted, owner-only directory. t.TempDir()
	// creates its parent with mode 0777 & ^umask, so under a permissive
	// umask (e.g. 002) the group-writable ancestor would make the broker
	// refuse to bind and the test would skip for the wrong reason. A
	// uniquely named owner-only directory under /tmp is world-traversable
	// but not group-writable, so the ancestor check passes whatever the
	// umask is.
	sockDir, err := os.MkdirTemp("/tmp", "seqpass-hostbinding-")
	if err != nil {
		t.Skipf("socket fixture unavailable: %v", err)
		return
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	if err := os.Chmod(sockDir, 0700); err != nil {
		t.Fatal(err)
	}
	agentSock := filepath.Join(sockDir, "agent.sock")
	euid := uint32(os.Geteuid())
	auth := &UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{euid: true},
		AgentUIDs:  map[uint32]bool{euid: true},
		IntakeUIDs: map[uint32]bool{euid: true},
		// Deliberately omit PrincipalAdmin so the admin identity is not authorized.
	}
	srv := NewServer(svc, agentSock, "", nil, auth)
	if err := srv.Start(); err != nil {
		t.Skipf("socket fixture unavailable: %v", err)
		return
	}
	defer srv.Close()

	agent, err := Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if _, err := agent.Call(MethodHostBindingCreate, map[string]interface{}{
		"action":          "create",
		"human_principal": "uid:1000",
		"agent_principal": "uid:2001",
		"host_kind":       "codex",
		"ttl_seconds":     uint64(3600),
	}); err == nil {
		t.Fatal("agent domain reached admin.host_binding_create")
	}
}
