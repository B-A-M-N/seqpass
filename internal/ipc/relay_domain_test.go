package ipc

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// threeSocketServer starts a broker with agent + admin + intake sockets,
// all gated to the test UID. Callers address each domain separately.
func threeSocketServer(t *testing.T, svc *service.Service) (agent, admin, intake string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	agent = filepath.Join(dir, "agent.sock")
	admin = filepath.Join(dir, "admin.sock")
	intake = filepath.Join(dir, "intake.sock")
	euid := uint32(os.Geteuid())
	auth := &UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{euid: true},
		AgentUIDs:  map[uint32]bool{euid: true},
		IntakeUIDs: map[uint32]bool{euid: true},
	}
	srv := NewServer(svc, agent, admin, nil, auth)
	srv.IntakeSocket = intake
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return agent, admin, intake
}

func relayTestService(t *testing.T) *service.Service {
	t.Helper()
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(t.TempDir(), "relay-ipc.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	uid := uint32(os.Geteuid())
	if err := svc.AddDestination(&types.Destination{
		ID: "rd1", Name: "r", Type: "recipient-socket",
		Endpoint: "/tmp/seqpass-relay-ipc-test.sock", ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	return svc
}

// SP-TUI-04: each socket admits exactly its domain. Plaintext intake is
// unreachable from the agent socket, and agent methods are unreachable
// from the intake socket — in both directions.
func TestIntakeDomainIsolation(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock := threeSocketServer(t, svc)

	ag, err := Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	in, err := Dial(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	// Agent -> intake methods: denied at the allowlist, before dispatch.
	for _, m := range []string{MethodIntakeInspect, MethodIntakeFulfill, MethodIntakeReject, MethodIntakeCancel} {
		if _, err := ag.Call(m, map[string]interface{}{"request_id": "req-x"}); err == nil {
			t.Fatalf("agent reached %s", m)
		}
	}
	// Intake -> agent methods: denied symmetrically.
	for _, m := range []string{MethodRelayRequest, MethodRelayStatus, MethodCatalog, MethodUseSubmit} {
		if _, err := in.Call(m, map[string]interface{}{"request_id": "req-x"}); err == nil {
			t.Fatalf("intake reached %s", m)
		}
	}
	// Intake -> admin methods: denied (separate operator surface).
	if _, err := in.Call(MethodOpsPending, nil); err == nil {
		t.Fatal("intake reached admin method")
	}
}

// The three domains compose into one working handoff: agent requests,
// intake fulfills, agent polls — all over their own sockets.
func TestRelayAcrossDomains(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock := threeSocketServer(t, svc)
	ag, _ := Dial(agentSock)
	defer ag.Close()
	in, _ := Dial(intakeSock)
	defer in.Close()

	data, err := ag.Call(MethodRelayRequest, map[string]interface{}{
		"destination_id": "rd1", "data_kind": "password", "purpose": "test",
	})
	if err != nil {
		t.Fatalf("relay.request: %v", err)
	}
	m, _ := data.(map[string]interface{})
	reqID, _ := m["request_id"].(string)
	if reqID == "" || m["status"] != "awaiting_user" {
		t.Fatalf("unexpected request: %+v", data)
	}
	if _, err := in.Call(MethodIntakeFulfill, map[string]interface{}{
		"request_id": reqID,
		"payload":    base64.StdEncoding.EncodeToString([]byte("hunter2-handoff")),
	}); err != nil {
		t.Fatalf("intake.fulfill: %v", err)
	}
	st, err := ag.Call(MethodRelayStatus, map[string]interface{}{"request_id": reqID})
	if err != nil {
		t.Fatalf("relay.status: %v", err)
	}
	sm, _ := st.(map[string]interface{})
	if sm["status"] != "authorized" || sm["plaintext_in_public_receipt"] != false {
		t.Fatalf("status = %+v", st)
	}
	if _, ok := sm["secret_exposed"]; ok {
		t.Fatalf("status claims properties outside the broker boundary: %+v", st)
	}
}

// The intake socket is owner-only: it carries plaintext inbound and
// must be unreachable to agent identities at the filesystem layer too.
func TestIntakeSocketOwnerOnly(t *testing.T) {
	svc := relayTestService(t)
	_, _, intakeSock := threeSocketServer(t, svc)
	st, err := os.Stat(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("intake socket mode = %o, want 0600", perm)
	}
}

// A UID outside every allowlist reaches nothing, on any socket.
func TestStrangerDeniedEverywhere(t *testing.T) {
	svc := relayTestService(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(dir, "a.sock")
	srv := NewServer(svc, agent, "", nil, &UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{1: true},
		AgentUIDs:  map[uint32]bool{1: true},
		IntakeUIDs: map[uint32]bool{1: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := Dial(agent)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Call(MethodHealth, nil); err == nil {
		t.Fatal("stranger reached the broker")
	}
}

func TestIntakeAllowlistShape(t *testing.T) {
	// No plaintext-output method exists anywhere near the agent.
	for m := range AgentAllowlist {
		if strings.HasPrefix(m, "intake.") {
			t.Fatalf("agent allowlist contains %s", m)
		}
	}
	for _, m := range []string{MethodIntakeInspect, MethodIntakeFulfill, MethodIntakeReject, MethodIntakeCancel} {
		if !IntakeAllowlist[m] {
			t.Fatalf("intake missing %s", m)
		}
		if !AdminAllowlist[m] {
			t.Fatalf("admin missing %s", m)
		}
	}
	for _, m := range []string{MethodRelayRequest, MethodRelayStatus, MethodRelayCancel} {
		if !AgentAllowlist[m] {
			t.Fatalf("agent missing %s", m)
		}
	}
}
