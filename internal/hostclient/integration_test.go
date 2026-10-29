package hostclient_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/hostclient"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/types"
)

// Live end-to-end test over real Unix sockets: agent requests, trusted
// intake fulfills, host client reads sanitized status.
func TestTrustedClientFullCycle(t *testing.T) {
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(dir, "full-cycle.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	uid := uint32(0)
	if err := svc.AddDestination(&types.Destination{
		ID: "registered-service", Name: "Test Recipient", Type: "recipient-socket",
		Endpoint: filepath.Join(dir, "recipient.sock"), ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}

	agentSock := filepath.Join(dir, "agent.sock")
	adminSock := filepath.Join(dir, "admin.sock")
	intakeSock := filepath.Join(dir, "intake.sock")
	hostSock := filepath.Join(dir, "host.sock")
	euid := uint32(os.Geteuid())
	auth := &ipc.UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{euid: true},
		AgentUIDs:  map[uint32]bool{euid: true},
		IntakeUIDs: map[uint32]bool{euid: true},
	}
	srv := ipc.NewServer(svc, agentSock, adminSock, nil, auth)
	srv.IntakeSocket = intakeSock
	srv.HostSocket = hostSock
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ag, err := ipc.Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	in, err := ipc.Dial(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	host, err := ipc.Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	reqData, err := ag.Call(ipc.MethodRelayRequest, map[string]interface{}{
		"destination_id": "registered-service", "data_kind": "api_key",
	})
	if err != nil {
		t.Fatalf("relay.request: %v", err)
	}
	reqID, _ := reqData.(map[string]interface{})["request_id"].(string)

	// SP-16: use distinct human and agent principals for valid isolated sessions.
	// After registration, bind the relay to the host session using the
	// binding's agent principal so requireRelayHostSession passes.
	if err := svc.DB().CreateHostPrincipalBinding(&types.HostPrincipalBinding{
		HumanPrincipal: "uid:" + fmt.Sprint(os.Geteuid()),
		AgentPrincipal: "uid:99999",
		HostKind:       "opencode",
		ExpiresAt:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	regData, err := in.Call(ipc.MethodHostRegister, map[string]interface{}{
		"host_kind": "opencode", "host_version": "2.0", "adapter_version": "0.1",
		"presentation": "native", "input_transport": "protected_intake",
	})
	if err != nil {
		t.Fatalf("host.register: %v", err)
	}
	rm := regData.(map[string]interface{})
	sessionID, _ := rm["session"].(map[string]interface{})["id"].(string)
	token, _ := rm["token"].(map[string]interface{})["token"].(string)

	client, err := hostclient.New(in, host, harness.HostSessionToken{
		SessionID: sessionID, Token: token,
	})
	if err != nil {
		t.Fatalf("new trusted client: %v", err)
	}

	// SP-16: bind the relay to the host session. The relay was created by
	// the agent socket as euid; the session's agent is the binding agent.
	// Create the relay via the service as the binding agent instead.
	binding, _ := svc.DB().ResolveHostPrincipalBinding("uid:"+fmt.Sprint(os.Geteuid()), "opencode", time.Now())
	if binding != nil {
		reqID2, err := svc.RelayRequest(binding.AgentPrincipal, "registered-service", "api_key", "", time.Minute, "single_dispatch", 1)
		if err != nil {
			t.Fatal(err)
		}
		reqID = reqID2
		if err := svc.BindRelayHost(binding.AgentPrincipal, reqID, &types.HostSession{ID: sessionID}); err != nil {
			t.Fatalf("bind relay to host session: %v", err)
		}
	}

	notice, err := client.GetRequest(reqID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if notice.RequestID != reqID || notice.Version != harness.ProtectedInputNoticeSchemaVersion {
		t.Fatalf("invalid notice: %+v", notice)
	}

	if err := client.Fulfill(reqID, notice.RequestRev, []byte("test-secret")); err != nil {
		t.Fatalf("Fulfill: %v", err)
	}

	status, err := client.GetStatus(reqID)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.RequestID != reqID {
		t.Fatalf("status request mismatch: %+v", status)
	}
	if status.State != types.RelayAuthorized {
		t.Fatalf("unexpected state: %q", status.State)
	}
	if status.OperationID == "" {
		t.Fatal("operation ID missing")
	}
}
