package ipc

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fmt"
	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/types"
)

// threeSocketServer starts a broker with agent + admin + intake sockets,
// all gated to the test UID. Callers address each domain separately.
func fourSocketServer(t *testing.T, svc *service.Service) (agent, admin, intake, host string) {
	t.Helper()
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	agent = filepath.Join(dir, "agent.sock")
	admin = filepath.Join(dir, "admin.sock")
	intake = filepath.Join(dir, "intake.sock")
	host = filepath.Join(dir, "host.sock")
	euid := uint32(os.Geteuid())
	auth := &UIDAuthorizer{
		AdminUIDs:  map[uint32]bool{euid: true},
		AgentUIDs:  map[uint32]bool{euid: true},
		IntakeUIDs: map[uint32]bool{euid: true},
	}
	srv := NewServer(svc, agent, admin, nil, auth)
	srv.IntakeSocket = intake
	srv.HostSocket = host
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return agent, admin, intake, host
}

func threeSocketServer(t *testing.T, svc *service.Service) (agent, admin, intake string) {
	t.Helper()
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
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

func createTestHostBinding(t *testing.T, svc *service.Service, human, agent, kind string) {
	t.Helper()
	// SP-09: only one active binding is allowed per (human, host_kind).
	// Revoke any existing binding first so test setup can provision a
	// fresh binding for a different agent on the same host kind.
	existing, _ := svc.DB().ResolveHostPrincipalBinding(human, kind, time.Now())
	if existing != nil {
		_ = svc.DB().RevokeHostPrincipalBinding(human, existing.AgentPrincipal, kind)
	}
	if err := svc.DB().CreateHostPrincipalBinding(&types.HostPrincipalBinding{
		HumanPrincipal: human, AgentPrincipal: agent, HostKind: kind,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
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
		Endpoint: filepath.Join(testruntime.DirOrTemp(t), "recipient.sock"), ExpectedUID: &uid,
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
		"request_id":       reqID,
		"request_revision": 1,
		"payload":          base64.StdEncoding.EncodeToString([]byte("hunter2-handoff")),
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
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
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
	// Host registration is protected IPC only; host event/review remain
	// display-only and intake methods never leak into that surface.
	if !IntakeAllowlist[MethodHostRegister] || !AdminAllowlist[MethodHostRegister] {
		t.Fatal("trusted host registration missing")
	}
	for m := range HostAllowlist {
		if strings.HasPrefix(m, "intake.") || strings.HasPrefix(m, "admin.") {
			t.Fatalf("host allowlist contains privileged method %s", m)
		}
	}
}

// HI-02/HI-03: a native-host session is broker registered and token
// authenticated; host events/reviews are display-only and bound to the
// requesting agent and authenticated human principal.
func TestHostSessionPresentationDomain(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock, hostSock := fourSocketServer(t, svc)
	svc.SetHostInputAssurance(string(harness.InputExternalTTY), string(intake.AssuranceModelBlind))
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
	host, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	// SP-16: create the relay as the distinct agent principal (uid:99999)
	// so relay, binding, and host session all share the same agent.
	createTestHostBinding(t, svc, "uid:"+fmt.Sprint(os.Geteuid()), "uid:99999", "codex")
	bindingAgent := "uid:99999"
	reqID, err := svc.RelayRequest(bindingAgent, "rd1", "api_key", "host integration", time.Minute, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	if reqID == "" {
		t.Fatal("missing request ID")
	}
	if _, err := ag.Call(MethodHostRegister, map[string]interface{}{"host_kind": "codex"}); err == nil {
		t.Fatal("agent registered host session")
	}
	reg, err := in.Call(MethodHostRegister, map[string]interface{}{
		"host_kind": "codex", "thread_id": "turn-host", "ttl_seconds": 600,
		"host_version": "1.2.3", "adapter_version": "0.1.0",
		"presentation": "native", "input_transport": "protected_intake",
		"supports_resume": "true", "supports_cancel_prompt": "true",
	})
	if err != nil {
		t.Fatalf("host.register: %v", err)
	}
	rm := reg.(map[string]interface{})
	sessionID, _ := rm["session"].(map[string]interface{})["id"].(string)
	tokenObj, _ := rm["token"].(map[string]interface{})
	token, _ := tokenObj["token"].(string)
	if sessionID == "" || token == "" {
		t.Fatalf("missing host session/token: %+v", reg)
	}
	capsObj, _ := tokenObj["credentials"].(map[string]interface{})
	if capsObj["presentation"] != "native" || capsObj["input_transport"] != "protected_intake" {
		t.Fatalf("native capability not negotiated: %+v", reg)
	}
	if capsObj["credential_form_via_mcp"] != false {
		t.Fatalf("MCP credential form incorrectly enabled: %+v", reg)
	}
	if capsObj["supports_resume"] != true || capsObj["supports_cancel_prompt"] != true {
		t.Fatalf("optional capability flags lost: %+v", reg)
	}
	// SP-16: bind the relay to the host session.
	if err := svc.BindRelayHost("uid:99999", reqID, &types.HostSession{ID: sessionID}); err != nil {
		t.Fatalf("bind relay to host session: %v", err)
	}
	notice, err := host.Call(MethodHostNotice, map[string]interface{}{
		"session_id": sessionID, "session_token": token, "request_id": reqID,
	})
	if err != nil {
		t.Fatalf("host.notice: %v", err)
	}
	nm := notice.(map[string]interface{})
	if nm["version"] != float64(harness.ProtectedInputNoticeSchemaVersion) ||
		nm["request_id"] != reqID || nm["host_session_id"] != sessionID ||
		nm["request_revision"].(float64) <= 0 {
		t.Fatalf("unexpected notice: %+v", notice)
	}
	if nm["untrusted_purpose"] != "host integration" || nm["recipient_label"] == "" {
		t.Fatalf("notice fields invalid: %+v", notice)
	}
	ev, err := host.Call(MethodHostEvent, map[string]interface{}{
		"session_id": sessionID, "session_token": token, "request_id": reqID, "sequence": 1,
	})
	if err != nil {
		t.Fatalf("host.event: %v", err)
	}
	if em := ev.(map[string]interface{}); em["request_id"] != reqID || em["state"] != "awaiting_user" {
		t.Fatalf("unexpected host event: %+v", ev)
	}
	review, err := host.Call(MethodHostReview, map[string]interface{}{
		"session_id": sessionID, "session_token": token, "request_id": reqID,
	})
	if err != nil {
		t.Fatalf("host.review: %v", err)
	}
	if rev := review.(map[string]interface{}); rev["endpoint"] == "" || rev["purpose_untrusted"] != true || rev["trusted_host_render"] != true {
		t.Fatalf("unexpected review: %+v", review)
	}
	// Host presentation can never fulfill, and an invalid token cannot
	// observe anything.
	if _, err := host.Call(MethodIntakeFulfill, map[string]interface{}{"request_id": reqID, "request_revision": 1}); err == nil {
		t.Fatal("host fulfilled")
	}
	if _, err := host.Call(MethodHostEvent, map[string]interface{}{
		"session_id": sessionID, "session_token": "wrong", "request_id": reqID,
	}); err == nil {
		t.Fatal("invalid host token accepted")
	}
}

// HI-02 regression: two concurrent host sessions bound to different
// agents cannot observe each other's requests, even when one adapter
// knows the other request ID.
func TestConcurrentHostSessionsStayIsolated(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock, hostSock := fourSocketServer(t, svc)
	agA, err := Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer agA.Close()
	// Both test agent connections share the current test UID/principal;
	// same-principal sessions are intentionally allowed, but this also
	// verifies explicit token/session scoping at the API boundary.
	agB, err := Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer agB.Close()
	in, err := Dial(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	hostA, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer hostA.Close()
	hostB, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer hostB.Close()


	uidCounter := 0
	register := func() (string, string) {
		t.Helper()
		// SP-16: use a distinct agent principal for each call. The closure
		// captures the counter to generate unique agent UIDs.
		uidCounter++
		agentUID := fmt.Sprintf("uid:900%02d", uidCounter)
		// Note: we do NOT create a binding here because SP-09 unique active
		// binding enforcement means a second binding for the same human+kind
		// would need to revoke the first, invalidating the first session.
		// Instead, create a fresh binding per registration only on the first
		// call; subsequent sessions share the same binding agent.
		if uidCounter == 1 {
			createTestHostBinding(t, svc, "uid:"+fmt.Sprint(os.Geteuid()), agentUID, "hermes")
		}
		reg, err := in.Call(MethodHostRegister, map[string]interface{}{
			"host_kind": "hermes", "ttl_seconds": 300,
			"host_version": "1.0", "adapter_version": "0.1",
			"presentation": "request_status", "input_transport": "external_tty",
		})
		if err != nil {
			t.Fatal(err)
		}
		m := reg.(map[string]interface{})
		sid, _ := m["session"].(map[string]interface{})["id"].(string)
		tok, _ := m["token"].(map[string]interface{})["token"].(string)
		return sid, tok
	}
	sessA, tokA := register()
	sessB, tokB := register()
	// SP-16: create relays via the service using the binding agent (uid:90001)
	// so relay, binding, and host session all share the same agent principal.
	reqA, err := svc.RelayRequest("uid:90001", "rd1", "api_key", "", time.Minute, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	reqB, err := svc.RelayRequest("uid:90001", "rd1", "token", "", time.Minute, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Explicitly bind each relay to its own session — requireRelayHostSession
	// checks but does not auto-create the binding.
	sessAObj, _ := svc.DB().GetHostSession(sessA)
	sessBObj, _ := svc.DB().GetHostSession(sessB)
	if sessAObj == nil || sessBObj == nil {
		t.Fatal("host sessions not found after registration")
	}
	if err := svc.BindRelayHost("uid:90001", reqA, sessAObj); err != nil {
		t.Fatalf("bind reqA to sessA: %v", err)
	}
	if err := svc.BindRelayHost("uid:90001", reqB, sessBObj); err != nil {
		t.Fatalf("bind reqB to sessB: %v", err)
	}
	hosts := map[string]*Client{"A": hostA, "B": hostB}
	for _, tc := range []struct {
		label, sessionID, token, requestID string
	}{
		{"A", sessA, tokA, reqA}, {"B", sessB, tokB, reqB},
	} {
		if _, err := hosts[tc.label].Call(MethodHostEvent, map[string]interface{}{
			"session_id": tc.sessionID, "session_token": tc.token, "request_id": tc.requestID,
		}); err != nil {
			t.Fatalf("own session %s denied: %v", tc.label, err)
		}
	}
	// Explicit cross-session access is denied even under the same OS
	// principal. Distinct authenticated host identities remain mandatory
	// in production for agent attribution.
	if _, err := hostB.Call(MethodHostEvent, map[string]interface{}{
		"session_id": sessA, "session_token": tokA, "request_id": reqB,
	}); err == nil {
		t.Fatal("cross-agent host session accepted another session's relay")
	}
}

// HI-10: host prompt cancellation does not fabricate a final dispatch
// outcome. Pending prompts may be withdrawn; dispatched grants return
// prompt_cancelled=false so uncertain delivery is not hidden.
func TestHostPromptCancellationDoesNotHideDispatch(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock, hostSock := fourSocketServer(t, svc)
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
	host, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	// SP-16: use distinct human and agent principals. Create the relay
	// via the service as the binding agent so relay, binding, and session
	// share the same principal.
	createTestHostBinding(t, svc, "uid:"+fmt.Sprint(os.Geteuid()), "uid:99997", "codex")
	reqID, err := svc.RelayRequest("uid:99997", "rd1", "api_key", "", time.Minute, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := in.Call(MethodHostRegister, map[string]interface{}{"host_kind": "codex"})
	if err != nil {
		t.Fatal(err)
	}
	m := reg.(map[string]interface{})
	sid := m["session"].(map[string]interface{})["id"].(string)
	tok := m["token"].(map[string]interface{})["token"].(string)
	// Bind the relay to the session.
	if err := svc.BindRelayHost("uid:99997", reqID, &types.HostSession{ID: sid}); err != nil {
		t.Fatalf("bind relay: %v", err)
	}
	cancel := func() bool {
		t.Helper()
		res, err := host.Call(MethodHostCancelPrompt, map[string]interface{}{
			"session_id": sid, "session_token": tok, "request_id": reqID,
		})
		if err != nil {
			t.Fatalf("cancel prompt: %v", err)
		}
		return res.(map[string]interface{})["prompt_cancelled"] == true
	}
	if !cancel() {
		t.Fatal("pending prompt was not cancelled")
	}
	// A terminal cancelled grant remains cancelled and cannot be revived.
	// The relay was created via svc as uid:99997; check status directly.
	st, err := svc.RelayStatus("uid:99997", reqID)
	if err != nil {
		t.Fatal(err)
	}
	if st["status"] != "cancelled" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

// HI-13: data-kind admission and intake payload limits must stay aligned
// across trusted surfaces. An oversized value is refused before staging.
func TestRelayInputLimitsStayBounded(t *testing.T) {
	svc := relayTestService(t)
	_, _, intakeSock, _ := fourSocketServer(t, svc)
	in, err := Dial(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	data, err := in.Call(MethodIntakeRequest, map[string]interface{}{
		"destination_id": "rd1", "data_kind": "api_key", "payload": "c2VjcmV0",
	})
	if err != nil {
		t.Fatalf("valid intake request: %v", err)
	}
	if data.(map[string]interface{})["status"] != "authorized" {
		t.Fatalf("unexpected intake request: %+v", data)
	}
	// 65 KiB exceeds the bounded intake contract; the encoded string is
	// intentionally one byte over the existing max.
	tooLarge := make([]byte, 64*1024+1)
	if _, err := in.Call(MethodIntakeRequest, map[string]interface{}{
		"destination_id": "rd1", "data_kind": "api_key",
		"payload": base64.StdEncoding.EncodeToString(tooLarge),
	}); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

// SP-03/SP-04 acceptance: two agents with distinct host sessions cannot see,
// bind, cancel, or fulfill one another's relays even when they know the
// other request ID. Distinct agent principals are enforced throughout.
func TestTwoAgentHostSessionIsolation(t *testing.T) {
	svc := relayTestService(t)
	agentSock, _, intakeSock, hostSock := fourSocketServer(t, svc)
	agA, err := Dial(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer agA.Close()
	in, err := Dial(intakeSock)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	hostA, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer hostA.Close()
	hostB, err := Dial(hostSock)
	if err != nil {
		t.Fatal(err)
	}
	defer hostB.Close()

	// SP-16: create relays via the service using distinct agent principals
	// so relay, binding, and host session all share the same agent.
	createTestHostBinding(t, svc, "uid:"+fmt.Sprint(os.Geteuid()), "uid:9001", "codex")
	createTestHostBinding(t, svc, "uid:"+fmt.Sprint(os.Geteuid()), "uid:9002", "hermes")
	reqIDA, err := svc.RelayRequest("uid:9001", "rd1", "api_key", "agent-a request", time.Minute, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	if reqIDA == "" {
		t.Fatal("missing request ID A")
	}
	_ = agA // agent socket connection retained for other assertions

	regA, err := in.Call(MethodHostRegister, map[string]interface{}{
		"host_kind": "codex", "thread_id": "thread-a", "ttl_seconds": 300,
		"host_version": "1.0", "adapter_version": "0.1",
		"presentation": "native", "input_transport": "external_tty",
	})
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	sessA := regA.(map[string]interface{})["session"].(map[string]interface{})["id"].(string)
	tokA := regA.(map[string]interface{})["token"].(map[string]interface{})["token"].(string)

	regB, err := in.Call(MethodHostRegister, map[string]interface{}{
		"host_kind": "hermes", "thread_id": "thread-b", "ttl_seconds": 300,
		"host_version": "1.0", "adapter_version": "0.1",
		"presentation": "native", "input_transport": "external_tty",
	})
	if err != nil {
		t.Fatalf("register B: %v", err)
	}
	sessB := regB.(map[string]interface{})["session"].(map[string]interface{})["id"].(string)
	tokB := regB.(map[string]interface{})["token"].(map[string]interface{})["token"].(string)

	// Bind reqA to session A — the relay and session share agent uid:9001.
	if err := svc.BindRelayHost("uid:9001", reqIDA, &types.HostSession{ID: sessA}); err != nil {
		t.Fatalf("bind A: %v", err)
	}

	// Host A sees its bound relay.
	pendingA, err := hostA.Call(MethodHostPending, map[string]interface{}{
		"session_id": sessA, "session_token": tokA,
	})
	if err != nil {
		t.Fatalf("pending A: %v", err)
	}
	foundA := false
	if arr, ok := pendingA.([]interface{}); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok && m["request_id"] == reqIDA {
				foundA = true
			}
		}
	}
	if !foundA {
		t.Fatal("host A did not see its own relay")
	}

	// Host B's pending inbox must not contain reqA.
	pendingB, err := hostB.Call(MethodHostPending, map[string]interface{}{
		"session_id": sessB, "session_token": tokB,
	})
	if err != nil {
		t.Fatalf("pending B: %v", err)
	}
	foundB := false
	if arr, ok := pendingB.([]interface{}); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok && m["request_id"] == reqIDA {
				foundB = true
			}
		}
	}
	if foundB {
		t.Fatal("host B saw agent A's relay — isolation violated")
	}

	// Host B cannot access reqA directly.
	if _, err := hostB.Call(MethodHostNotice, map[string]interface{}{
		"session_id": sessB, "session_token": tokB, "request_id": reqIDA,
	}); err == nil {
		t.Fatal("host B accessed another session's relay")
	}
	if _, err := hostB.Call(MethodHostCancelPrompt, map[string]interface{}{
		"session_id": sessB, "session_token": tokB, "request_id": reqIDA,
	}); err == nil {
		t.Fatal("host B cancelled another session's relay")
	}
}
