package service

import (
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
)

func TestRegisterAndAuthenticateHostSession(t *testing.T) {
	svc := hostSessionService(t)
	reg := harness.HostRegistration{
		HostKind:     harness.HostKindCodex,
		ThreadID:     "turn-abc",
		TTLOfSession: 5 * time.Minute,
	}
	h, tok, err := svc.RegisterHostSession("uid:2001", "uid:1000", reg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if h.AgentPrincipal != "uid:2001" || h.HumanPrincipal != "uid:1000" {
		t.Fatalf("principals not broker assigned: %+v", h)
	}
	got, err := svc.HostSessionAuth(h.ID, tok.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != h.ID || got.ThreadID != "turn-abc" {
		t.Fatalf("wrong session: %+v", got)
	}
	if _, err := svc.HostSessionAuth(h.ID, "wrong"); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func TestHostSessionBindingRefusesCrossAgent(t *testing.T) {
	svc := hostSessionService(t)
	codexHost, codexToken, err := svc.RegisterHostSession("uid:2001", "uid:1000", harness.HostRegistration{HostKind: harness.HostKindCodex})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HostSessionAuth(codexHost.ID, codexToken.Token); err != nil {
		t.Fatal(err)
	}
	hermesHost, hermesToken, err := svc.RegisterHostSession("uid:2002", "uid:1000", harness.HostRegistration{HostKind: harness.HostKindHermes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HostSessionAuth(hermesHost.ID, hermesToken.Token); err != nil {
		t.Fatal(err)
	}
	// A forged thread ID is only correlation metadata. Binding validation
	// uses broker-assigned principals, not the caller's thread text.
	if err := svc.BindRelayHost("uid:2001", "req-other", hermesHost); err == nil {
		t.Fatal("foreign relay bound")
	}
	// Correctly bound unknown relay still fails closed.
	if err := svc.BindRelayHost("uid:2001", "req-other", codexHost); err == nil {
		t.Fatal("unknown relay bound")
	}
}

func hostSessionService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(Config{DBPath: t.TempDir() + "/host-session.db", VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func relayRev(svc *Service, requestID string) uint64 {
	r, err := svc.DB().GetRelay(requestID)
	if err != nil || r == nil {
		return 0
	}
	return r.Revision
}
