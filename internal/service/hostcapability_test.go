package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/types"
)

func TestRegisterHostSessionNegotiatesCapabilities(t *testing.T) {
	svc := hostSessionService(t)
	reg := harness.HostRegistration{
		HostKind:       harness.HostKindOpenCode,
		ThreadID:       "thread-1",
		HostVersion:    "2.0",
		AdapterVersion: "0.1",
		Credentials: harness.HostCapabilities{
			Presentation:            "native",
			InputTransport:          "protected_intake",
			SupportsResume:          true,
			SupportsCancelPrompt:    true,
			SupportsMultiplePending: true,
		},
	}
	if err := svc.DB().CreateHostPrincipalBinding(&types.HostPrincipalBinding{
		HumanPrincipal: "uid:1000", AgentPrincipal: "uid:2001", HostKind: string(harness.HostKindOpenCode),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	_, token, err := svc.RegisterHostSession("uid:2001", "uid:1000", reg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	got := token.Credentials
	if got.Presentation != "native" || got.InputTransport != "protected_intake" {
		t.Fatalf("native capability not retained: %+v", got)
	}
	if got.CredentialFormViaMCP {
		t.Fatal("MCP credential form must remain prohibited in the capability contract")
	}
	if !got.SupportsResume || !got.SupportsCancelPrompt || !got.SupportsMultiplePending {
		t.Fatalf("optional capability flags lost: %+v", got)
	}
}

func TestRegisterAllSevenHarnessHostKinds(t *testing.T) {
	svc := hostSessionService(t)
	for i, kind := range []harness.HostSessionKind{
		harness.HostKindCodex, harness.HostKindOpenCode, harness.HostKindPi,
		harness.HostKindJCode, harness.HostKindQwen, harness.HostKindClaude,
		harness.HostKindAgy,
	} {
		reg := harness.HostRegistration{HostKind: kind, ThreadID: "turn"}
		if err := svc.DB().CreateHostPrincipalBinding(&types.HostPrincipalBinding{
			HumanPrincipal: "uid:1000", AgentPrincipal: "uid:2001", HostKind: string(kind),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		host, token, err := svc.RegisterHostSession("uid:2001", "uid:1000", reg)
		if err != nil {
			t.Fatalf("%s register: %v", kind, err)
		}
		if host.HostKind != string(kind) {
			t.Fatalf("%s host kind changed", kind)
		}
		if token.Credentials.Presentation != "request_status" || token.Credentials.InputTransport != "external_tty" {
			t.Fatalf("%s default capability too strong: %+v", kind, token.Credentials)
		}
		if i == 0 {
			continue
		}
	}
}

func TestUnknownHostKindRejected(t *testing.T) {
	svc := hostSessionService(t)
	if _, _, err := svc.RegisterHostSession("uid:2001", "uid:1000", harness.HostRegistration{HostKind: "not-a-harness"}); err == nil {
		t.Fatal("unknown host kind accepted")
	}
}

func TestRelayFulfillRejectRequiresExactReviewedRevision(t *testing.T) {
	svc := hostSessionService(t)
	uid := uint32(0)
	if err := svc.AddDestination(&types.Destination{
		ID: "revd1", Name: "rev recipient", Type: "recipient-socket",
		Endpoint: filepath.Join(testruntime.DirOrTemp(t), "recipient.sock"), ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	reqID, err := svc.RelayRequest("uid:2001", "revd1", "api_key", "", time.Minute, types.RelaySingleDispatch, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.DB().GetRelay(reqID)
	if err != nil || r == nil {
		t.Fatal("relay missing")
	}
	if err := svc.RelayReject("uid:1000", reqID, r.Revision+1); err == nil {
		t.Fatal("stale reject accepted")
	}
	if err := svc.RelayReject("uid:1000", reqID, r.Revision); err != nil {
		t.Fatalf("current reject refused: %v", err)
	}
	reqID2, err := svc.RelayRequest("uid:2001", "revd1", "api_key", "", time.Minute, types.RelaySingleDispatch, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RelayFulfill("uid:1000", reqID2, 999, []byte("secret")); err == nil {
		t.Fatal("stale fulfill accepted")
	}
	if _, err := svc.RelayFulfill("uid:1000", reqID2, 0, []byte("secret")); err == nil {
		t.Fatal("missing revision accepted")
	}
	r2, err := svc.DB().GetRelay(reqID2)
	if err != nil || r2 == nil {
		t.Fatal("second relay missing")
	}
	if _, err := svc.RelayFulfill("uid:1000", reqID2, r2.Revision, []byte("secret")); err != nil {
		t.Fatalf("current fulfill refused: %v", err)
	}
}
