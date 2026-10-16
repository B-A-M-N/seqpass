package hostnative

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

func TestHostSessionNoticeBinding(t *testing.T) {
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(t.TempDir(), "binding.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	uid := uint32(0)
	if err := svc.AddDestination(&types.Destination{
		ID: "registered-service", Name: "Registered Recipient", Type: "recipient-socket",
		Endpoint: "/tmp/seqpass-host-native-contract.sock", ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	reqID, err := svc.RelayRequest("uid:2001", "registered-service", "api_key", "untrusted note", time.Minute, types.RelaySingleDispatch, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := svc.RegisterHostSession("uid:2001", "uid:1000", harness.HostRegistration{
		HostKind: harness.HostKindOpenCode, ThreadID: "thread-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	notice, err := svc.HostRelayNotice("uid:1000", reqID, session)
	if err != nil {
		t.Fatalf("notice: %v", err)
	}
	if notice.HostSessionID != session.ID || notice.RequestID != reqID || notice.RequestRev == 0 {
		t.Fatalf("notice not session/request bound: %+v", notice)
	}
	if _, err := svc.HostRelayNotice("uid:999", reqID, session); err == nil {
		t.Fatal("wrong human accepted")
	}
	if _, err := svc.HostRelayNotice("uid:1000", "req-unknown", session); err == nil {
		t.Fatal("unknown request accepted")
	}
}
