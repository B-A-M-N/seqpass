package service

import (
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/types"
)

func relayHostFixture(t *testing.T) (*Service, string, *types.HostSession) {
	t.Helper()
	svc, err := New(Config{DBPath: t.TempDir() + "/host-events.db", VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	uid := uint32(0)
	if err := svc.AddDestination(&types.Destination{
		ID: "hd1", Name: "host destination", Type: "recipient-socket",
		Endpoint: "/tmp/seqpass-host-event-test.sock", ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	reqID, err := svc.RelayRequest("uid:2001", "hd1", "api_key", "untrusted reason", time.Minute, types.RelaySingleDispatch, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := svc.RegisterHostSession("uid:2001", "uid:1000", harness.HostRegistration{
		HostKind: harness.HostKindCodex, ThreadID: "turn-1", TTLOfSession: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, reqID, session
}

func TestHostRelayEventIsPayloadFreeAndSessionBound(t *testing.T) {
	svc, reqID, session := relayHostFixture(t)
	ev, err := svc.HostRelayEvent("uid:2001", reqID, session, 7)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != harness.HostRelayPending || ev.SessionID != session.ID ||
		ev.Sequence != 7 || ev.RequestID != reqID || ev.State != types.RelayAwaitingUser {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if _, err := svc.HostRelayEvent("uid:2002", reqID, session, 7); err == nil {
		t.Fatal("event crossed session ownership")
	}
}

func TestHostRelayReviewHidesPlaintextAndMarksPurposeUntrusted(t *testing.T) {
	svc, reqID, session := relayHostFixture(t)
	review, err := svc.HostRelayReview("uid:1000", reqID, session)
	if err != nil {
		t.Fatal(err)
	}
	if !review.TrustedHostRender || !review.PurposeUntrusted || review.Purpose != "untrusted reason" {
		t.Fatalf("review flags wrong: %+v", review)
	}
	if review.Endpoint == "" || review.DestinationName == "" || review.DataKind != "api_key" {
		t.Fatalf("verified fields missing: %+v", review)
	}
	if review.Mode != harness.InputExternalTTY || review.Assurance != string(intake.AssuranceModelBlind) {
		t.Fatalf("default assurance too strong: %+v", review)
	}
	if _, err := svc.HostRelayReview("uid:2001", reqID, session); err == nil {
		t.Fatal("wrong human accepted")
	}
}

func TestSetHostAssuranceRejectsSelfDeclaredNative(t *testing.T) {
	svc := hostSessionService(t)
	if err := svc.SetHostInputAssurance(string(harness.InputHostNative), string(intake.AssuranceModelBlind)); err != nil {
		t.Fatalf("qualified model-blind native record refused: %v", err)
	}
	if err := svc.SetHostInputAssurance(string(harness.InputHostNative), string(intake.AssuranceAgentIsolated)); err != nil {
		t.Fatalf("fully verified native refused: %v", err)
	}
}

func TestHostRelayNoticeIsVersionedAndSessionBound(t *testing.T) {
	svc, reqID, session := relayHostFixture(t)
	notice, err := svc.HostRelayNotice("uid:1000", reqID, session)
	if err != nil {
		t.Fatalf("notice: %v", err)
	}
	if notice.Version != harness.ProtectedInputNoticeSchemaVersion {
		t.Fatalf("notice version = %d", notice.Version)
	}
	if notice.RequestID != reqID || notice.RequestRev == 0 || notice.HostSessionID != session.ID {
		t.Fatalf("notice binding invalid: %+v", notice)
	}
	if notice.RecipientID != "hd1" || notice.RecipientLabel == "" || notice.Consumption != types.RelaySingleDispatch {
		t.Fatalf("notice recipient facts invalid: %+v", notice)
	}
	if notice.UntrustedPurpose != "untrusted reason" {
		t.Fatalf("untrusted purpose not preserved: %+v", notice)
	}
	if _, err := svc.HostRelayNotice("uid:2001", reqID, session); err == nil {
		t.Fatal("wrong human accepted")
	}
}
