package service

import (
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

// CV-08: every execution-affecting field has one authoritative protection,
// and each protection demonstrably fires.
func TestApprovalEnvelopeAuthority(t *testing.T) {
	mk := func(t *testing.T) (*Service, string) {
		svc := testService(t)
		seedRef(t, svc, "s1", "")
		allowPolicy(t, svc, "uid:1000", "s1", "github.get_repo", "*")
		id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
			SecretRef: "s1", Operation: "github.get_repo",
			Params: map[string]string{"repo": "o/r"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return svc, id
	}

	// Authorization rules: a committed policy change bumps the epoch and
	// defeats a pending approval, even with the right hash and revision.
	svc, id := mk(t)
	stored, _ := svc.DB().GetUse(id)
	pols, _ := svc.DB().ListPolicies()
	if len(pols) == 0 {
		t.Fatal("no policies")
	}
	if err := svc.DB().SetPolicyEnabled(pols[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.DB().ApproveUse(id, "op", stored.OpHash, stored.AuthEpoch, stored.Revision); err == nil {
		t.Fatal("approval survived a committed authorization change (epoch guard dead)")
	}

	// Digest: approving a different action's hash fails.
	svc2, id2 := mk(t)
	stored2, _ := svc2.DB().GetUse(id2)
	other := metadata.UseOpHash("uid:1000", "s1", "github.get_repo", "",
		map[string]string{"repo": "o/other"},
		types.ResourceDescriptor{Kind: "github.repository", Identifier: "o/other"})
	if err := svc2.DB().ApproveUse(id2, "op", other, stored2.AuthEpoch, stored2.Revision); err == nil {
		t.Fatal("approval bound a different action's digest (hash guard dead)")
	}

	// Destination config: re-pinning the endpoint after approval defeats
	// the claim carrying the old digest.
	svc3 := testService(t)
	seedRef(t, svc3, "s1", "")
	allowPolicy(t, svc3, "uid:1000", "s1", "transfer", "d1")
	uid := uint32(1000)
	sock := t.TempDir() + "/r.sock"
	if err := svc3.AddDestination(&types.Destination{ID: "d1", Name: "d",
		Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}); err != nil {
		t.Fatal(err)
	}
	tid, err := svc3.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "s1", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := svc3.DB().GetTransfer(tid)
	if err := svc3.DB().ApproveTransfer(tid, "op", tr.OpHash, tr.AuthEpoch, tr.Revision); err != nil {
		t.Fatal(err)
	}
	if err := svc3.DB().UpdateDestinationEndpoint("d1", t.TempDir()+"/other.sock", "op"); err != nil {
		t.Fatal(err)
	}
	tr, _ = svc3.DB().GetTransfer(tid)
	if _, claimed, err := svc3.DB().ClaimTransfer(tid, tr.OpHash, tr.DestDigest, tr.Revision, "w", time.Now().Add(time.Minute)); err != nil || claimed {
		t.Fatalf("claim crossed a destination re-pin: claimed=%v err=%v", claimed, err)
	}
}
