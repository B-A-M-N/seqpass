package service

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func submitUnapproved(t *testing.T, svc *Service) string {
	t.Helper()
	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// SC-02: concurrent approvals of the same reviewed revision are serialized
// by the atomic CAS — exactly one wins, the rest fail closed.
func TestConcurrentApproveSingleWinner(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id := submitUnapproved(t, svc)
	tr, _ := svc.DB().GetTransfer(id)

	const racers = 8
	var wins int64
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.ApproveTransfer(id, "operator", tr.Revision); err == nil {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("approval CAS admitted %d winners, want exactly 1 (SC-02)", wins)
	}
}

// SC-02: a review bound to an older authorization epoch cannot authorize
// after revocation. Bumping the epoch (policy toggle) invalidates the
// operator's stale artifact.
func TestStaleEpochApprovalDenied(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id := submitUnapproved(t, svc)
	tr, _ := svc.DB().GetTransfer(id)

	pols, err := svc.DB().ListPolicies()
	if err != nil || len(pols) == 0 {
		t.Fatalf("policies: %v", pols)
	}
	if err := svc.DB().SetPolicyEnabled(pols[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(id, "operator", tr.Revision); err == nil {
		t.Fatal("stale-epoch approval succeeded after revocation (SC-02)")
	}
}

// SC-02: a destination edit behind the operator's back invalidates the
// reviewed artifact. The endpoint update bumps revision + epoch, so the
// approval CAS (revision + live epoch) fails closed; even if approved, the
// claim-time digest check would refuse the changed destination.
func TestChangedDestinationApprovalDenied(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)
	id := submitUnapproved(t, svc)
	tr, _ := svc.DB().GetTransfer(id)
	if err := svc.DB().UpdateDestinationEndpoint("d1", "/tmp/moved.sock", "operator"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(id, "operator", tr.Revision); err == nil {
		t.Fatal("approval succeeded for a changed destination (SC-02)")
	}
}
