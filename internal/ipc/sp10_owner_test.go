package ipc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// SP-10: a second intake identity cannot inspect another
// intake identity's claimed request. Pre-claim, any trusted intake UID
// can claim; post-claim, only the owner proceeds.
func TestIntakeOwnerScopingService(t *testing.T) {
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(t.TempDir(), "sp10.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	uid := uint32(os.Geteuid())
	svc.AddDestination(&types.Destination{
		ID: "sp10", Name: "s", Type: "recipient-socket",
		Endpoint: "/tmp/sp10-test.sock", ExpectedUID: &uid,
	})
	reqID, err := svc.RelayRequest("agent-a", "sp10", "password", "x", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	items, err := svc.RelayInspect("uid:intake-b", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items.([]*types.RelayRecord) {
		if it.ID == reqID {
			found = true
		}
	}
	if !found {
		t.Fatal("unclaimed request not visible to intake-b")
	}
	opID, err := svc.RelayFulfill("uid:operator-a", reqID, []byte("sp10-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if opID == "" {
		t.Fatal("fulfill returned empty opID")
	}
	_, err = svc.RelayInspect("uid:intake-b", reqID, 50)
	if err == nil {
		t.Fatal("intake-b should be denied access to operator-a claimed request")
	}
	_, err = svc.RelayInspect("uid:operator-a", reqID, 50)
	if err != nil {
		t.Fatalf("owner should still inspect own request: %v", err)
	}
}
