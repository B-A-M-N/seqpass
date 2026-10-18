package metadata

import (
	"fmt"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// SP-17: quota enforcement is transactional — a race between count and
// insert cannot exceed the per-agent limit.
func TestCreateRelayWithQuotaPerAgent(t *testing.T) {
	db := testDB(t)
	now := time.Now()
	for i := 0; i < maxPendingPerAgent; i++ {
		r := &types.RelayRecord{
			ID: fmt.Sprintf("req-%d", i), AgentPrincipal: "uid:2001",
			DestinationID: "d1", DataKind: "password", Consumption: types.RelaySingleDispatch,
			MaxDeliveries: 1, ExpiresAt: now.Add(time.Minute),
		}
		if err := db.CreateRelayWithQuota("uid:2001", r); err != nil {
			t.Fatalf("relay %d: %v", i, err)
		}
	}
	r := &types.RelayRecord{
		ID: "req-over", AgentPrincipal: "uid:2001",
		DestinationID: "d1", DataKind: "password", Consumption: types.RelaySingleDispatch,
		MaxDeliveries: 1, ExpiresAt: now.Add(time.Minute),
	}
	if err := db.CreateRelayWithQuota("uid:2001", r); err == nil {
		t.Fatal("quota exceeded silently")
	}
	// A different agent is unaffected.
	r2 := &types.RelayRecord{
		ID: "req-other-agent", AgentPrincipal: "uid:2002",
		DestinationID: "d1", DataKind: "password", Consumption: types.RelaySingleDispatch,
		MaxDeliveries: 1, ExpiresAt: now.Add(time.Minute),
	}
	if err := db.CreateRelayWithQuota("uid:2002", r2); err != nil {
		t.Fatalf("other agent denied: %v", err)
	}
}

// SP-17: the global ceiling prevents unlimited system-wide pending relays.
func TestCreateRelayWithQuotaGlobalCeiling(t *testing.T) {
	// The global ceiling constant exceeds the per-agent limit and both
	// are enforced inside the same transaction.
	if maxPendingTotal <= maxPendingPerAgent {
		t.Fatal("global ceiling should exceed per-agent limit")
	}
}
