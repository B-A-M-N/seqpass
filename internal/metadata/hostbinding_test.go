package metadata

import (
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// SP-09: a second active binding for the same (human, host_kind) is refused.
func TestCreateHostPrincipalBindingRefusesDuplicateActive(t *testing.T) {
	db := testDB(t)
	now := time.Now()
	first := &types.HostPrincipalBinding{
		HumanPrincipal: "uid:1000", AgentPrincipal: "uid:2001",
		HostKind: "codex", ExpiresAt: now.Add(time.Hour),
	}
	if err := db.CreateHostPrincipalBinding(first); err != nil {
		t.Fatal(err)
	}
	second := &types.HostPrincipalBinding{
		HumanPrincipal: "uid:1000", AgentPrincipal: "uid:2002",
		HostKind: "codex", ExpiresAt: now.Add(time.Hour),
	}
	if err := db.CreateHostPrincipalBinding(second); err == nil {
		t.Fatal("second active binding for the same human+kind accepted")
	}
}
