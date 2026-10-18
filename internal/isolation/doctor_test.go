package isolation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkPublicTempDir creates a directory under /tmp (world-traversable), unlike
// t.TempDir whose ancestors are 0700 and would make every identity look
// blocked for the wrong reason.
func mkPublicTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "seqpass-iso-")
	if err != nil {
		t.Skipf("no public temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// best-effort deployments must always be labelled unverified, never verified.
func TestDoctorBestEffortIsUnverified(t *testing.T) {
	rep, err := Doctor(Config{AssuranceMode: ModeBestEffort, BrokerUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified {
		t.Fatal("best-effort topology reported verified")
	}
	if !rep.Unverified || rep.Label != LabelUnverified {
		t.Fatalf("best-effort not labelled unverified: %+v", rep)
	}
}

// An isolated claim with the agent sharing the broker identity fails closed.
func TestDoctorSameUIDAgentFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "metadata.db")
	if err := os.WriteFile(db, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	rep, err := Doctor(Config{
		AssuranceMode: ModeIsolated,
		BrokerUID:     uid,
		AgentUIDs:     []uint32{uid},
		DBPath:        db,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified {
		t.Fatal("same-UID agent topology reported verified")
	}
	found := false
	for _, n := range rep.FailedNames() {
		if n == "identity_disjoint" {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity overlap not detected: %+v", rep.Checks)
	}
}

// An agent identity that cannot even traverse the protected directory is
// reported as denied.
func TestDoctorDeniedAccessReported(t *testing.T) {
	root := t.TempDir()
	prot := filepath.Join(root, "protected")
	if err := os.Mkdir(prot, 0700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(prot, "metadata.db")
	if err := os.WriteFile(db, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// A UID that is neither the owner nor a group member (and is
	// unresolvable, so the doctor assumes the worst case for group bits).
	agent := uint32(65533)
	if agent == uint32(os.Geteuid()) {
		t.Skip("agent uid collides with the test identity")
	}
	rep, err := Doctor(Config{
		AssuranceMode: ModeIsolated,
		BrokerUID:     uint32(os.Geteuid()),
		AgentUIDs:     []uint32{agent},
		DBPath:        db,
		AdminSocket:   filepath.Join(prot, "admin.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !checkByName(rep, "agent_denied_broker_database") {
		t.Fatalf("owner-only database reported accessible: %+v", rep.Checks)
	}
}

// A world-readable protected object is reported accessible, so the
// deployment is not verified even though it was configured isolated.
func TestDoctorDetectsAccessibleProtectedObject(t *testing.T) {
	dir := mkPublicTempDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "metadata.db")
	if err := os.WriteFile(db, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	agent := uint32(65533)
	if agent == uint32(os.Geteuid()) {
		t.Skip("agent uid collides with the test identity")
	}
	rep, err := Doctor(Config{
		AssuranceMode: ModeIsolated,
		BrokerUID:     uint32(os.Geteuid()),
		AgentUIDs:     []uint32{agent},
		DBPath:        db,
	})
	if err != nil {
		t.Fatal(err)
	}
	if checkByName(rep, "agent_denied_broker_database") {
		t.Fatalf("world-readable database reported denied: %+v", rep.Checks)
	}
	if rep.Verified {
		t.Fatal("accessible protected object still reported verified")
	}
}

// The doctor must not claim terminal isolation: that is a property of the
// specific terminal the human types into, decided by host qualification, and
// it cannot be observed from the agent's process. Claiming it would let
// VerifiedProperties.Complete report agent_isolated from an unproven fact.
func TestDoctorDoesNotClaimTerminalIsolation(t *testing.T) {
	agent := uint32(65533)
	if agent == uint32(os.Geteuid()) {
		t.Skip("agent uid collides with the test identity")
	}
	rep, err := Doctor(Config{
		AssuranceMode: ModeIsolated,
		BrokerUID:     uint32(os.Geteuid()),
		AgentUIDs:     []uint32{agent},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Properties.TerminalIsolated {
		t.Fatalf("doctor claimed terminal isolation it cannot verify: %+v", rep.Properties)
	}
	// Every other property may be reported from live evidence, but the
	// incomplete set must never read as complete.
	if rep.Properties.Complete() {
		t.Fatalf("incomplete properties reported complete: %+v", rep.Properties)
	}
}

// A broker-owned protected object that does not exist must not be scored as
// though the agent were denied access to it.
func TestDoctorMissingBrokerOwnedObjectFails(t *testing.T) {
	dir := mkPublicTempDir(t)
	agent := uint32(65533)
	if agent == uint32(os.Geteuid()) {
		t.Skip("agent uid collides with the test identity")
	}
	rep, err := Doctor(Config{
		AssuranceMode: ModeIsolated,
		BrokerUID:     uint32(os.Geteuid()),
		AgentUIDs:     []uint32{agent},
		AdminSocket:   filepath.Join(dir, "does-not-exist.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if checkByName(rep, "agent_denied_admin_socket") {
		t.Fatalf("absent broker-owned socket reported as protected: %+v", rep.Checks)
	}
	if rep.Verified {
		t.Fatal("missing broker-owned protected object still reported verified")
	}
}

// An external endpoint that is merely idle is reported as absent truthfully,
// without claiming protection was proven, and without failing the topology.
func TestDoctorAbsentRecipientEndpointIsReportedNotClaimedProtected(t *testing.T) {
	dir := mkPublicTempDir(t)
	agent := uint32(65533)
	if agent == uint32(os.Geteuid()) {
		t.Skip("agent uid collides with the test identity")
	}
	sock := filepath.Join(dir, "idle-recipient.sock")
	rep, err := Doctor(Config{
		AssuranceMode:      ModeIsolated,
		BrokerUID:          uint32(os.Geteuid()),
		AgentUIDs:          []uint32{agent},
		RecipientEndpoints: []string{sock},
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, detail := "", ""
	for _, c := range rep.Checks {
		if c.Name == "agent_denied_recipient_socket" {
			ok, detail = c.Name, c.Detail
			if !c.OK {
				t.Fatalf("idle recipient endpoint failed the topology: %+v", c)
			}
		}
	}
	if ok == "" {
		t.Fatalf("recipient endpoint was not evaluated: %+v", rep.Checks)
	}
	if detail == "protected" {
		t.Fatalf("absent endpoint reported as protected: %q", detail)
	}
	if !strings.Contains(detail, "absent") {
		t.Fatalf("absent endpoint detail not truthful: %q", detail)
	}
}

func TestAccessibleByGroupAndOwner(t *testing.T) {
	dir := mkPublicTempDir(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	// Owner can read.
	if ok, _ := accessibleBy(f, uid, nil, false, false); !ok {
		t.Fatal("owner denied read")
	}
	// A member of the file's group can read once the directory allows
	// traversal (unknown groups forces the group path, modelling an
	// unresolvable identity).
	if err := os.Chmod(dir, 0711); err != nil {
		t.Fatal(err)
	}
	if ok, _ := accessibleBy(f, 65533, nil, true, false); !ok {
		t.Fatal("group read denied")
	}
	// An unrelated identity with no group membership and owner-only
	// directory traversal is denied.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if ok, _ := accessibleBy(f, 65533, nil, false, false); ok {
		t.Fatal("unrelated identity allowed through an owner-only directory")
	}
}
