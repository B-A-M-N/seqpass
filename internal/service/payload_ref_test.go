package service

import (
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func setupPayloadRefFixture(t *testing.T, svc *Service) {
	t.Helper()
	sr := &types.SecretReference{ID: "cert1", Name: "cert", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("cert1", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	uid := uint32(1)
	dest := &types.Destination{ID: "d1", Name: "r", Type: "recipient-socket",
		Endpoint: filepath.Join(t.TempDir(), "r.sock"), ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "cert1", "transfer", "d1")
}

// SC-08: component selection is bound at submit. The empty ref and an
// explicit component:<name> selector are accepted; anything else is
// rejected before it can bind an approval.
func TestPayloadRefBoundAtSubmit(t *testing.T) {
	svc := testService(t)
	setupPayloadRefFixture(t, svc)

	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1", PayloadRef: "component:extra",
	})
	if err != nil {
		t.Fatalf("explicit component selector rejected: %v", err)
	}
	env, err := svc.OpEnvelope("transfer", id)
	if err != nil {
		t.Fatal(err)
	}
	if env["payload_ref"] != "component:extra" {
		t.Fatalf("approval envelope lost payload_ref: %v", env["payload_ref"])
	}
	// Well-formed but unavailable names pass submit (approval binds them)
	// and fail closed at execution; malformed refs never reach approval.
	for _, bad := range []string{"../evil", "component:", "all", "*", "component:\u0007"} {
		if _, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
			SecretRef: "cert1", DestinationID: "d1", PayloadRef: bad,
		}); err == nil {
			t.Fatalf("payload ref %q accepted at submit (SC-08)", bad)
		}
	}
}

// SC-08: the ephemeral spool is a development-only source. Under a
// production vault type, unbound refs fail closed instead of resolving an
// empty spool through an unreachable intake.
func TestEphemeralRejectedInProduction(t *testing.T) {
	dir := t.TempDir()
	svc, err := New(Config{DBPath: filepath.Join(dir, "prod.db"), VaultType: "aegiskeys"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	sr := &types.SecretReference{ID: "plain", Name: "plain", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	uid := uint32(1)
	dest := &types.Destination{ID: "d1", Name: "r", Type: "recipient-socket",
		Endpoint: filepath.Join(dir, "r.sock"), ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "plain", "transfer", "d1")
	if _, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "plain", DestinationID: "d1",
	}); err == nil {
		t.Fatal("ephemeral ref accepted under production vault type (SC-08)")
	}
}
