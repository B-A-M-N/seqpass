package service

// P0-D regressions: the local cache must not conceal an altered replay.
// Every retry under the same provisioning request ID re-proves the FULL
// canonical request identity byte-identical via the KEYED commitment
// (HMAC-SHA256 under the broker-local secret): principal, mode, service,
// kind, label, binding, canonical operation allowlist, expiry, hints,
// resolver grant — and the secret VALUE. No plaintext and no unkeyed
// (dictionary-attackable) hash of the secret is ever persisted.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
)

// provisionOnce provisions with a fixed request ID and returns the ref.
func provisionOnce(t *testing.T, svc *Service, m *mockBrokerChild, requestID, binding string, mode string, ops []string, value string) (*ProvisionReport, *types.SecretReference) {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: value, Service: "svc", Label: "L-" + requestID,
		Kind: "api-key", Binding: binding, Operations: ops,
	}
	report, ref, err := svc.ProvisionCredential(context.Background(), "intake:test", mode, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	return report, ref
}

// retryWith re-submits under the SAME request ID with one altered
// property and asserts the keyed-commitment refusal.
func retryWith(t *testing.T, svc *Service, requestID, binding, mode string, ops []string, value, label, service, kind string) error {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: value, Service: service, Label: label,
		Kind: kind, Binding: binding, Operations: ops,
	}
	_, _, err := svc.ProvisionCredential(context.Background(), "intake:test", mode, req, nil)
	return err
}

// TestRequestIdentityAlteredReplayRefused: every behaviorally
// significant alteration under the same request ID is refused — the
// cached durable state never conceals the replay.
func TestRequestIdentityAlteredReplayRefused(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := provisionOnce(t, svc, m, "prov-ident-1", "seqpass/ident/1", IntakeSaveOnly,
		[]string{"test.credential_save"}, "ident-secret-1")

	// Idempotent baseline: the IDENTICAL request reconciles cleanly.
	if _, _, err := svc.ProvisionCredential(context.Background(), "intake:test", IntakeSaveOnly, aegiskeys.ProvisionRequest{
		RequestID: "prov-ident-1", Value: "ident-secret-1", Service: "svc", Label: "L-prov-ident-1",
		Kind: "api-key", Binding: "seqpass/ident/1", Operations: []string{"test.credential_save"},
	}, nil); err != nil {
		t.Fatalf("identical retry must reconcile idempotently: %v", err)
	}

	cases := []struct {
		name string
		mode string
		ops  []string
		val  string
		mlbl string
		svcN string
		kind string
	}{
		{"value", IntakeSaveOnly, []string{"test.credential_save"}, "EVIL-secret", "L-prov-ident-1", "svc", "api-key"},
		{"mode", IntakeSaveAndUse, []string{"test.credential_save"}, "ident-secret-1", "L-prov-ident-1", "svc", "api-key"},
		{"op-scope-widened", IntakeSaveOnly, []string{"test.credential_save", "http.request"}, "ident-secret-1", "L-prov-ident-1", "svc", "api-key"},
		{"op-scope-swapped", IntakeSaveOnly, []string{"http.request"}, "ident-secret-1", "L-prov-ident-1", "svc", "api-key"},
		{"label", IntakeSaveOnly, []string{"test.credential_save"}, "ident-secret-1", "RENAMED", "svc", "api-key"},
		{"service", IntakeSaveOnly, []string{"test.credential_save"}, "ident-secret-1", "L-prov-ident-1", "other-svc", "api-key"},
		{"kind", IntakeSaveOnly, []string{"test.credential_save"}, "ident-secret-1", "L-prov-ident-1", "svc", "password"},
	}
	for _, tc := range cases {
		err := retryWith(t, svc, "prov-ident-1", "seqpass/ident/1", tc.mode, tc.ops, tc.val, tc.mlbl, tc.svcN, tc.kind)
		if err == nil {
			t.Fatalf("%s: altered replay under the same request ID was accepted", tc.name)
		}
		if !strings.Contains(err.Error(), "identity mismatch") {
			t.Fatalf("%s: wrong refusal: %v", tc.name, err)
		}
	}
	// The durable reference is unchanged by every refused replay.
	got, _ := svc.db.GetSecretRef(ref.ID)
	if got == nil || got.ReconcileStatus != types.ProvisionReconcileCommitted || got.RecordID != ref.RecordID {
		t.Fatalf("refused replays mutated the durable reference: %+v", got)
	}
}

// TestRequestIdentityPrincipalChangeRefused: the principal participates
// in the commitment — a different intake identity cannot replay another
// principal's request.
func TestRequestIdentityPrincipalChangeRefused(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := provisionOnce(t, svc, m, "prov-ident-2", "seqpass/ident/2", IntakeSaveOnly,
		[]string{"test.credential_save"}, "ident-secret-2")

	req := aegiskeys.ProvisionRequest{
		RequestID: "prov-ident-2", Value: "ident-secret-2", Service: "svc", Label: "L-prov-ident-2",
		Kind: "api-key", Binding: "seqpass/ident/2", Operations: []string{"test.credential_save"},
	}
	if _, _, err := svc.ProvisionCredential(context.Background(), "intake:other", IntakeSaveOnly, req, nil); err == nil {
		t.Fatal("a different principal replayed another principal's request ID")
	}
	if _, _, err := svc.ProvisionStatusReport(context.Background(), "intake:other", "prov-ident-2"); err == nil {
		t.Fatal("a different principal read another principal's provisioning report")
	}
	_ = ref
}

// TestRequestCommitmentNotPlaintextNotUnkeyed: the persisted commitment
// reveals neither the plaintext nor an unkeyed hash of the secret — it
// verifies ONLY under the broker-local secret, and the value alone (even
// with full public request metadata) never reproduces it.
func TestRequestCommitmentNotPlaintextNotUnkeyed(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := provisionOnce(t, svc, m, "prov-ident-3", "seqpass/ident/3", IntakeSaveOnly,
		[]string{"test.credential_save"}, "ident-secret-3")

	if ref.RequestCommitment == "" {
		t.Fatal("no commitment stored")
	}
	if strings.Contains(ref.RequestCommitment, "ident-secret-3") {
		t.Fatal("plaintext leaked into the persisted commitment")
	}
	// An attacker with the WHOLE database can compute unkeyed hashes of
	// candidate values but cannot verify a guess: the commitment is
	// keyed under a broker-local secret that is not derivable from the
	// commitment itself.
	key, kerr := svc.db.RequestCommitmentKey()
	if kerr != nil || key == "" {
		t.Fatalf("broker commitment key unavailable: %v", kerr)
	}
	want, cerr := svc.db.ProvisionRequestCommitment("intake:test", IntakeSaveOnly, aegiskeys.ProvisionRequest{
		RequestID: "prov-ident-3", Value: "ident-secret-3", Service: "svc", Label: "L-prov-ident-3",
		Kind: "api-key", Binding: "seqpass/ident/3", Operations: []string{"test.credential_save"},
	})
	if cerr != nil || want != ref.RequestCommitment {
		t.Fatalf("commitment not reproducible under the broker key: %v", cerr)
	}
	// A DIFFERENT database (fresh broker secret) computes a different
	// commitment for the same request — the key is broker-local, not a
	// constant.
	svc2 := testService(t)
	defer svc2.Close()
	other, _ := svc2.db.ProvisionRequestCommitment("intake:test", IntakeSaveOnly, aegiskeys.ProvisionRequest{
		RequestID: "prov-ident-3", Value: "ident-secret-3", Service: "svc", Label: "L-prov-ident-3",
		Kind: "api-key", Binding: "seqpass/ident/3", Operations: []string{"test.credential_save"},
	})
	if other == ref.RequestCommitment {
		t.Fatal("commitment key is not broker-local (same across fresh databases)")
	}
}

// TestRequestIdentityLegacyRowFailsClosed: a pre-P0-D row (no
// commitment) must not be reconciled from the cache — an identity that
// was never committed cannot be trusted.
func TestRequestIdentityLegacyRowFailsClosed(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := provisionOnce(t, svc, m, "prov-ident-4", "seqpass/ident/4", IntakeSaveOnly,
		[]string{"test.credential_save"}, "ident-secret-4")

	// Simulate a legacy row (committed before P0-D): the commitment is
	// stripped at the durable layer only.
	if err := svc.db.SetSecretRefRequestCommitment(ref.ID, ""); err != nil {
		t.Fatal(err)
	}
	err := retryWith(t, svc, "prov-ident-4", "seqpass/ident/4", IntakeSaveOnly,
		[]string{"test.credential_save"}, "ident-secret-4", "L-prov-ident-4", "svc", "api-key")
	if err == nil || !strings.Contains(err.Error(), "reconciliation required") {
		t.Fatalf("legacy row reconciled from cache without a commitment: %v", err)
	}
}
