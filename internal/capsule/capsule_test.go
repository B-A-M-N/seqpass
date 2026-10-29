package capsule

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func testKeys(t *testing.T) (*keyset.Handle, *keyset.Handle, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	template := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	priv, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, issuerPub, issuerPriv
}

func testPayload(now time.Time) Payload {
	return Payload{HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:work:main",
		App: "opencode", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), Credential: []byte("opaque-test-credential")}
}

func TestSealOpenAndStrictTargetBinding(t *testing.T) {
	pub, priv, issuerPub, issuerPriv := testKeys(t)
	now := time.Now().UTC().Truncate(time.Second)
	payload := testPayload(now)
	payload.Provider = "openrouter"
	e, err := Seal(payload, "recipient-key-1", "issuer-key-1", pub, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(parsed, Expect{RecipientKeyID: "recipient-key-1", SigningKeyID: "issuer-key-1", HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:work:main", App: "opencode", Provider: "openrouter", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7, Now: now}, issuerPub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Credential) != string(payload.Credential) || got.App != payload.App || got.Account != payload.Account || got.Slot != payload.Slot {
		t.Fatal("opened payload did not preserve its authenticated target")
	}
	zero(got.Credential)
	if _, err := Open(parsed, Expect{RecipientKeyID: "substituted", SigningKeyID: "issuer-key-1", HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:work:main", App: "opencode", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7, Now: now}, issuerPub, priv); err == nil {
		t.Fatal("accepted recipient key substitution")
	}
	targetSubstitution := Expect{RecipientKeyID: "recipient-key-1", SigningKeyID: "issuer-key-1", HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:attacker:main", App: "opencode", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7, Now: now}
	if _, err := Open(parsed, targetSubstitution, issuerPub, priv); err == nil {
		t.Fatal("accepted target identity substitution")
	}
	providerSubstitution := Expect{RecipientKeyID: "recipient-key-1", SigningKeyID: "issuer-key-1", HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:work:main", App: "opencode", Provider: "some-other-provider", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7, Now: now}
	if _, err := Open(parsed, providerSubstitution, issuerPub, priv); err == nil {
		t.Fatal("accepted provider identity substitution")
	}
}

func TestOpenRejectsTamperExpiryUnknownVersionAndTrailingJSON(t *testing.T) {
	pub, priv, issuerPub, issuerPriv := testKeys(t)
	now := time.Now().UTC().Truncate(time.Second)
	e, err := Seal(testPayload(now), "recipient-key-1", "issuer-key-1", pub, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	expect := Expect{RecipientKeyID: "recipient-key-1", SigningKeyID: "issuer-key-1", HandoffID: "handoff-1", OperationID: "op-1", DestinationID: "dest-1", DestinationRevision: 3, TargetID: "opencode:work:main", App: "opencode", Account: "work", Slot: "main", UpdateMethod: "opencode-config", SourceRef: "aegis/ref-1", SourceRevision: 7, Now: now}
	bad := e
	bad.Ciphertext = append([]byte(nil), e.Ciphertext...)
	bad.Ciphertext[len(bad.Ciphertext)-1] ^= 1
	if _, err := Open(bad, expect, issuerPub, priv); err == nil {
		t.Fatal("accepted ciphertext tamper")
	}
	bad = e
	bad.Version++
	if _, err := Open(bad, expect, issuerPub, priv); err == nil {
		t.Fatal("accepted unknown version")
	}
	expect.Now = now.Add(6 * time.Minute)
	if _, err := Open(e, expect, issuerPub, priv); err == nil {
		t.Fatal("accepted expired capsule")
	}
	wire, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(append(wire, []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if _, err := Parse([]byte(strings.Replace(string(wire), `"version":1`, `"version":1,"unknown":true`, 1))); err == nil {
		t.Fatal("accepted unknown envelope field")
	}
}

func TestSealRejectsUnboundedLifetime(t *testing.T) {
	pub, _, _, issuerPriv := testKeys(t)
	now := time.Now().UTC()
	p := testPayload(now)
	p.ExpiresAt = now.Add(16 * time.Minute)
	if _, err := Seal(p, "recipient-key-1", "issuer-key-1", pub, issuerPriv); err == nil {
		t.Fatal("accepted unbounded lifetime")
	}
}

func TestRecipientAndIssuerKeyEnrollmentRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	privatePath, publicPath := filepath.Join(root, "recipient.tink.json"), filepath.Join(root, "recipient.pub")
	pubBytes, err := GenerateRecipientKeys(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPub, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pubBytes) != string(loadedPub) || len(pubBytes) != 32 {
		t.Fatal("recipient public key export mismatch")
	}
	priv, err := LoadRecipientPrivate(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("recipient private key mode=%o", info.Mode().Perm())
	}
	issuerPrivatePath, issuerPublicPath := filepath.Join(root, "issuer.seed"), filepath.Join(root, "issuer.pub")
	issuerPub, err := GenerateIssuerKeys(issuerPrivatePath, issuerPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedIssuerPub, err := os.ReadFile(issuerPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(issuerPub) != string(loadedIssuerPub) {
		t.Fatal("issuer public key export mismatch")
	}
	issuerPriv, err := LoadIssuerPrivate(issuerPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	pubHandle, err := RecipientPublicHandle(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := testPayload(now)
	env, err := Seal(p, "recipient-key-1", "issuer-key-1", pubHandle, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(env, Expect{RecipientKeyID: "recipient-key-1", SigningKeyID: "issuer-key-1", HandoffID: p.HandoffID, OperationID: p.OperationID, DestinationID: p.DestinationID, DestinationRevision: p.DestinationRevision, TargetID: p.TargetID, App: p.App, Account: p.Account, Slot: p.Slot, UpdateMethod: p.UpdateMethod, Activation: p.Activation, SourceRef: p.SourceRef, SourceRevision: p.SourceRevision, Now: now}, issuerPub, priv)
	if err != nil || string(opened.Credential) != string(p.Credential) {
		t.Fatalf("enrolled keys failed capsule round trip: %v", err)
	}
	zero(opened.Credential)
	zero(issuerPriv)
}
