package metadata

import (
	"bytes"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestSealedCapsuleDestinationPinsRecipientAndAppTarget(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{
		ID: "dest-capsule", Name: "work app", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock",
		ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule, RecipientKeyID: "recipient-key-2026-01", ReceiptKeyID: "receipt-key-2026-01", IssuerKeyID: "issuer-key-2026-01",
		RecipientPublicKey: bytes.Repeat([]byte{0x5a}, 32),
		ReceiptPublicKey:   bytes.Repeat([]byte{0x5c}, 32),
		IssuerPublicKey:    bytes.Repeat([]byte{0x6b}, 32),
		CredentialTarget:   &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "aegis/ref-7", SourceRevision: 4},
	}
	if err := db.CreateDestination(dest); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDestination(dest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.RecipientKeyID != dest.RecipientKeyID || got.ReceiptKeyID != dest.ReceiptKeyID || got.IssuerKeyID != dest.IssuerKeyID || !bytes.Equal(got.RecipientPublicKey, dest.RecipientPublicKey) || !bytes.Equal(got.ReceiptPublicKey, dest.ReceiptPublicKey) || !bytes.Equal(got.IssuerPublicKey, dest.IssuerPublicKey) || got.CredentialTarget == nil || *got.CredentialTarget != *dest.CredentialTarget {
		t.Fatalf("destination key and target failed to round-trip: %#v", got)
	}
	base := DestDigest(got)
	changedKey := *got
	changedKey.RecipientPublicKey = append([]byte(nil), got.RecipientPublicKey...)
	changedKey.RecipientPublicKey[0] ^= 1
	if DestDigest(&changedKey) == base {
		t.Fatal("recipient key change did not invalidate approval digest")
	}
	changedTarget := *got
	target := *got.CredentialTarget
	target.Slot = "fast"
	changedTarget.CredentialTarget = &target
	if DestDigest(&changedTarget) == base {
		t.Fatal("app target change did not invalidate approval digest")
	}
	changedIssuer := *got
	changedIssuer.IssuerKeyID = "issuer-key-rotated"
	if DestDigest(&changedIssuer) == base {
		t.Fatal("issuer key change did not invalidate approval digest")
	}
	changedIssuerPublic := *got
	changedIssuerPublic.IssuerPublicKey = append([]byte(nil), got.IssuerPublicKey...)
	changedIssuerPublic.IssuerPublicKey[0] ^= 1
	if DestDigest(&changedIssuerPublic) == base {
		t.Fatal("issuer public key change did not invalidate approval digest")
	}
	changedReceipt := *got
	changedReceipt.ReceiptPublicKey = append([]byte(nil), got.ReceiptPublicKey...)
	changedReceipt.ReceiptPublicKey[0] ^= 1
	if DestDigest(&changedReceipt) == base {
		t.Fatal("recipient receipt key change did not invalidate approval digest")
	}
}

func TestSealedCapsuleDestinationRequiresPinnedKeyAndTarget(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{ID: "bad-capsule", Name: "bad", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock", ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule}
	if err := db.CreateDestination(dest); err == nil {
		t.Fatal("accepted sealed destination without recipient key and app target")
	}
	dest.RecipientKeyID = "recipient-key"
	dest.RecipientPublicKey = bytes.Repeat([]byte{1}, 32)
	dest.IssuerKeyID = "issuer-key"
	dest.IssuerPublicKey = bytes.Repeat([]byte{2}, 32)
	dest.CredentialTarget = &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "ref", SourceRevision: 1}
	dest.ReceiptKeyID = "receipt-key"
	dest.ReceiptPublicKey = append([]byte(nil), dest.IssuerPublicKey...)
	if err := db.CreateDestination(dest); err == nil {
		t.Fatal("accepted the issuer signing key as the recipient receipt key")
	}
	dest.ReceiptPublicKey = bytes.Repeat([]byte{3}, 32)
	dest.ReceiptKeyID = dest.IssuerKeyID
	if err := db.CreateDestination(dest); err == nil {
		t.Fatal("accepted the issuer key ID for the recipient receipt signer")
	}
	dest.ReceiptKeyID = "receipt-key"
	if err := db.CreateDestination(dest); err != nil {
		t.Fatalf("rejected valid distinct signing identities: %v", err)
	}
}

func TestOpenCodeV2TargetCanBeRegistered(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{
		ID: "dest-opencode-v2", Name: "OpenCode v2", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock",
		ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule,
		RecipientKeyID: "recipient-v2", RecipientPublicKey: bytes.Repeat([]byte{0x51}, 32),
		ReceiptKeyID: "receipt-v2", ReceiptPublicKey: bytes.Repeat([]byte{0x53}, 32),
		IssuerKeyID: "issuer-v2", IssuerPublicKey: bytes.Repeat([]byte{0x61}, 32),
		CredentialTarget: &types.AppCredentialTarget{
			ID: "opencode:openrouter:api_key", App: "opencode", Account: "openrouter", Slot: "api_key",
			UpdateMethod: "opencode-auth-import-v2", SourceRef: "aegis/ref-v2", SourceRevision: 1,
		},
	}
	if err := db.CreateDestination(dest); err != nil {
		t.Fatalf("OpenCode v2 target registration failed: %v", err)
	}
}

func TestCodexTargetCanBeRegistered(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{
		ID: "dest-codex", Name: "Codex", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock",
		ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule,
		RecipientKeyID: "recipient-codex-r1", RecipientPublicKey: bytes.Repeat([]byte{0x31}, 32),
		ReceiptKeyID: "receipt-codex-r1", ReceiptPublicKey: bytes.Repeat([]byte{0x33}, 32),
		IssuerKeyID: "issuer-codex-r1", IssuerPublicKey: bytes.Repeat([]byte{0x41}, 32),
		CredentialTarget: &types.AppCredentialTarget{
			ID: "codex:openai:api_key", App: "codex", Account: "openai", Slot: "api_key",
			UpdateMethod: "codex-auth-file-v1", SourceRef: "aegis/openai", SourceRevision: 1,
		},
	}
	if err := db.CreateDestination(dest); err != nil {
		t.Fatalf("Codex target registration failed: %v", err)
	}
}

func TestFIGatewayCredentialTargetCanBeRegistered(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{
		ID: "dest-fi-gateway", Name: "FI Gateway", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock",
		ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule,
		RecipientKeyID: "recipient-fi-gateway-r1", RecipientPublicKey: bytes.Repeat([]byte{0x71}, 32),
		ReceiptKeyID: "receipt-fi-gateway-r1", ReceiptPublicKey: bytes.Repeat([]byte{0x73}, 32),
		IssuerKeyID: "issuer-fi-gateway-r1", IssuerPublicKey: bytes.Repeat([]byte{0x72}, 32),
		CredentialTarget: &types.AppCredentialTarget{
			ID: "fi-gateway:openrouter:primary:api_key", App: "fi-gateway", Provider: "openrouter",
			Account: "primary", Slot: "api_key", UpdateMethod: "fi-gateway-credential-manager-v1",
			SourceRef: "aegis/openrouter", SourceRevision: 1,
		},
	}
	if err := db.CreateDestination(dest); err != nil {
		t.Fatalf("FI Gateway credential target registration failed: %v", err)
	}
}

func TestRecipientKeyRotationBumpsRevisionAndAuthorizationEpoch(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid := uint32(2201)
	dest := &types.Destination{ID: "rotate-dest", Name: "work", Type: "recipient-socket", Endpoint: "/run/seqpass/recipient.sock", ExpectedUID: &uid,
		HandoffMode: types.HandoffSealedCapsule, RecipientKeyID: "key-old", RecipientPublicKey: bytes.Repeat([]byte{1}, 32), ReceiptKeyID: "receipt-old", ReceiptPublicKey: bytes.Repeat([]byte{5}, 32), IssuerKeyID: "issuer-old", IssuerPublicKey: bytes.Repeat([]byte{3}, 32),
		CredentialTarget: &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "ref-1", SourceRevision: 1}}
	if err := db.CreateDestination(dest); err != nil {
		t.Fatal(err)
	}
	before, err := db.GetDestination(dest.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeDigest := DestDigest(before)
	var beforeEpoch int64
	if err := db.db.QueryRow(`SELECT epoch FROM authorization_state WHERE id=1`).Scan(&beforeEpoch); err != nil {
		t.Fatal(err)
	}
	newTarget := *dest.CredentialTarget
	newTarget.Account = "work-rotated"
	newTarget.ID = "opencode:work-rotated:api_key"
	newKey := bytes.Repeat([]byte{2}, 32)
	newReceiptKey := bytes.Repeat([]byte{6}, 32)
	newIssuerPublic := bytes.Repeat([]byte{4}, 32)
	if err := db.UpdateDestinationHandoffIdentity(dest.ID, types.HandoffSealedCapsule, "key-new", newKey, "receipt-new", newReceiptKey, "issuer-new", newIssuerPublic, nil, nil, &newTarget, "operator"); err != nil {
		t.Fatal(err)
	}
	after, err := db.GetDestination(dest.ID)
	if err != nil {
		t.Fatal(err)
	}
	var afterEpoch int64
	if err := db.db.QueryRow(`SELECT epoch FROM authorization_state WHERE id=1`).Scan(&afterEpoch); err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision+1 || afterEpoch != beforeEpoch+1 || after.RecipientKeyID != "key-new" || after.ReceiptKeyID != "receipt-new" || after.IssuerKeyID != "issuer-new" || !bytes.Equal(after.RecipientPublicKey, newKey) || !bytes.Equal(after.ReceiptPublicKey, newReceiptKey) || !bytes.Equal(after.IssuerPublicKey, newIssuerPublic) || DestDigest(after) == beforeDigest {
		t.Fatalf("recipient rotation did not invalidate authorization: before=%#v after=%#v epochs=%d/%d", before, after, beforeEpoch, afterEpoch)
	}
}
