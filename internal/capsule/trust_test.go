package capsule

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestRecipientTrustIsLocalPrivateAndCreateOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(root, "recipient.key")
	if err := os.WriteFile(privateKey, []byte("private"), 0400); err != nil {
		t.Fatal(err)
	}
	trustPath, err := DefaultRecipientTrustPath(root, "opencode-primary")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustPath), 0700); err != nil {
		t.Fatal(err)
	}
	trust := RecipientTrust{
		Version: RecipientTrustVersion, DestinationID: "opencode-primary", DestinationRevision: 3,
		RecipientKeyID: "recipient-r3", RecipientPrivateKey: privateKey,
		IssuerKeyID: "issuer-r1", IssuerPublicKey: make([]byte, 32),
		ReceiptKeyID: "receipt-r3", ReceiptPrivateKey: filepath.Join(root, "receipt.seed"), ReceiptPublicKey: bytes.Repeat([]byte{1}, 32),
		Target:       types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "provider/work", SourceRevision: 5},
		BrokerSocket: filepath.Join(root, "broker.sock"),
	}
	if err := StoreRecipientTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	sharedKey := trust
	sharedKey.ReceiptPublicKey = append([]byte(nil), sharedKey.IssuerPublicKey...)
	if err := sharedKey.Validate(); err == nil {
		t.Fatal("recipient trust reused the issuer signing key for receipts")
	}
	sharedID := trust
	sharedID.ReceiptKeyID = sharedID.IssuerKeyID
	if err := sharedID.Validate(); err == nil {
		t.Fatal("recipient trust reused an identity ID across signing roles")
	}
	sharedID = trust
	sharedID.RecipientKeyID = sharedID.IssuerKeyID
	if err := sharedID.Validate(); err == nil {
		t.Fatal("recipient trust reused an identity ID across encryption and signing roles")
	}
	info, err := os.Stat(trustPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("trust registration mode=%v err=%v", info, err)
	}
	loaded, err := LoadRecipientTrust(trustPath)
	if err != nil || loaded.Version != trust.Version || loaded.DestinationID != trust.DestinationID || loaded.DestinationRevision != trust.DestinationRevision || loaded.RecipientKeyID != trust.RecipientKeyID || loaded.RecipientPrivateKey != trust.RecipientPrivateKey || loaded.IssuerKeyID != trust.IssuerKeyID || !bytes.Equal(loaded.IssuerPublicKey, trust.IssuerPublicKey) || loaded.ReceiptKeyID != trust.ReceiptKeyID || loaded.ReceiptPrivateKey != trust.ReceiptPrivateKey || !bytes.Equal(loaded.ReceiptPublicKey, trust.ReceiptPublicKey) || loaded.Target != trust.Target || loaded.BrokerSocket != trust.BrokerSocket {
		t.Fatalf("loaded trust mismatch: %#v err=%v", loaded, err)
	}
	if err := StoreRecipientTrust(trustPath, trust); err == nil {
		t.Fatal("registration replacement was not refused")
	}
	if got, err := DefaultRecipientTrustPath(root, "../attacker"); err == nil || got != "" {
		t.Fatalf("unsafe destination ID escaped registration directory: %q %v", got, err)
	}
}

func TestRecipientTrustRejectsSymlinkAndWritableRegistration(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	trustPath, err := DefaultRecipientTrustPath(root, "destination")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(trustPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "other.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other.json"), trustPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecipientTrust(trustPath); err == nil {
		t.Fatal("symlink trust registration was accepted")
	}
	if err := os.Remove(trustPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, []byte(`{"version":1}`), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(trustPath, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecipientTrust(trustPath); err == nil {
		t.Fatal("group/world-writable trust registration was accepted")
	}
}

func TestRecipientTrustPinsCodexCommandAndHome(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".config", "seqpass", "recipients"), 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "recipient.key")
	if err := os.WriteFile(key, []byte("private"), 0400); err != nil {
		t.Fatal(err)
	}
	trust := RecipientTrust{
		Version: RecipientTrustVersion, DestinationID: "codex-primary", DestinationRevision: 2,
		RecipientKeyID: "recipient-r2", RecipientPrivateKey: key,
		IssuerKeyID: "issuer-r1", IssuerPublicKey: make([]byte, 32),
		ReceiptKeyID: "receipt-r2", ReceiptPrivateKey: filepath.Join(root, "receipt.seed"), ReceiptPublicKey: bytes.Repeat([]byte{1}, 32),
		Target: types.AppCredentialTarget{
			ID: "codex:openai:api_key", App: "codex", Account: "openai", Slot: "api_key",
			UpdateMethod: "codex-auth-file-v1", SourceRef: "provider/openai", SourceRevision: 4,
		},
		BrokerSocket: filepath.Join(root, "broker.sock"), CodexCommand: "/usr/bin/codex",
		CodexHome: filepath.Join(root, ".codex"),
	}
	path, err := DefaultRecipientTrustPath(root, trust.DestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := StoreRecipientTrust(path, trust); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRecipientTrust(path)
	if err != nil || loaded.Target != trust.Target || loaded.CodexCommand != trust.CodexCommand || loaded.CodexHome != trust.CodexHome {
		t.Fatalf("Codex recipient pins did not round-trip: %#v err=%v", loaded, err)
	}
}

func TestRecipientTrustPinsFIGatewaySocketAndProviderTarget(t *testing.T) {
	root := t.TempDir()
	peerUID := uint32(4242)
	trust := RecipientTrust{
		Version: RecipientTrustVersion, DestinationID: "fi-gateway", DestinationRevision: 1,
		RecipientKeyID: "recipient-r1", RecipientPrivateKey: filepath.Join(root, "recipient.key"),
		IssuerKeyID: "issuer-r1", IssuerPublicKey: make([]byte, 32),
		ReceiptKeyID: "receipt-r1", ReceiptPrivateKey: filepath.Join(root, "receipt.seed"), ReceiptPublicKey: bytes.Repeat([]byte{1}, 32),
		Target: types.AppCredentialTarget{
			ID: "fi-gateway:openrouter:staging:api_key", App: "fi-gateway", Provider: "openrouter",
			Account: "staging", Slot: "api_key", UpdateMethod: "fi-gateway-credential-manager-v1",
			SourceRef: "provider/openrouter", SourceRevision: 2,
		},
		BrokerSocket:     filepath.Join(root, "seqpass-broker.sock"),
		FIGatewaySocket:  filepath.Join(root, "fi-gateway-credentials.sock"),
		FIGatewayPeerUID: &peerUID,
	}
	if err := trust.Validate(); err != nil {
		t.Fatalf("valid FI Gateway recipient trust rejected: %v", err)
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	var loaded RecipientTrust
	if err := json.Unmarshal(encoded, &loaded); err != nil || loaded.FIGatewayPeerUID == nil || *loaded.FIGatewayPeerUID != peerUID {
		t.Fatalf("gateway peer UID pin did not round-trip: %#v err=%v", loaded.FIGatewayPeerUID, err)
	}
	offline := trust
	offline.BrokerSocket = ""
	if err := offline.Validate(); err != nil {
		t.Fatalf("offline recipient registration without a broker socket rejected: %v", err)
	}
	trust.FIGatewaySocket = "relative.sock"
	if err := trust.Validate(); err == nil {
		t.Fatal("accepted a non-absolute gateway socket pin")
	}
	trust.FIGatewaySocket = filepath.Join(root, "fi-gateway-credentials.sock")
	trust.Target.App = "opencode"
	if err := trust.Validate(); err == nil {
		t.Fatal("accepted a gateway peer UID pin for a different application")
	}
}
