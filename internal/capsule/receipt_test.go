package capsule

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReceiptSigningKeyProvisioningIsSeparateAndPrivate(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	privatePath, publicPath := filepath.Join(root, "receipt.seed"), filepath.Join(root, "receipt.pub")
	public, err := GenerateReceiptKeys(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := LoadReceiptPrivate(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("loaded recipient receipt key does not match the registered public key")
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("receipt private key mode=%#o", info.Mode().Perm())
	}
	for i := range private {
		private[i] = 0
	}
}

func TestRecipientReceiptBindsCapsuleAndRejectsCourierTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	receipt, err := SignReceipt(Receipt{
		ReceiptKeyID: "recipient-receipt-r1", OperationID: "op-1", HandoffID: "handoff-1",
		DestinationID: "gateway-staging", DestinationRevision: 4,
		CapsuleDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CapsuleBytes:  321, State: "applied", IssuedAt: issued,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := VerifyReceipt(receipt, "recipient-receipt-r1", public)
	if err != nil || parsed.OperationID != "op-1" || parsed.CapsuleBytes != 321 {
		t.Fatalf("valid recipient receipt rejected: %#v %v", parsed, err)
	}
	parsed.State = "rejected"
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(tampered, "recipient-receipt-r1", public); err == nil {
		t.Fatal("courier modified the signed outcome")
	}
	if _, err := VerifyReceipt(receipt, "another-recipient-key", public); err == nil {
		t.Fatal("receipt key substitution was accepted")
	}
	if _, err := VerifyReceipt(receipt, "recipient-receipt-r1", ed25519.PublicKey(make([]byte, 32))); err == nil {
		t.Fatal("receipt verified with an untrusted key")
	}
}

func TestRecipientReceiptRejectsUnknownStateAndExpiredShape(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := SignReceipt(Receipt{
		ReceiptKeyID: "recipient-receipt-r1", OperationID: "op-1", HandoffID: "handoff-1",
		DestinationID: "gateway-staging", DestinationRevision: 1,
		CapsuleDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CapsuleBytes:  100, State: "applied", IssuedAt: time.Now().UTC(),
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	var parsed Receipt
	if err := json.Unmarshal(r, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.State = "completed"
	invalid, _ := json.Marshal(parsed)
	if _, err := VerifyReceipt(invalid, "recipient-receipt-r1", public); err == nil {
		t.Fatal("unknown receipt outcome was accepted")
	}
	parsed.State = "applied"
	parsed.IssuedAt = time.Now().Add(2 * time.Minute)
	future, _ := json.Marshal(parsed)
	if _, err := ParseReceipt(future); err == nil {
		t.Fatal("receipt timestamp too far in the future was accepted")
	}
}
