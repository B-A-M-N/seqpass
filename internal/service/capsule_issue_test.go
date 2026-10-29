package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

func TestSealedCapsuleIssueIsOpaqueAndLeavesOperationUncertain(t *testing.T) {
	svc := testService(t)
	const secret = "SEALED-HANDOFF-SECRET-9173"
	if err := svc.AddSecretRef(&types.SecretReference{ID: "capsule-ref", Name: "capsule", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("capsule-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(root, "recipient.json")
	pubPath := filepath.Join(root, "recipient.pub")
	pub, err := capsule.GenerateRecipientKeys(privPath, pubPath)
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivPath := filepath.Join(root, "recipient-receipt.seed")
	receiptPubPath := filepath.Join(root, "recipient-receipt.pub")
	receiptPub, err := capsule.GenerateReceiptKeys(receiptPrivPath, receiptPubPath)
	if err != nil {
		t.Fatal(err)
	}
	issuerSeedPath := filepath.Join(root, "issuer.seed")
	issuerPubPath := filepath.Join(root, "issuer.pub")
	if _, err := capsule.GenerateIssuerKeys(issuerSeedPath, issuerPubPath); err != nil {
		t.Fatal(err)
	}
	issuer, err := capsule.LoadIssuerPrivate(issuerSeedPath)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.HandoffSigningKeyID = "issuer-test-v1"
	svc.cfg.HandoffSigningKey = issuer
	uid := uint32(os.Geteuid())
	target := &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "capsule-ref", SourceRevision: 4}
	dest := &types.Destination{ID: "capsule-dest", Name: "capsule", Type: "sealed-capsule", ExpectedUID: &uid, HandoffMode: types.HandoffSealedCapsule, RecipientKeyID: "recipient-test-v1", RecipientPublicKey: pub, ReceiptKeyID: "recipient-receipt-v1", ReceiptPublicKey: receiptPub, IssuerKeyID: "issuer-test-v1", IssuerPublicKey: issuer.Public().(ed25519.PublicKey), CredentialTarget: target}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "capsule-ref", "transfer", "capsule-dest")
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "capsule-ref", DestinationID: "capsule-dest"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	handoff, err := svc.IssueHandoff(context.Background(), "uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	caps, ok := handoff.(*types.HandoffCapsule)
	if !ok || caps.HandoffID == "" || caps.OperationID != op || len(caps.Envelope) == 0 {
		t.Fatalf("invalid capsule response: %#v", handoff)
	}
	if _, err := svc.RetrieveHandoffCapsule("uid:other", op); err == nil {
		t.Fatal("non-requesting principal retrieved the sealed capsule")
	}
	retrieved, err := svc.RetrieveHandoffCapsule("uid:1000", op)
	if err != nil || string(retrieved.Envelope) != string(caps.Envelope) {
		t.Fatalf("capsule retrieval was not byte-identical: err=%v", err)
	}
	stored, err := svc.DB().GetDispatch(op)
	if err != nil || string(stored.CapsuleBytes) != string(caps.Envelope) {
		t.Fatalf("dispatch did not retain the exact encrypted capsule: err=%v", err)
	}
	if err := svc.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := metadata.NewDB(svc.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	svc.db = reopened
	retrieved, err = svc.RetrieveHandoffCapsule("uid:1000", op)
	if err != nil || string(retrieved.Envelope) != string(caps.Envelope) {
		t.Fatalf("restart retrieval did not return original ciphertext: err=%v", err)
	}
	policies, err := svc.DB().ListPolicies()
	if err != nil || len(policies) != 1 {
		t.Fatalf("list capsule authorization policy: count=%d err=%v", len(policies), err)
	}
	if err := svc.DB().SetPolicyEnabled(policies[0].ID, false); err != nil {
		t.Fatalf("revoke capsule authorization: %v", err)
	}
	if _, err := svc.RetrieveHandoffCapsule("uid:1000", op); err == nil {
		t.Fatal("revoked requester retrieved a persisted capsule")
	}
	raw, _ := json.Marshal(caps)
	if strings.Contains(string(raw), secret) {
		t.Fatal("agent-visible capsule response contains plaintext credential")
	}
	env, err := capsule.Parse(caps.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := capsule.LoadRecipientPrivate(privPath)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic := issuer.Public().(ed25519.PublicKey)
	opened, err := capsule.Open(env, capsule.Expect{
		RecipientKeyID: "recipient-test-v1", SigningKeyID: "issuer-test-v1", HandoffID: caps.HandoffID,
		OperationID: op, DestinationID: dest.ID, DestinationRevision: dest.Revision,
		TargetID: target.ID, App: target.App, Account: target.Account, Slot: target.Slot, UpdateMethod: target.UpdateMethod,
		SourceRef: target.SourceRef, SourceRevision: target.SourceRevision,
	}, issuerPublic, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened.Credential) != secret {
		t.Fatal("recipient did not decrypt the approved credential")
	}
	for i := range opened.Credential {
		opened.Credential[i] = 0
	}
	tr, err := svc.DB().GetTransfer(op)
	if err != nil || tr.Status != types.StatusUncertain {
		t.Fatalf("capsule issuance must remain uncertain pending receipt: %#v %v", tr, err)
	}
	capsuleDigest := transfer.DigestPayload(string(caps.Envelope))
	if err := svc.CompleteHandoff(uid, op, capsuleDigest, "applied", len(caps.Envelope)); err == nil {
		t.Fatal("sealed receipt without handoff ID accepted")
	}
	if err := svc.CompleteSealedHandoff(uid, "wrong-handoff", op, capsuleDigest, "applied", len(caps.Envelope)); err == nil {
		t.Fatal("receipt for a substituted handoff ID accepted")
	}
	receiptPrivate, err := capsule.LoadReceiptPrivate(receiptPrivPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := capsule.SignReceipt(capsule.Receipt{
		ReceiptKeyID: dest.ReceiptKeyID, OperationID: op, HandoffID: caps.HandoffID,
		DestinationID: dest.ID, DestinationRevision: dest.Revision,
		CapsuleDigest: capsuleDigest, CapsuleBytes: len(caps.Envelope),
		State: "applied", IssuedAt: time.Now().UTC(),
	}, receiptPrivate)
	for i := range receiptPrivate {
		receiptPrivate[i] = 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var tampered capsule.Receipt
	if err := json.Unmarshal(receipt, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Signature[0] ^= 0x80
	tamperedReceipt, _ := json.Marshal(tampered)
	if err := svc.CompleteSealedHandoffReceipt(tamperedReceipt); err == nil {
		t.Fatal("agent-modified receipt signature was accepted")
	}
	if err := svc.CompleteSealedHandoffReceipt(receipt); err != nil {
		t.Fatalf("recipient-signed receipt was not accepted: %v", err)
	}
	tr, err = svc.DB().GetTransfer(op)
	if err != nil || tr.Status != types.StatusCompleted {
		t.Fatalf("recipient receipt did not complete operation: %#v %v", tr, err)
	}
	rotatedTarget := *dest.CredentialTarget
	rotatedReceiptPub := make([]byte, ed25519.PublicKeySize)
	rotatedReceiptPub[0] = 1
	if err := svc.DB().UpdateDestinationHandoffIdentity(dest.ID, types.HandoffSealedCapsule,
		dest.RecipientKeyID, dest.RecipientPublicKey, "recipient-receipt-v2", rotatedReceiptPub,
		dest.IssuerKeyID, dest.IssuerPublicKey, nil, nil, &rotatedTarget, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteSealedHandoffReceipt(receipt); err == nil {
		t.Fatal("receipt signed by the retired recipient key was accepted after rotation")
	}
}
