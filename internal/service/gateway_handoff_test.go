package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/apptarget"
	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

func TestSealedHandoffAppliesGatewayCredentialAndRequiresSignedReceipt(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("local gateway credential receiver uses a Unix-domain socket")
	}
	const credential = "synthetic-gateway-handoff-key"
	svc := testService(t)
	if err := svc.AddSecretRef(&types.SecretReference{ID: "gateway-handoff-ref", Name: "gateway", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("gateway-handoff-ref", []byte(credential)); err != nil {
		t.Fatal(err)
	}

	root := publicTempDir(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	recipientPrivatePath := filepath.Join(root, "recipient.hpke")
	recipientPublic, err := capsule.GenerateRecipientKeys(recipientPrivatePath, filepath.Join(root, "recipient.pub"))
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivatePath := filepath.Join(root, "recipient.receipt")
	receiptPublic, err := capsule.GenerateReceiptKeys(receiptPrivatePath, filepath.Join(root, "receipt.pub"))
	if err != nil {
		t.Fatal(err)
	}
	issuerPrivatePath := filepath.Join(root, "issuer.seed")
	if _, err := capsule.GenerateIssuerKeys(issuerPrivatePath, filepath.Join(root, "issuer.pub")); err != nil {
		t.Fatal(err)
	}
	issuerPrivate, err := capsule.LoadIssuerPrivate(issuerPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuerPrivate)
	svc.cfg.HandoffSigningKeyID = "gateway-issuer-r1"
	svc.cfg.HandoffSigningKey = issuerPrivate

	uid := uint32(os.Geteuid())
	target := &types.AppCredentialTarget{
		ID: "fi-gateway:openrouter:primary:api_key", App: "fi-gateway", Provider: "openrouter",
		Account: "primary", Slot: "api_key", UpdateMethod: apptarget.FIGatewayCredentialManagerV1,
		SourceRef: "gateway-handoff-ref", SourceRevision: 2,
	}
	issuerPublic := ed25519.PrivateKey(issuerPrivate).Public().(ed25519.PublicKey)
	destination := &types.Destination{
		ID: "local-gateway-primary", Name: "local gateway", Type: "sealed-capsule", ExpectedUID: &uid,
		HandoffMode: types.HandoffSealedCapsule, RecipientKeyID: "gateway-recipient-r1", RecipientPublicKey: recipientPublic,
		ReceiptKeyID: "gateway-receipt-r1", ReceiptPublicKey: receiptPublic,
		IssuerKeyID: svc.cfg.HandoffSigningKeyID, IssuerPublicKey: issuerPublic, CredentialTarget: target,
	}
	if err := svc.AddDestination(destination); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "gateway-handoff-ref", "transfer", destination.ID)
	operationID, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "gateway-handoff-ref", DestinationID: destination.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(operationID, "operator", -1); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueHandoff(context.Background(), "uid:1000", operationID)
	if err != nil {
		t.Fatal(err)
	}
	handoffCapsule, ok := issued.(*types.HandoffCapsule)
	if !ok {
		t.Fatalf("expected sealed capsule, got %T", issued)
	}
	envelope, err := capsule.Parse(handoffCapsule.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := capsule.LoadRecipientPrivate(recipientPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := capsule.Open(envelope, capsule.Expect{
		RecipientKeyID: destination.RecipientKeyID, SigningKeyID: destination.IssuerKeyID,
		HandoffID: handoffCapsule.HandoffID, OperationID: operationID,
		DestinationID: destination.ID, DestinationRevision: destination.Revision,
		TargetID: target.ID, App: target.App, Provider: target.Provider, Account: target.Account,
		Slot: target.Slot, UpdateMethod: target.UpdateMethod,
		SourceRef: target.SourceRef, SourceRevision: target.SourceRevision,
	}, issuerPublic, recipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened.Credential)

	socketPath := filepath.Join(root, "gateway-credentials.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix-domain socket unavailable: %v", err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	go func() {
		for i, operation := range []string{"apply", "reconcile"} {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			var request struct {
				Operation   string `json:"op"`
				OperationID string `json:"operation_id"`
				TargetID    string `json:"target_id"`
				Provider    string `json:"provider"`
				Account     string `json:"account"`
				Credential  string `json:"credential"`
			}
			decodeErr := json.NewDecoder(bufio.NewReader(connection)).Decode(&request)
			if decodeErr == nil && (request.Operation != operation || request.OperationID != handoffCapsule.HandoffID ||
				request.TargetID != target.ID || request.Provider != target.Provider ||
				request.Account != target.Account || request.Credential != credential) {
				decodeErr = os.ErrInvalid
			}
			response := `{"ok":true,"applied":true,"credential_id":"synthetic-id","provider":"openrouter","account":"primary","version":1}`
			if i == 1 {
				response = `{"ok":true,"applied":true,"provider":"openrouter","account":"primary","credential_id":"synthetic-id","version":1}`
			}
			if decodeErr == nil {
				_, decodeErr = connection.Write([]byte(response + "\n"))
			}
			_ = connection.Close()
			if decodeErr != nil {
				serverErr <- decodeErr
				return
			}
		}
		serverErr <- nil
	}()

	adapter, err := apptarget.NewRecipientAdapter(*target, t.TempDir(), apptarget.RecipientOptions{FIGatewaySocket: socketPath})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(root, "recipient-journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := transfer.NewApplicationConsumer(journal, &apptarget.TransferCommitter{Target: *target, Adapter: adapter})
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := consumer.Accept(context.Background(), transfer.Delivery{
		OperationID: handoffCapsule.HandoffID, DataKind: "api_key", Payload: opened.Credential, Target: target,
	})
	if err != nil || acceptance.State != transfer.StateApplied {
		t.Fatalf("gateway did not confirm applied credential: acceptance=%+v err=%v", acceptance, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("gateway credential receiver rejected transfer: %v", err)
	}

	receiptPrivate, err := capsule.LoadReceiptPrivate(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := capsule.SignReceipt(capsule.Receipt{
		ReceiptKeyID: destination.ReceiptKeyID, OperationID: operationID,
		HandoffID: handoffCapsule.HandoffID, DestinationID: destination.ID,
		DestinationRevision: destination.Revision, CapsuleDigest: transfer.DigestPayload(string(handoffCapsule.Envelope)),
		CapsuleBytes: len(handoffCapsule.Envelope), State: "applied", IssuedAt: time.Now().UTC(),
	}, receiptPrivate)
	clear(receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteSealedHandoffReceipt(receipt); err != nil {
		t.Fatalf("signed gateway receipt did not complete the transfer: %v", err)
	}
	completed, err := svc.DB().GetTransfer(operationID)
	if err != nil || completed.Status != types.StatusCompleted {
		t.Fatalf("gateway transfer was not completed from its signed receipt: status=%q err=%v", completed.Status, err)
	}
}

func TestRecipientPullTicketAppliesGatewayCredentialWithoutReturningItToCourier(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("local gateway credential receiver uses a Unix-domain socket")
	}
	const credential = "synthetic-gateway-ticket-key"
	svc := testService(t)
	if err := svc.AddSecretRef(&types.SecretReference{ID: "gateway-ticket-ref", Name: "gateway ticket", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("gateway-ticket-ref", []byte(credential)); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	target := &types.AppCredentialTarget{
		ID: "fi-gateway:openrouter:staging:api_key", App: "fi-gateway", Provider: "openrouter",
		Account: "staging", Slot: "api_key", UpdateMethod: apptarget.FIGatewayCredentialManagerV1,
		SourceRef: "gateway-ticket-ref", SourceRevision: 1,
	}
	destination := &types.Destination{
		ID: "gateway-ticket-destination", Name: "local gateway", Type: "recipient-socket",
		Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid,
		HandoffMode: types.HandoffRecipientPull, CredentialTarget: target,
	}
	if err := svc.AddDestination(destination); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "gateway-ticket-ref", "transfer", destination.ID)
	operationID, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "gateway-ticket-ref", DestinationID: destination.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(operationID, "operator", -1); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueHandoff(context.Background(), "uid:1000", operationID)
	if err != nil {
		t.Fatal(err)
	}
	ticket, ok := issued.(*types.HandoffTicket)
	if !ok || ticket.TicketID == "" || ticket.Nonce == "" {
		t.Fatalf("expected opaque recipient-pull ticket, got %#v", issued)
	}
	ticketJSON, err := json.Marshal(ticket)
	if err != nil || bytes.Contains(ticketJSON, []byte(credential)) {
		t.Fatal("agent-visible recipient ticket contains credential material")
	}
	delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(delivery.Payload)

	socketPath := os.Getenv("SEQPASS_GATEWAY_INTEGRATION_SOCKET")
	var serverErr chan error
	if socketPath == "" {
		socketPath = filepath.Join(root, "gateway-ticket-credentials.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Skipf("local gateway credential receiver uses a Unix-domain socket: %v", err)
		}
		defer listener.Close()
		if err := os.Chmod(socketPath, 0600); err != nil {
			t.Fatal(err)
		}
		serverErr = make(chan error, 1)
		go func() {
			for _, operation := range []string{"apply", "reconcile"} {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					serverErr <- acceptErr
					return
				}
				var request struct {
					Operation   string `json:"op"`
					OperationID string `json:"operation_id"`
					TargetID    string `json:"target_id"`
					Provider    string `json:"provider"`
					Account     string `json:"account"`
					Credential  string `json:"credential"`
				}
				decodeErr := json.NewDecoder(bufio.NewReader(connection)).Decode(&request)
				if decodeErr == nil && (request.Operation != operation || request.OperationID != operationID ||
					request.TargetID != target.ID || request.Provider != target.Provider || request.Account != target.Account || request.Credential != credential) {
					decodeErr = os.ErrInvalid
				}
				response := `{"ok":true,"applied":true,"credential_id":"synthetic-id","provider":"openrouter","account":"staging","version":1}`
				if decodeErr == nil {
					_, decodeErr = connection.Write([]byte(response + "\n"))
				}
				_ = connection.Close()
				if decodeErr != nil {
					serverErr <- decodeErr
					return
				}
			}
			serverErr <- nil
		}()
	}

	adapter, err := apptarget.NewRecipientAdapter(*target, t.TempDir(), apptarget.RecipientOptions{FIGatewaySocket: socketPath})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(root, "ticket-recipient-journal"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := transfer.NewApplicationConsumer(journal, &apptarget.TransferCommitter{Target: *target, Adapter: adapter})
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := consumer.Accept(context.Background(), transfer.Delivery{
		OperationID: delivery.OperationID, DataKind: "api_key", Payload: delivery.Payload, Target: &delivery.Target,
	})
	if err != nil || acceptance.State != transfer.StateApplied {
		t.Fatalf("gateway did not confirm ticket-delivered credential: acceptance=%+v err=%v", acceptance, err)
	}
	if serverErr != nil {
		if err := <-serverErr; err != nil {
			t.Fatalf("gateway credential receiver rejected ticket transfer: %v", err)
		}
	}
	if err := svc.CompleteHandoff(uid, operationID, delivery.PayloadDigest, "applied", len(delivery.Payload)); err != nil {
		t.Fatalf("recipient completion was not accepted: %v", err)
	}
	completed, err := svc.DB().GetTransfer(operationID)
	if err != nil || completed.Status != types.StatusCompleted {
		t.Fatalf("ticket transfer was not completed: status=%q err=%v", completed.Status, err)
	}
}
