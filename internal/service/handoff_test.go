package service

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

func readHandoffTicketState(t *testing.T, dbPath, operationID string) string {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var state string
	if err := db.QueryRow(`SELECT state FROM handoff_tickets WHERE operation_id=?`, operationID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

const handoffCrashHelperEnv = "SEQPASS_HANDOFF_CRASH_HELPER"

// TestSeqPassHandoffCrashHelper runs in a child test process that the parent
// kills at a durable recovery boundary. It intentionally does not defer Close.
func TestSeqPassHandoffCrashHelper(t *testing.T) {
	if os.Getenv(handoffCrashHelperEnv) != "1" {
		return
	}
	dbPath := os.Getenv("SEQPASS_HANDOFF_CRASH_DB")
	stage := os.Getenv("SEQPASS_HANDOFF_CRASH_STAGE")
	ticketID := os.Getenv("SEQPASS_HANDOFF_CRASH_TICKET")
	nonce := os.Getenv("SEQPASS_HANDOFF_CRASH_NONCE")
	opID := os.Getenv("SEQPASS_HANDOFF_CRASH_OP")
	secret := os.Getenv("SEQPASS_HANDOFF_CRASH_SECRET")
	uid := uint32(0)
	needsTicket := stage == "claim" || stage == "after-source-resolution" || stage == "pre-dispatch" || stage == "after-dispatch"
	needsSecret := stage == "claim" || stage == "after-source-resolution" || stage == "pre-dispatch" || stage == "capsule-issued" || stage == "after-dispatch"
	validStage := needsTicket || stage == "capsule-issued" || stage == "capsule-retrieve" || stage == "capsule-complete" || stage == "ticket-recovery"
	if !validStage || dbPath == "" || opID == "" || (needsSecret && secret == "") || (needsTicket && (ticketID == "" || nonce == "")) {
		t.Fatal("crash helper configuration missing")
	}
	if needsTicket {
		uid64, err := strconv.ParseUint(os.Getenv("SEQPASS_HANDOFF_CRASH_UID"), 10, 32)
		if err != nil {
			t.Fatal("crash helper recipient UID missing")
		}
		uid = uint32(uid64)
	}
	config := Config{DBPath: dbPath, VaultType: "memory-test"}
	if stage == "capsule-issued" {
		seedPath := os.Getenv("SEQPASS_HANDOFF_CRASH_ISSUER_SEED")
		issuerKey, err := capsule.LoadIssuerPrivate(seedPath)
		if err != nil {
			t.Fatal(err)
		}
		config.HandoffSigningKeyID = "crash-matrix-issuer-v1"
		config.HandoffSigningKey = issuerKey
	}
	svc, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if needsSecret {
		if err := svc.vault.Store("crash-matrix-ref", []byte(secret)); err != nil {
			t.Fatal(err)
		}
	}
	switch stage {
	case "claim":
		if _, err := svc.DB().ClaimHandoffTicket(ticketID, nonce, uid, time.Now()); err != nil {
			t.Fatal(err)
		}
	case "after-source-resolution", "pre-dispatch":
		if _, err := svc.DB().ClaimHandoffTicket(ticketID, nonce, uid, time.Now()); err != nil {
			t.Fatal(err)
		}
		tr, err := svc.DB().GetTransfer(opID)
		if err != nil || tr == nil {
			t.Fatalf("transfer lookup failed: %v", err)
		}
		_, attemptID, err := svc.admitTransferMode(tr, "recipient", true)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := svc.resolveCredentialMaterial(context.Background(), tr.Source, types.OperationTransfer, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		zeroCredential(&cred)
		if stage == "pre-dispatch" {
			if err := svc.DB().BeginDispatch("transfer", tr.ID, attemptID, tr.OpHash, tr.DestDigest, "recipient", time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	case "capsule-issued":
		issued, err := svc.IssueHandoff(context.Background(), "uid:1000", opID)
		if err != nil {
			t.Fatal(err)
		}
		sealed, ok := issued.(*types.HandoffCapsule)
		if !ok {
			t.Fatalf("expected sealed capsule, got %T", issued)
		}
		env, err := capsule.Parse(sealed.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("READY %s %d %s %d\n", transfer.DigestPayload(string(sealed.Envelope)), len(sealed.Envelope), env.HandoffID, env.ExpiresAt.UnixNano())
		select {}
	case "capsule-retrieve":
		retrieved, err := svc.RetrieveHandoffCapsule("uid:1000", opID)
		if err != nil {
			t.Fatal(err)
		}
		env, err := capsule.Parse(retrieved.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("READY %s %d %s %d\n", transfer.DigestPayload(string(retrieved.Envelope)), len(retrieved.Envelope), env.HandoffID, env.ExpiresAt.UnixNano())
		return
	case "capsule-complete":
		receiptPath := os.Getenv("SEQPASS_HANDOFF_CRASH_RECEIPT")
		receipt, err := os.ReadFile(receiptPath)
		if err != nil || len(receipt) == 0 {
			t.Fatal("signed receipt unavailable")
		}
		if err := svc.CompleteSealedHandoffReceipt(receipt); err != nil {
			t.Fatalf("post-restart receipt reconciliation failed: %v", err)
		}
		fmt.Println("READY completed")
		return
	case "ticket-recovery":
		tr, err := svc.DB().GetTransfer(opID)
		if err != nil || tr == nil {
			t.Fatalf("recovered transfer lookup failed: %v", err)
		}
		state := readHandoffTicketState(t, dbPath, opID)
		fmt.Printf("READY %s %s\n", tr.Status, state)
		return
	case "after-dispatch":
		delivery, err := svc.RedeemHandoffTicket(context.Background(), ticketID, nonce, uid)
		if err != nil || delivery == nil {
			t.Fatalf("ticket dispatch failed: %v", err)
		}
		fmt.Printf("READY %s %d\n", delivery.PayloadDigest, len(delivery.Payload))
		for i := range delivery.Payload {
			delivery.Payload[i] = 0
		}
		select {}
	default:
		t.Fatalf("unknown crash stage %q", stage)
	}
	fmt.Printf("READY %s\n", stage)
	select {}
}

func TestRecipientPullCrashRecoveryMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix recipient identity and process kill semantics")
	}
	for _, stage := range []string{"claim", "after-source-resolution", "pre-dispatch", "after-dispatch"} {
		t.Run(stage, func(t *testing.T) {
			const secret = "SYNTHETIC-CRASH-MATRIX-CREDENTIAL"
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "broker.db")
			svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.AddSecretRef(&types.SecretReference{ID: "crash-matrix-ref", Name: "crash-matrix", Owner: "test"}); err != nil {
				t.Fatal(err)
			}
			if err := svc.vault.Store("crash-matrix-ref", []byte(secret)); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid())
			dest := &types.Destination{
				ID: "crash-matrix-dest", Name: "crash matrix", Type: "recipient-socket",
				Endpoint: filepath.Join(dir, "recipient.sock"), ExpectedUID: &uid,
				HandoffMode: types.HandoffRecipientPull,
				CredentialTarget: &types.AppCredentialTarget{
					ID: "opencode:crash-matrix:api_key", App: "opencode", Account: "crash-matrix", Slot: "api_key",
					UpdateMethod: "opencode-auth-json-v1", SourceRef: "crash-matrix-ref", SourceRevision: 1,
				},
			}
			if err := svc.AddDestination(dest); err != nil {
				t.Fatal(err)
			}
			allowPolicy(t, svc, "uid:1000", "crash-matrix-ref", "transfer", dest.ID)
			opID, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "crash-matrix-ref", DestinationID: dest.ID})
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.ApproveTransfer(opID, "operator", -1); err != nil {
				t.Fatal(err)
			}
			ticket, err := svc.IssueHandoffTicket("uid:1000", opID)
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.Close(); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestSeqPassHandoffCrashHelper$")
			cmd.Env = append(os.Environ(),
				handoffCrashHelperEnv+"=1",
				"SEQPASS_HANDOFF_CRASH_DB="+dbPath,
				"SEQPASS_HANDOFF_CRASH_STAGE="+stage,
				"SEQPASS_HANDOFF_CRASH_TICKET="+ticket.TicketID,
				"SEQPASS_HANDOFF_CRASH_NONCE="+ticket.Nonce,
				"SEQPASS_HANDOFF_CRASH_OP="+opID,
				"SEQPASS_HANDOFF_CRASH_UID="+strconv.FormatUint(uint64(uid), 10),
				"SEQPASS_HANDOFF_CRASH_SECRET="+secret,
			)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(stdout)
			ready := false
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "READY ") {
					ready = true
					break
				}
			}
			if !ready {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("child did not reach crash point: %v", scanner.Err())
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("child unexpectedly exited without process kill")
			}
			recoveryCmd := exec.Command(os.Args[0], "-test.run=^TestSeqPassHandoffCrashHelper$")
			recoveryCmd.Env = append(os.Environ(),
				handoffCrashHelperEnv+"=1",
				"SEQPASS_HANDOFF_CRASH_DB="+dbPath,
				"SEQPASS_HANDOFF_CRASH_STAGE=ticket-recovery",
				"SEQPASS_HANDOFF_CRASH_TICKET="+ticket.TicketID,
				"SEQPASS_HANDOFF_CRASH_OP="+opID,
			)
			recoveryOutput, err := recoveryCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("new-process ticket recovery failed: %v: %s", err, recoveryOutput)
			}
			var processStatus, processTicketState string
			for _, line := range strings.Split(string(recoveryOutput), "\n") {
				if _, scanErr := fmt.Sscanf(line, "READY %s %s", &processStatus, &processTicketState); scanErr == nil {
					break
				}
			}
			wantStatus, wantTicketState := types.StatusAuthorized, "issued"
			if stage == "after-dispatch" {
				wantStatus, wantTicketState = types.StatusUncertain, "uncertain"
			}
			if processStatus != wantStatus || processTicketState != wantTicketState {
				t.Fatalf("fresh-process startup recovered status=%q ticket=%q, want %q/%q; output=%s", processStatus, processTicketState, wantStatus, wantTicketState, recoveryOutput)
			}

			svc, err = New(Config{DBPath: dbPath, VaultType: "memory-test"})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Close()
			tr, err := svc.DB().GetTransfer(opID)
			if err != nil || tr == nil {
				t.Fatalf("recovered transfer lookup failed: %v", err)
			}
			state := readHandoffTicketState(t, dbPath, opID)
			switch stage {
			case "claim", "after-source-resolution", "pre-dispatch":
				if tr.Status != types.StatusAuthorized || state != "issued" {
					t.Fatalf("pre-release crash recovery status=%q ticket=%q, want authorized/issued", tr.Status, state)
				}
				if err := svc.vault.Store("crash-matrix-ref", []byte(secret)); err != nil {
					t.Fatal(err)
				}
				delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
				if err != nil || delivery == nil || string(delivery.Payload) != secret {
					t.Fatalf("pre-release ticket was not safely retryable: delivery=%v err=%v", delivery != nil, err)
				}
				for i := range delivery.Payload {
					delivery.Payload[i] = 0
				}
			case "after-dispatch":
				if tr.Status != types.StatusUncertain || state != "uncertain" {
					t.Fatalf("post-release crash recovery status=%q ticket=%q, want uncertain/uncertain", tr.Status, state)
				}
				if _, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid); err == nil {
					t.Fatal("dispatched ticket replay was accepted after restart")
				}
			}
		})
	}
}

func TestSealedCapsuleLostResponseSurvivesIssuerKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires process-kill semantics")
	}
	const secret = "SYNTHETIC-SEALED-CAPSULE-RESPONSE-LOST"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "broker.db")
	paths := map[string]string{
		"recipient-private": filepath.Join(dir, "recipient.json"),
		"recipient-public":  filepath.Join(dir, "recipient.pub"),
		"receipt-private":   filepath.Join(dir, "receipt.seed"),
		"receipt-public":    filepath.Join(dir, "receipt.pub"),
		"issuer-private":    filepath.Join(dir, "issuer.seed"),
		"issuer-public":     filepath.Join(dir, "issuer.pub"),
	}
	recipientPublic, err := capsule.GenerateRecipientKeys(paths["recipient-private"], paths["recipient-public"])
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, err := capsule.GenerateReceiptKeys(paths["receipt-private"], paths["receipt-public"])
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, err := capsule.GenerateIssuerKeys(paths["issuer-private"], paths["issuer-public"])
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddSecretRef(&types.SecretReference{ID: "crash-matrix-ref", Name: "crash-matrix", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("crash-matrix-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	target := &types.AppCredentialTarget{
		ID: "opencode:crash-capsule:api_key", App: "opencode", Account: "crash-capsule", Slot: "api_key",
		UpdateMethod: "opencode-auth-json-v1", SourceRef: "crash-matrix-ref", SourceRevision: 1,
	}
	dest := &types.Destination{
		ID: "crash-capsule-dest", Name: "crash capsule", Type: "sealed-capsule", ExpectedUID: &uid,
		HandoffMode:    types.HandoffSealedCapsule,
		RecipientKeyID: "crash-recipient-v1", RecipientPublicKey: recipientPublic,
		ReceiptKeyID: "crash-receipt-v1", ReceiptPublicKey: receiptPublic,
		IssuerKeyID: "crash-matrix-issuer-v1", IssuerPublicKey: ed25519.PublicKey(issuerPublic),
		CredentialTarget: target,
	}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "crash-matrix-ref", "transfer", dest.ID)
	opID, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "crash-matrix-ref", DestinationID: dest.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(opID, "operator", -1); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSeqPassHandoffCrashHelper$")
	cmd.Env = append(os.Environ(),
		handoffCrashHelperEnv+"=1",
		"SEQPASS_HANDOFF_CRASH_DB="+dbPath,
		"SEQPASS_HANDOFF_CRASH_STAGE=capsule-issued",
		"SEQPASS_HANDOFF_CRASH_OP="+opID,
		"SEQPASS_HANDOFF_CRASH_UID="+strconv.FormatUint(uint64(uid), 10),
		"SEQPASS_HANDOFF_CRASH_SECRET="+secret,
		"SEQPASS_HANDOFF_CRASH_ISSUER_SEED="+paths["issuer-private"],
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	var expectedDigest, expectedHandoffID string
	var expectedBytes int
	var expectedExpiry int64
	for scanner.Scan() {
		if _, err := fmt.Sscanf(scanner.Text(), "READY %s %d %s %d", &expectedDigest, &expectedBytes, &expectedHandoffID, &expectedExpiry); err == nil && expectedDigest != "" {
			break
		}
	}
	if expectedDigest == "" || expectedBytes <= 0 || expectedHandoffID == "" || expectedExpiry <= 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("issuer did not reach post-persistence response boundary: %v", scanner.Err())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("issuer unexpectedly exited without process kill")
	}
	// A fresh OS process performs service startup recovery and retrieves the
	// persisted package. This proves the restart path beyond reopening a DB in
	// the issuing test process.
	recoveryCmd := exec.Command(os.Args[0], "-test.run=^TestSeqPassHandoffCrashHelper$")
	recoveryCmd.Env = append(os.Environ(),
		handoffCrashHelperEnv+"=1",
		"SEQPASS_HANDOFF_CRASH_DB="+dbPath,
		"SEQPASS_HANDOFF_CRASH_STAGE=capsule-retrieve",
		"SEQPASS_HANDOFF_CRASH_OP="+opID,
	)
	recoveryOutput, err := recoveryCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh-process capsule retrieval failed: %v: %s", err, recoveryOutput)
	}
	var recoveredDigest, handoffID string
	var recoveredBytes int
	var recoveredExpiry int64
	for _, line := range strings.Split(string(recoveryOutput), "\n") {
		if _, scanErr := fmt.Sscanf(line, "READY %s %d %s %d", &recoveredDigest, &recoveredBytes, &handoffID, &recoveredExpiry); scanErr == nil && handoffID != "" {
			break
		}
	}
	if recoveredDigest != expectedDigest || recoveredBytes != expectedBytes || handoffID != expectedHandoffID || recoveredExpiry != expectedExpiry {
		t.Fatalf("new-process retrieval differs from lost IPC response: digest=%s bytes=%d handoff=%q expiry=%d output=%s", recoveredDigest, recoveredBytes, handoffID, recoveredExpiry, recoveryOutput)
	}

	// Simulate a recipient applying the capsule while the issuer response and
	// receipt acknowledgment are lost. Deliver its signed receipt to another
	// fresh issuer process and verify settlement without replay.
	receiptKey, err := capsule.LoadReceiptPrivate(paths["receipt-private"])
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := capsule.SignReceipt(capsule.Receipt{
		ReceiptKeyID: "crash-receipt-v1", OperationID: opID, HandoffID: handoffID,
		DestinationID: dest.ID, DestinationRevision: dest.Revision,
		CapsuleDigest: expectedDigest, CapsuleBytes: expectedBytes,
		State: "applied", IssuedAt: time.Now().UTC(),
	}, receiptKey)
	for i := range receiptKey {
		receiptKey[i] = 0
	}
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "lost-response-recovered-receipt.json")
	if err := os.WriteFile(receiptPath, receipt, 0600); err != nil {
		t.Fatal(err)
	}
	completionCmd := exec.Command(os.Args[0], "-test.run=^TestSeqPassHandoffCrashHelper$")
	completionCmd.Env = append(os.Environ(),
		handoffCrashHelperEnv+"=1",
		"SEQPASS_HANDOFF_CRASH_DB="+dbPath,
		"SEQPASS_HANDOFF_CRASH_STAGE=capsule-complete",
		"SEQPASS_HANDOFF_CRASH_OP="+opID,
		"SEQPASS_HANDOFF_CRASH_RECEIPT="+receiptPath,
	)
	completionOutput, err := completionCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(completionOutput), "READY completed") {
		t.Fatalf("fresh-process receipt reconciliation failed: %v: %s", err, completionOutput)
	}

	svc, err = New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	tr, err := svc.DB().GetTransfer(opID)
	if err != nil || tr == nil || tr.Status != types.StatusCompleted {
		t.Fatalf("lost-response operation state=%v err=%v, want completed after receipt", tr, err)
	}
	svc.ExpireStaleRequests()
	dispatch, err := svc.DB().GetDispatch(opID)
	if err != nil || dispatch == nil || len(dispatch.CapsuleBytes) != 0 || dispatch.PayloadDigest != expectedDigest || dispatch.PayloadBytes != expectedBytes {
		t.Fatalf("final settlement did not prune only cached ciphertext: dispatch=%#v err=%v", dispatch, err)
	}
}

func TestRecipientPullTicketIsBoundOneUseAndReceiptSafe(t *testing.T) {
	svc := testService(t)
	const secret = "HANDOFF-SECRET-MARKER-71c2"
	if err := svc.AddSecretRef(&types.SecretReference{ID: "pull-ref", Name: "pull", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("pull-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{ID: "pull-dest", Name: "pull", Type: "recipient-socket", Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid, HandoffMode: types.HandoffRecipientPull, CredentialTarget: &types.AppCredentialTarget{ID: "opencode:work:api_key", App: "opencode", Account: "work", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "pull-ref", SourceRevision: 1}}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "pull-ref", "transfer", "pull-dest")
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "pull-ref", DestinationID: "pull-dest"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	svc.runWorkerOnce(context.Background())
	stillReady, _ := svc.db.GetTransfer(op)
	if stillReady == nil || stillReady.Status != types.StatusAuthorized {
		t.Fatal("auto worker consumed a recipient-pull transfer")
	}
	if _, err := svc.IssueHandoffTicket("uid:999", op); err == nil {
		t.Fatal("non-owner issued ticket")
	}
	ticket, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ticket.TicketID, secret) || strings.Contains(ticket.Nonce, secret) {
		t.Fatal("ticket contains secret material")
	}
	if err := svc.DB().SetHandoffTicketState(op, "expired"); err != nil {
		t.Fatal(err)
	}
	renewed, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.TicketID == ticket.TicketID {
		t.Fatal("expired ticket was not replaced")
	}
	if _, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid); err == nil {
		t.Fatal("replaced ticket locator remained valid")
	}
	ticket = renewed
	if _, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid+1); err == nil {
		t.Fatal("wrong recipient UID redeemed ticket")
	}
	if _, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, "wrong", uid); err == nil {
		t.Fatal("wrong ticket nonce redeemed")
	}
	delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
	if err != nil {
		t.Fatal(err)
	}
	if string(delivery.Payload) != secret {
		t.Fatal("recipient did not receive the approved payload")
	}
	path := svc.cfg.DBPath
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	// Startup reconciliation must classify the durable dispatch as uncertain,
	// never reopen the ticket after credential bytes may have crossed IPC.
	// path after an ambiguous broker restart.
	svc, err = New(Config{DBPath: path, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	var ticketState string
	ticketState = readHandoffTicketState(t, svc.cfg.DBPath, op)
	if ticketState != "uncertain" {
		t.Fatalf("dispatched ticket state after restart=%q err=%v, want uncertain", ticketState, err)
	}
	if err := svc.CompleteHandoff(uid, op, delivery.PayloadDigest, "applied", len(delivery.Payload)-1); err == nil {
		t.Fatal("wrong byte count accepted")
	}
	if err := svc.CompleteHandoff(uid, op, delivery.PayloadDigest, "applied", len(delivery.Payload)); err != nil {
		t.Fatal(err)
	}
	if err := svc.CompleteHandoff(uid, op, delivery.PayloadDigest, "applied", len(delivery.Payload)); err != nil {
		t.Fatalf("lost-ACK retry was not idempotent: %v", err)
	}
	for i := range delivery.Payload {
		delivery.Payload[i] = 0
	}
	if _, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid); err == nil {
		t.Fatal("ticket replay succeeded")
	}
	tr, err := svc.db.GetTransfer(op)
	if err != nil || tr.Status != types.StatusCompleted {
		t.Fatalf("transfer status=%v err=%v", tr, err)
	}
	detail, err := svc.StatusDetail("uid:1000", "transfer", op)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(detail.Result)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), delivery.PayloadDigest) {
		t.Fatal("secret or payload digest leaked into receipt")
	}
}

func TestRecipientPullCrashAfterSourceResolutionBeforeRecordIsRetryable(t *testing.T) {
	svc := testService(t)
	const secret = "SYNTHETIC-CLAIM-CRASH-ONLY"
	if err := svc.AddSecretRef(&types.SecretReference{ID: "claim-crash-ref", Name: "claim-crash", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("claim-crash-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	root := publicTempDir(t)
	dest := &types.Destination{ID: "claim-crash-dest", Name: "claim crash", Type: "recipient-socket", Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid, HandoffMode: types.HandoffRecipientPull, CredentialTarget: &types.AppCredentialTarget{ID: "opencode:claim-crash:api_key", App: "opencode", Account: "claim-crash", Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "claim-crash-ref", SourceRevision: 1}}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "claim-crash-ref", "transfer", dest.ID)
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "claim-crash-ref", DestinationID: dest.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB().ClaimHandoffTicket(ticket.TicketID, ticket.Nonce, uid, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after source resolution and the dispatch barrier, but
	// before the durable dispatch record makes any response releasable.
	tr, err := svc.DB().GetTransfer(op)
	if err != nil || tr == nil {
		t.Fatalf("transfer lookup failed: %v", err)
	}
	dest, attemptID, err := svc.admitTransferMode(tr, "recipient", true)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.resolveCredentialMaterial(context.Background(), tr.Source, types.OperationTransfer, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	zeroCredential(&cred)
	if err := svc.DB().BeginDispatch("transfer", tr.ID, attemptID, tr.OpHash, tr.DestDigest, "recipient", time.Now()); err != nil {
		t.Fatal(err)
	}
	if dispatch, err := svc.DB().GetDispatch(op); err != nil || dispatch != nil {
		t.Fatalf("simulated pre-dispatch crash unexpectedly has dispatch: %#v %v", dispatch, err)
	}
	path := svc.cfg.DBPath
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc, err = New(Config{DBPath: path, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	var state string
	state = readHandoffTicketState(t, svc.cfg.DBPath, op)
	if state != "issued" {
		t.Fatalf("unreleased claim state after restart=%q, want issued", state)
	}
	if err := svc.vault.Store("claim-crash-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
	if err != nil || delivery == nil || string(delivery.Payload) != secret {
		t.Fatalf("safe retry after proven pre-dispatch crash failed: delivery=%v err=%v", delivery != nil, err)
	}
	for i := range delivery.Payload {
		delivery.Payload[i] = 0
	}
}

func TestRecipientPullRevocationBeforeRedemptionDoesNotDispatch(t *testing.T) {
	svc := testService(t)
	defer svc.Close()
	if err := svc.AddSecretRef(&types.SecretReference{ID: "revoked-ref", Name: "revoked", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("revoked-ref", []byte("SYNTHETIC-REVOKED-BEFORE-REDEEM")); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{
		ID: "revoked-pull-dest", Name: "revoked pull", Type: "recipient-socket",
		Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid,
		HandoffMode: types.HandoffRecipientPull,
		CredentialTarget: &types.AppCredentialTarget{
			ID: "opencode:openrouter:api_key", App: "opencode", Account: "openrouter", Slot: "api_key",
			UpdateMethod: "opencode-auth-json-v1", SourceRef: "revoked-ref", SourceRevision: 1,
		},
	}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "revoked-ref", "transfer", dest.ID)
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "revoked-ref", DestinationID: dest.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	policies, err := svc.DB().ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	var allowID string
	for _, policy := range policies {
		if policy.Name == "allow" {
			allowID = policy.ID
			break
		}
	}
	if allowID == "" {
		t.Fatal("allow policy not found")
	}
	if err := svc.DB().SetPolicyEnabled(allowID, false); err != nil {
		t.Fatal(err)
	}
	delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
	if err == nil || delivery != nil {
		if delivery != nil {
			for i := range delivery.Payload {
				delivery.Payload[i] = 0
			}
		}
		t.Fatal("revoked transfer released credential material to the recipient")
	}
	dispatch, err := svc.DB().GetDispatch(op)
	if err != nil || dispatch != nil {
		t.Fatalf("revoked transfer created a dispatch record: %#v %v", dispatch, err)
	}
}

func TestRecipientPullTicketConcurrentRedemptionHasOneWinner(t *testing.T) {
	svc := testService(t)
	defer svc.Close()
	const secret = "SYNTHETIC-CONCURRENT-TICKET-SECRET"
	if err := svc.AddSecretRef(&types.SecretReference{ID: "concurrent-ref", Name: "concurrent", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("concurrent-ref", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{
		ID: "concurrent-pull-dest", Name: "concurrent pull", Type: "recipient-socket",
		Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid,
		HandoffMode: types.HandoffRecipientPull,
		CredentialTarget: &types.AppCredentialTarget{
			ID: "opencode:openrouter:api_key", App: "opencode", Account: "openrouter", Slot: "api_key",
			UpdateMethod: "opencode-auth-json-v1", SourceRef: "concurrent-ref", SourceRevision: 1,
		},
	}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "concurrent-ref", "transfer", dest.ID)
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "concurrent-ref", DestinationID: dest.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	type result struct {
		delivery *types.HandoffDelivery
		err      error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			delivery, redeemErr := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid)
			results <- result{delivery: delivery, err: redeemErr}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for result := range results {
		if result.err == nil {
			winners++
			if result.delivery == nil || string(result.delivery.Payload) != secret {
				t.Fatal("winning redemption did not receive the approved credential")
			}
			for i := range result.delivery.Payload {
				result.delivery.Payload[i] = 0
			}
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent redemption winners=%d, want exactly one", winners)
	}
	dispatch, err := svc.DB().GetDispatch(op)
	if err != nil || dispatch == nil || dispatch.HandoffMode != types.HandoffRecipientPull {
		t.Fatalf("winning redemption dispatch missing: %#v %v", dispatch, err)
	}
}

func TestRecipientPullExpiredTicketDoesNotDispatch(t *testing.T) {
	svc := testService(t)
	defer svc.Close()
	if err := svc.AddSecretRef(&types.SecretReference{ID: "expired-ref", Name: "expired", Owner: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("expired-ref", []byte("SYNTHETIC-EXPIRED-TICKET-SECRET")); err != nil {
		t.Fatal(err)
	}
	root := publicTempDir(t)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{
		ID: "expired-pull-dest", Name: "expired pull", Type: "recipient-socket",
		Endpoint: filepath.Join(root, "recipient.sock"), ExpectedUID: &uid,
		HandoffMode: types.HandoffRecipientPull,
		CredentialTarget: &types.AppCredentialTarget{
			ID: "opencode:openrouter:api_key", App: "opencode", Account: "openrouter", Slot: "api_key",
			UpdateMethod: "opencode-auth-json-v1", SourceRef: "expired-ref", SourceRevision: 1,
		},
	}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "expired-ref", "transfer", dest.ID)
	op, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "expired-ref", DestinationID: dest.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(op, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.IssueHandoffTicket("uid:1000", op)
	if err != nil {
		t.Fatal(err)
	}
	ticketDB, err := sql.Open("sqlite3", svc.cfg.DBPath+"?mode=rw&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer ticketDB.Close()
	if _, err := ticketDB.Exec(`UPDATE handoff_tickets SET expires_at=? WHERE operation_id=?`, time.Now().Add(-time.Second), op); err != nil {
		t.Fatal(err)
	}
	if delivery, err := svc.RedeemHandoffTicket(context.Background(), ticket.TicketID, ticket.Nonce, uid); err == nil || delivery != nil {
		if delivery != nil {
			for i := range delivery.Payload {
				delivery.Payload[i] = 0
			}
		}
		t.Fatal("expired ticket released credential material")
	}
	dispatch, err := svc.DB().GetDispatch(op)
	if err != nil || dispatch != nil {
		t.Fatalf("expired ticket created a dispatch record: %#v %v", dispatch, err)
	}
}
