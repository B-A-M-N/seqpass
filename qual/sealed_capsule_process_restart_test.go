//go:build linux

package qual

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// TestQualSealedCapsuleProductionProcessRestart exercises the shipped SeqPass
// broker executable, rather than a service instance or test-binary helper. It
// verifies exact capsule retrieval after broker death and reconciles a signed
// recipient receipt delivered only after another issuer restart.
func TestQualSealedCapsuleProductionProcessRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid()), topology: map[string]string{}}
	h.bin = buildBinary(t, dir)
	uid := strconv.FormatUint(uint64(os.Geteuid()), 10)
	dbPath := filepath.Join(dir, "broker.db")
	agentSocket := filepath.Join(dir, "agent.sock")
	adminSocket := filepath.Join(dir, "admin.sock")
	intakeSocket := filepath.Join(dir, "intake.sock")
	h.agent = agentSocket
	h.admin = adminSocket
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issuerSeed := filepath.Join(dir, "issuer.seed")
	issuerPublicPath := filepath.Join(dir, "issuer.pub")
	issuerPublic, err := capsule.GenerateIssuerKeys(issuerSeed, issuerPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivatePath := filepath.Join(dir, "recipient.hpke")
	recipientPublicPath := filepath.Join(dir, "recipient.hpke.pub")
	recipientPublic, err := capsule.GenerateRecipientKeys(recipientPrivatePath, recipientPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivatePath := filepath.Join(dir, "recipient.receipt.seed")
	receiptPublicPath := filepath.Join(dir, "recipient.receipt.pub")
	receiptPublic, err := capsule.GenerateReceiptKeys(receiptPrivatePath, receiptPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	startProductionBroker := func() {
		t.Helper()
		cmd := exec.Command(h.bin, "broker",
			"--vault", "memory-test", "--dev",
			"--db", dbPath,
			"--socket", agentSocket,
			"--admin-socket", adminSocket,
			"--intake-socket", intakeSocket,
			"--recipient-socket=",
			"--agent-uid", uid,
			"--admin-uid", uid,
			"--intake-uid", uid,
			"--handoff-signing-key-id", "qual-issuer-v1",
			"--handoff-signing-seed", issuerSeed,
		)
		cmd.Env = append(os.Environ(), "SEQ_PASS_CONFIG="+configPath)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start production broker: %v", err)
		}
		h.broker = cmd
		t.Cleanup(func() {
			if h.broker != nil && h.broker.Process != nil {
				_ = h.broker.Process.Kill()
				_ = h.broker.Wait()
				h.broker = nil
			}
		})
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			cli, dialErr := ipc.Dial(agentSocket)
			if dialErr == nil {
				_, healthErr := cli.Call(ipc.MethodHealth, nil)
				_ = cli.Close()
				if healthErr == nil {
					admin, adminErr := ipc.Dial(adminSocket)
					if adminErr == nil {
						_, healthErr = admin.Call(ipc.MethodHealth, nil)
						_ = admin.Close()
						if healthErr == nil {
							return
						}
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = h.broker.Process.Kill()
		_ = h.broker.Wait()
		t.Fatalf("production broker sockets did not become ready")
	}
	stopProductionBroker := func() {
		t.Helper()
		if h.broker == nil {
			t.Fatal("production broker is not running")
		}
		if err := h.broker.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := h.broker.Wait(); err == nil {
			t.Fatal("broker unexpectedly exited without process kill")
		}
		h.broker = nil
	}
	startProductionBroker()

	const syntheticCredential = "SEQPASS-PROCESS-RESTART-SYNTHETIC-5c17"
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "process-restart-synthetic"}).(map[string]interface{})
	refID := strField(refData, "id")
	if refID == "" {
		t.Fatal("production broker did not create synthetic source reference")
	}
	adminCall(t, h, ipc.MethodSecretStage, map[string]interface{}{
		"ref_id": refID, "payload_b64": base64.StdEncoding.EncodeToString([]byte(syntheticCredential)),
	})
	target := types.AppCredentialTarget{
		ID: "opencode:qual:api_key", App: "opencode", Account: "qual", Slot: "api_key",
		UpdateMethod: "opencode-auth-json-v1", SourceRef: refID, SourceRevision: 1,
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "production-process-restart", "type": "sealed-capsule", "handoff_mode": "sealed-capsule",
		"expected_uid": float64(os.Geteuid()), "recipient_key_id": "qual-recipient-v1",
		"recipient_public_key_b64": base64.StdEncoding.EncodeToString(recipientPublic),
		"receipt_key_id":           "qual-receipt-v1",
		"receipt_public_key_b64":   base64.StdEncoding.EncodeToString(receiptPublic),
		"issuer_key_id":            "qual-issuer-v1",
		"issuer_public_key_b64":    base64.StdEncoding.EncodeToString(issuerPublic),
		"credential_target":        json.RawMessage(targetJSON),
	}).(map[string]interface{})
	destID := strField(destData, "id")
	if destID == "" {
		t.Fatal("production broker did not create capsule destination")
	}
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "process-restart-allow",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":[%q],"resources":["*"]}]`, h.uid, refID, destID),
	})
	submitted, err := agentCall(t, h, ipc.MethodTransferSubmit, map[string]interface{}{"secret_ref": refID, "destination_id": destID})
	if err != nil {
		t.Fatalf("submit synthetic capsule operation: %v", err)
	}
	opID := strField(submitted.(map[string]interface{}), "op_id")
	if opID == "" {
		t.Fatal("production broker returned no operation ID")
	}
	reviewed := adminCall(t, h, ipc.MethodOpShow, map[string]interface{}{"op_type": "transfer", "op_id": opID}).(map[string]interface{})
	adminCall(t, h, ipc.MethodApproveTransfer, map[string]interface{}{"op_id": opID, "expect_revision": reviewed["revision"]})
	issuedRaw, err := agentCall(t, h, ipc.MethodHandoffIssue, map[string]interface{}{"op_id": opID})
	if err != nil {
		t.Fatalf("issue capsule through production broker: %v", err)
	}
	issuedBytes, err := json.Marshal(issuedRaw)
	if err != nil {
		t.Fatal(err)
	}
	var issued types.HandoffCapsule
	if err := json.Unmarshal(issuedBytes, &issued); err != nil || len(issued.Envelope) == 0 {
		t.Fatalf("decode production capsule response: %v", err)
	}
	issuedEnv, err := capsule.Parse(issued.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := sql.Open("sqlite3", dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	var payloadBytes int
	var originalCapsule []byte
	if err := observer.QueryRow(`SELECT payload_digest,payload_bytes,capsule_bytes FROM dispatch_records WHERE op_id=?`, opID).
		Scan(&digest, &payloadBytes, &originalCapsule); err != nil {
		_ = observer.Close()
		t.Fatal(err)
	}
	_ = observer.Close()
	issuedCanonical, err := capsule.Marshal(issuedEnv)
	if err != nil || !bytes.Equal(issuedCanonical, originalCapsule) || digest != transfer.DigestPayload(string(originalCapsule)) || payloadBytes != len(originalCapsule) {
		t.Fatalf("issued response does not correspond to its durable ciphertext: marshal=%v digest_match=%t length_match=%t", err, digest == transfer.DigestPayload(string(originalCapsule)), payloadBytes == len(originalCapsule))
	}
	binarySum := sha256.Sum256(mustReadFile(t, h.bin))
	h.topology["production_binary_sha256"] = hex.EncodeToString(binarySum[:])
	h.topology["capsule_sha256"] = digest
	h.topology["destination_id"] = destID
	stopProductionBroker()
	startProductionBroker()

	retrievedRaw, err := agentCall(t, h, ipc.MethodHandoffRetrieve, map[string]interface{}{"op_id": opID})
	if err != nil {
		t.Fatalf("retrieve capsule after production broker restart: %v", err)
	}
	retrievedBytes, err := json.Marshal(retrievedRaw)
	if err != nil {
		t.Fatal(err)
	}
	var retrieved types.HandoffCapsule
	if err := json.Unmarshal(retrievedBytes, &retrieved); err != nil {
		t.Fatal(err)
	}
	retrievedEnv, err := capsule.Parse(retrieved.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	retrievedCanonical, err := capsule.Marshal(retrievedEnv)
	if err != nil {
		t.Fatal(err)
	}
	exactRecovery := bytes.Equal(retrievedCanonical, originalCapsule) &&
		retrievedEnv.HandoffID == issuedEnv.HandoffID && retrievedEnv.ExpiresAt.Equal(issuedEnv.ExpiresAt)
	h.recordTier("sealed-capsule-production-issuer-restart", tierSystem,
		"retrieve the exact persisted recipient-encrypted package after killing and restarting the built SeqPass CLI broker",
		"identical ciphertext digest and handoff expiry; no replacement package",
		fmt.Sprintf("exact=%t digest=%s handoff=%s expiry=%s", exactRecovery, digest, retrievedEnv.HandoffID, retrievedEnv.ExpiresAt.UTC().Format(time.RFC3339Nano)), exactRecovery)

	recipientPrivate, err := capsule.LoadRecipientPrivate(recipientPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := capsule.Open(retrievedEnv, capsule.Expect{
		RecipientKeyID: "qual-recipient-v1", SigningKeyID: "qual-issuer-v1", HandoffID: retrievedEnv.HandoffID,
		OperationID: opID, DestinationID: destID, DestinationRevision: 1,
		TargetID: target.ID, App: target.App, Account: target.Account, Slot: target.Slot,
		UpdateMethod: target.UpdateMethod, SourceRef: target.SourceRef, SourceRevision: target.SourceRevision,
	}, ed25519.PublicKey(issuerPublic), recipientPrivate)
	if err != nil || string(opened.Credential) != syntheticCredential {
		t.Fatalf("recipient could not verify persisted capsule: %v", err)
	}
	for i := range opened.Credential {
		opened.Credential[i] = 0
	}
	receiptPrivate, err := capsule.LoadReceiptPrivate(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := capsule.SignReceipt(capsule.Receipt{
		ReceiptKeyID: "qual-receipt-v1", OperationID: opID, HandoffID: retrievedEnv.HandoffID,
		DestinationID: destID, DestinationRevision: 1, CapsuleDigest: digest, CapsuleBytes: len(originalCapsule),
		State: "applied", IssuedAt: time.Now().UTC(),
	}, receiptPrivate)
	for i := range receiptPrivate {
		receiptPrivate[i] = 0
	}
	if err != nil {
		t.Fatal(err)
	}
	// The recipient's successful application is followed by lost receipt
	// delivery: kill the issuer, restart it, and submit the retained signed
	// receipt only to the new broker process.
	stopProductionBroker()
	startProductionBroker()
	if _, err := agentCall(t, h, ipc.MethodHandoffReceipt, map[string]interface{}{"receipt_b64": base64.StdEncoding.EncodeToString(receipt)}); err != nil {
		_, parseErr := capsule.ParseReceipt(receipt)
		db, dbErr := sql.Open("sqlite3", dbPath+"?mode=ro&_busy_timeout=5000")
		if dbErr != nil {
			t.Fatal(dbErr)
		}
		var revision int
		var receiptKeyID, storedDigest, storedHandoff string
		var storedBytes int
		lookupErr := db.QueryRow(`SELECT x.revision,x.receipt_key_id,d.payload_digest,d.payload_bytes,d.handoff_id
			FROM destinations x JOIN dispatch_records d ON d.dest_id=x.id WHERE d.op_id=?`, opID).
			Scan(&revision, &receiptKeyID, &storedDigest, &storedBytes, &storedHandoff)
		_ = db.Close()
		verifyErr := error(nil)
		if parseErr == nil {
			_, verifyErr = capsule.VerifyReceipt(receipt, "qual-receipt-v1", receiptPublic)
		}
		t.Fatalf("reconcile lost receipt after a second production restart: %v (parse=%v verify=%v lookup=%v revision=%d key=%q digest_match=%t bytes_match=%t handoff_match=%t)",
			err, parseErr, verifyErr, lookupErr, revision, receiptKeyID, storedDigest == digest,
			storedBytes == len(originalCapsule), storedHandoff == issuedEnv.HandoffID)
	}
	status, err := agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil || strField(status.(map[string]interface{}), "status") != types.StatusCompleted {
		t.Fatalf("receipt did not settle production operation: status=%v err=%v", status, err)
	}
	h.recordTier("sealed-capsule-lost-receipt-production-restart", tierSystem,
		"reconcile a signed recipient receipt after issuer restart and lost acknowledgment",
		"operation completes without replaying or reissuing the capsule", "completed after fresh production broker startup", true)
	stopProductionBroker()
	startProductionBroker()
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var storedStatus, storedDigest string
	var storedBytes, capsuleLength int
	if err := db.QueryRow(`SELECT t.status,d.payload_digest,d.payload_bytes,length(d.capsule_bytes)
		FROM transfers t JOIN dispatch_records d ON d.op_id=t.id WHERE t.id=?`, opID).
		Scan(&storedStatus, &storedDigest, &storedBytes, &capsuleLength); err != nil {
		t.Fatal(err)
	}
	retentionOK := storedStatus == types.StatusCompleted && storedDigest == digest && storedBytes == len(originalCapsule) && capsuleLength == 0
	h.recordTier("sealed-capsule-final-retention-production-restart", tierSystem,
		"verify startup cleanup clears settled capsule bytes while retaining receipt-reconciliation metadata",
		"capsule bytes are absent; digest and original byte count remain", fmt.Sprintf("status=%s capsule_bytes=%d digest_preserved=%t length_preserved=%t", storedStatus, capsuleLength, storedDigest == digest, storedBytes == len(originalCapsule)), retentionOK)
	writeManifest(t, h, "memory-test-synthetic-sealed-capsule-process-restart")
}

// TestQualRecipientPullProductionRestart runs the built broker and shipped
// recipient handoff CLI as separate processes. The memory-test vault is
// intentionally reseeded with the same synthetic value after issuer restart;
// this qualifies ticket recovery and recipient execution, not durable source
// credential storage (which requires the AegisKeys integration tier).
func TestQualRecipientPullProductionRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid()), topology: map[string]string{}}
	h.bin = buildBinary(t, dir)
	uid := strconv.FormatUint(uint64(os.Geteuid()), 10)
	dbPath := filepath.Join(dir, "broker.db")
	h.agent = filepath.Join(dir, "agent.sock")
	h.admin = filepath.Join(dir, "admin.sock")
	recipientSocket := filepath.Join(dir, "recipient-only.sock")
	intakeSocket := filepath.Join(dir, "intake.sock")
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	startBroker := func() {
		t.Helper()
		cmd := exec.Command(h.bin, "broker",
			"--vault", "memory-test", "--dev", "--db", dbPath,
			"--socket", h.agent, "--admin-socket", h.admin, "--intake-socket", intakeSocket,
			"--recipient-socket", recipientSocket, "--recipient-uid", uid,
			"--agent-uid", uid, "--admin-uid", uid, "--intake-uid", uid,
		)
		cmd.Env = append(os.Environ(), "SEQ_PASS_CONFIG="+configPath)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start production broker: %v", err)
		}
		h.broker = cmd
		t.Cleanup(func() {
			if h.broker != nil && h.broker.Process != nil {
				_ = h.broker.Process.Kill()
				_ = h.broker.Wait()
				h.broker = nil
			}
		})
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			cli, err := ipc.Dial(recipientSocket)
			if err == nil {
				_, healthErr := cli.Call(ipc.MethodHealth, nil)
				_ = cli.Close()
				if healthErr == nil {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = h.broker.Process.Kill()
		_ = h.broker.Wait()
		t.Fatal("production recipient socket did not become ready")
	}
	stopBroker := func() {
		t.Helper()
		if h.broker == nil {
			t.Fatal("production broker is not running")
		}
		if err := h.broker.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := h.broker.Wait(); err == nil {
			t.Fatal("broker unexpectedly exited without process kill")
		}
		h.broker = nil
	}
	startBroker()
	const syntheticCredential = "SEQPASS-PULL-RESTART-SYNTHETIC-1f30"
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "pull-restart-synthetic"}).(map[string]interface{})
	refID := strField(refData, "id")
	stageSynthetic := func() {
		t.Helper()
		adminCall(t, h, ipc.MethodSecretStage, map[string]interface{}{
			"ref_id": refID, "payload_b64": base64.StdEncoding.EncodeToString([]byte(syntheticCredential)),
		})
	}
	stageSynthetic()
	target := types.AppCredentialTarget{
		ID: "codex:qual:api_key", App: "codex", Account: "qual", Slot: "api_key",
		UpdateMethod: "codex-auth-file-v1", SourceRef: refID, SourceRevision: 1,
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "pull-production-restart", "type": "recipient-socket", "endpoint": filepath.Join(dir, "unused-app.sock"),
		"handoff_mode": "recipient-pull", "expected_uid": float64(os.Geteuid()),
		"credential_target": json.RawMessage(targetJSON),
	}).(map[string]interface{})
	destID := strField(destData, "id")
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "pull-process-restart-allow",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":[%q],"resources":["*"]}]`, h.uid, refID, destID),
	})
	submitted, err := agentCall(t, h, ipc.MethodTransferSubmit, map[string]interface{}{"secret_ref": refID, "destination_id": destID})
	if err != nil {
		t.Fatalf("submit recipient-pull operation: %v", err)
	}
	opID := strField(submitted.(map[string]interface{}), "op_id")
	reviewed := adminCall(t, h, ipc.MethodOpShow, map[string]interface{}{"op_type": "transfer", "op_id": opID}).(map[string]interface{})
	adminCall(t, h, ipc.MethodApproveTransfer, map[string]interface{}{"op_id": opID, "expect_revision": reviewed["revision"]})
	ticketRaw, err := agentCall(t, h, ipc.MethodHandoffIssue, map[string]interface{}{"op_id": opID})
	if err != nil {
		t.Fatalf("issue recipient-pull ticket: %v", err)
	}
	ticketBytes, _ := json.Marshal(ticketRaw)
	var ticket types.HandoffTicket
	if err := json.Unmarshal(ticketBytes, &ticket); err != nil || ticket.TicketID == "" || ticket.Nonce == "" {
		t.Fatalf("decode recipient-pull ticket: %v", err)
	}
	stopBroker()
	startBroker()
	status, err := agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil || strField(status.(map[string]interface{}), "status") != types.StatusAuthorized {
		t.Fatalf("issuer restart changed pre-dispatch operation: status=%v err=%v", status, err)
	}
	stageSynthetic() // The test vault is deliberately ephemeral across process restart.

	codexHome := filepath.Join(dir, "codex-home")
	if err := os.Mkdir(codexHome, 0700); err != nil {
		t.Fatal(err)
	}
	fakeCodex := filepath.Join(dir, "codex-test-command")
	script := "#!/bin/sh\nIFS= read -r key || exit 11\nmkdir -p \"$CODEX_HOME\"\nprintf '{\"auth_mode\":\"apikey\",\"OPENAI_API_KEY\":\"%s\"}\\n' \"$key\" > \"$CODEX_HOME/auth.json\"\nchmod 600 \"$CODEX_HOME/auth.json\"\n"
	if err := os.WriteFile(fakeCodex, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "recipient-journal")
	runRecipient := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(h.bin, args...)
		cmd.Env = append(os.Environ(), "SEQ_PASS_CONFIG="+configPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("production recipient command %v failed: %v: %s", args, err, out)
		}
		return out
	}
	proxySocket, droppedReceipt, stopProxy := startCompletionDropProxy(t, dir, recipientSocket)
	firstCmd := exec.Command(h.bin, "recipient", "handoff", "--broker-socket", proxySocket,
		"--ticket", ticket.TicketID, "--nonce", ticket.Nonce, "--journal", journal,
		"--codex-command", fakeCodex, "--codex-home", codexHome)
	firstCmd.Env = append(os.Environ(), "SEQ_PASS_CONFIG="+configPath)
	firstOutput, firstErr := firstCmd.CombinedOutput()
	if firstErr == nil {
		t.Fatalf("recipient unexpectedly received a completion acknowledgment: %s", firstOutput)
	}
	select {
	case proxyErr := <-droppedReceipt:
		if proxyErr != nil {
			t.Fatalf("receipt-drop proxy failed: %v", proxyErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recipient did not submit a completion receipt")
	}
	stopProxy()
	installed, err := os.ReadFile(filepath.Join(codexHome, "auth.json"))
	if err != nil || !bytes.Contains(installed, []byte(syntheticCredential)) {
		t.Fatalf("production recipient did not install synthetic credential: %v", err)
	}
	for i := range installed {
		installed[i] = 0
	}
	stopBroker()
	startBroker()
	status, err = agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil || strField(status.(map[string]interface{}), "status") != types.StatusUncertain {
		t.Fatalf("lost recipient receipt did not leave honest uncertain state: status=%v err=%v", status, err)
	}
	h.recordTier("recipient-pull-production-lost-receipt", tierSystem,
		"drop the shipped recipient's completion request after applying a synthetic credential",
		"recipient application persists, broker retains uncertain status, and CLI output discloses no credential",
		fmt.Sprintf("operation=%s status=%s recipient_output_secret_free=%t", opID, strField(status.(map[string]interface{}), "status"), !bytes.Contains(firstOutput, []byte(syntheticCredential))),
		strField(status.(map[string]interface{}), "status") == types.StatusUncertain && !bytes.Contains(firstOutput, []byte(syntheticCredential)))
	retryOutput := runRecipient("recipient", "handoff", "--broker-socket", recipientSocket,
		"--complete-op", opID, "--journal", journal)
	status, err = agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil || strField(status.(map[string]interface{}), "status") != types.StatusCompleted || bytes.Contains(retryOutput, []byte(syntheticCredential)) {
		t.Fatalf("recipient journal recovery after another issuer restart failed: status=%v err=%v", status, err)
	}
	installed, err = os.ReadFile(filepath.Join(codexHome, "auth.json"))
	if err != nil || !bytes.Contains(installed, []byte(syntheticCredential)) {
		t.Fatalf("recipient retry changed or lost the applied credential: %v", err)
	}
	for i := range installed {
		installed[i] = 0
	}
	h.recordTier("recipient-pull-production-recipient-restart", tierSystem,
		"restart the shipped recipient from its persistent operation journal and retry lost completion against a restarted broker",
		"idempotent receipt retry reconciles uncertainty without replaying the credential write",
		"completed after retry; installed synthetic value remains present", true)
	writeManifest(t, h, "memory-test-synthetic-recipient-pull-process-restart")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// startCompletionDropProxy forwards ticket redemption to the real broker, then
// drops the recipient completion request to simulate an applied write whose
// acknowledgment is lost. It forwards only framed IPC bytes and never logs or
// retains the response payload.
func startCompletionDropProxy(t *testing.T, dir, upstreamPath string) (string, <-chan error, func()) {
	t.Helper()
	path := filepath.Join(dir, "receipt-drop-proxy.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			frame, err := reader.ReadBytes('\n')
			if err != nil {
				done <- err
				return
			}
			var req ipc.Request
			if err := json.Unmarshal(frame, &req); err != nil {
				clear(frame)
				done <- fmt.Errorf("invalid IPC frame")
				return
			}
			if req.Method == ipc.MethodHandoffComplete {
				clear(frame)
				done <- nil
				return
			}
			if req.Method != ipc.MethodHandoffRedeem {
				clear(frame)
				done <- fmt.Errorf("unexpected IPC method")
				return
			}
			upstream, err := net.DialTimeout("unix", upstreamPath, 5*time.Second)
			if err != nil {
				clear(frame)
				done <- err
				return
			}
			_ = upstream.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := upstream.Write(frame); err != nil {
				clear(frame)
				_ = upstream.Close()
				done <- err
				return
			}
			clear(frame)
			response, err := bufio.NewReader(upstream).ReadBytes('\n')
			_ = upstream.Close()
			if err != nil {
				done <- err
				return
			}
			_, writeErr := conn.Write(response)
			clear(response)
			if writeErr != nil {
				done <- writeErr
				return
			}
		}
	}()
	stop := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	t.Cleanup(stop)
	return path, done, stop
}
