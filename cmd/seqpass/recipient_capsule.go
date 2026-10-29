package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/secretbridge/secretbridge/internal/apptarget"
	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// recipientCapsuleCmd keeps capsule trust recipient-local. Import reads only
// opaque bytes from stdin; all key, target, journal, and receipt pins come from
// the protected registration for the signed destination ID.
func recipientCapsuleCmd(args []string) {
	if len(args) == 0 {
		fatal("recipient capsule register|import|receipt")
	}
	switch args[0] {
	case "register":
		recipientCapsuleRegister(args[1:])
	case "import":
		recipientCapsuleImport(args[1:])
	case "receipt":
		recipientCapsuleReceipt(args[1:])
	default:
		fatal("recipient capsule register|import|receipt")
	}
}

func recipientCapsuleRegister(args []string) {
	fs := flag.NewFlagSet("recipient capsule register", flag.ExitOnError)
	destinationID := fs.String("destination-id", "", "operator-registered logical destination ID")
	destinationRevision := fs.Int("destination-revision", 0, "operator-approved destination revision")
	recipientKeyID := fs.String("recipient-key-id", "", "recipient key ID returned by trusted registration")
	privateKey := fs.String("recipient-private-key", "", "recipient-only HPKE private key file")
	issuerKeyID := fs.String("issuer-key-id", "", "out-of-band trusted issuer key ID")
	issuerPublic := fs.String("issuer-public-key", "", "out-of-band trusted raw Ed25519 public key file")
	receiptKeyID := fs.String("receipt-key-id", "", "recipient receipt signing key ID")
	receiptPrivate := fs.String("receipt-private-key", "", "recipient-only Ed25519 receipt seed file")
	receiptPublic := fs.String("receipt-public-key", "", "recipient Ed25519 receipt public key file")
	targetID := fs.String("target-id", "", "operator-registered application target ID")
	app := fs.String("app", "", "registered application ID")
	appProvider := fs.String("app-provider", "", "FI Gateway target upstream provider ID")
	account := fs.String("account", "", "registered account ID")
	slot := fs.String("slot", "", "registered credential slot")
	updateMethod := fs.String("update-method", "", "registered adapter update method")
	activation := fs.String("activation", "", "registered activation policy")
	sourceRef := fs.String("source-ref", "", "pinned credential source reference")
	sourceRevision := fs.Int("source-revision", 0, "pinned credential source revision")
	brokerSocket := fs.String("broker-socket", "", "recipient-authenticated broker socket for receipts")
	opencodeCommand := fs.String("opencode-command", "", "recipient-local absolute OpenCode v2 executable path")
	codexCommand := fs.String("codex-command", "", "recipient-local absolute Codex executable path")
	codexHome := fs.String("codex-home", "", "recipient-local CODEX_HOME (defaults to ~/.codex)")
	fiGatewaySocket := fs.String("fi-gateway-socket", "", "recipient-local FI Gateway credential socket")
	fiGatewayPeerUIDText := fs.String("fi-gateway-peer-uid", "", "expected FI Gateway socket peer UID (defaults to this recipient UID)")
	_ = fs.Parse(args)
	target := types.AppCredentialTarget{
		ID: *targetID, App: *app, Provider: *appProvider, Account: *account, Slot: *slot, UpdateMethod: *updateMethod,
		Activation: *activation, SourceRef: *sourceRef, SourceRevision: *sourceRevision,
	}
	currentUser, err := user.Current()
	must(err)
	var fiGatewayPeerUID *uint32
	if *fiGatewayPeerUIDText != "" {
		parsed, parseErr := strconv.ParseUint(*fiGatewayPeerUIDText, 10, 32)
		if parseErr != nil {
			fatal("FI Gateway peer UID must be an unsigned 32-bit integer")
		}
		uid := uint32(parsed)
		fiGatewayPeerUID = &uid
	}
	path, err := capsule.DefaultRecipientTrustPath(currentUser.HomeDir, *destinationID)
	must(err)
	issuerKey, err := readIssuerPublicKey(*issuerPublic)
	must(err)
	receiptPub, err := readIssuerPublicKey(*receiptPublic)
	must(err)
	cfg := capsule.RecipientTrust{
		Version: capsule.RecipientTrustVersion, DestinationID: *destinationID,
		DestinationRevision: *destinationRevision, RecipientKeyID: *recipientKeyID,
		RecipientPrivateKey: *privateKey, IssuerKeyID: *issuerKeyID, IssuerPublicKey: issuerKey,
		ReceiptKeyID: *receiptKeyID, ReceiptPrivateKey: *receiptPrivate, ReceiptPublicKey: receiptPub,
		Target: target, BrokerSocket: *brokerSocket, OpenCodeCommand: *opencodeCommand,
		CodexCommand: *codexCommand, CodexHome: *codexHome, FIGatewaySocket: *fiGatewaySocket, FIGatewayPeerUID: fiGatewayPeerUID,
	}
	must(cfg.Validate())
	if _, err := capsule.LoadRecipientPrivate(cfg.RecipientPrivateKey); err != nil {
		fatal("recipient private key is not usable by this identity")
	}
	receiptPrivateKey, err := capsule.LoadReceiptPrivate(cfg.ReceiptPrivateKey)
	if err != nil || !bytes.Equal(receiptPrivateKey.Public().(ed25519.PublicKey), cfg.ReceiptPublicKey) {
		fatal("recipient receipt signing key is not usable by this identity")
	}
	zeroBytes(receiptPrivateKey)
	if _, err := apptarget.NewRecipientAdapter(cfg.Target, currentUser.HomeDir, apptarget.RecipientOptions{
		OpenCodeCommand: cfg.OpenCodeCommand, CodexCommand: cfg.CodexCommand, CodexHome: cfg.CodexHome,
		FIGatewaySocket: cfg.FIGatewaySocket, FIGatewayPeerUID: cfg.FIGatewayPeerUID,
	}); err != nil {
		fatal("registered application adapter is not usable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fatal("could not create the recipient registration directory")
	}
	if err := capsule.StoreRecipientTrust(path, cfg); err != nil {
		fatal("could not create recipient trust registration; it may already exist or its directory is not private")
	}
	fmt.Printf("recipient capsule trust registered: %s\n", path)
}

func recipientCapsuleImport(args []string) {
	fs := flag.NewFlagSet("recipient capsule import", flag.ExitOnError)
	receiptOutput := fs.String("receipt-output", "", "write the signed, secret-free result receipt to a new file")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *receiptOutput == "" {
		fatal("recipient capsule import --receipt-output FILE reads the opaque capsule from stdin; trust pins are recipient-local")
	}
	if err := validateNewReceiptPath(*receiptOutput); err != nil {
		fatal("receipt output must be an absolute path that does not already exist")
	}
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not disable core dumps: %v\n", err)
	}
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, capsule.MaxSize+1))
	must(err)
	defer zeroBytes(encoded)
	if len(encoded) == 0 || len(encoded) > capsule.MaxSize {
		fatal("capsule input is empty or exceeds the size limit")
	}
	env, err := capsule.Parse(encoded)
	must(err)
	currentUser, err := user.Current()
	must(err)
	trustPath, err := capsule.DefaultRecipientTrustPath(currentUser.HomeDir, env.DestinationID)
	must(err)
	trust, err := capsule.LoadRecipientTrust(trustPath)
	if err != nil || trust.DestinationID != env.DestinationID {
		fatal("capsule destination has no valid recipient-local trust registration")
	}
	private, err := capsule.LoadRecipientPrivate(trust.RecipientPrivateKey)
	must(err)
	opened, err := capsule.Open(env, capsule.Expect{
		RecipientKeyID: trust.RecipientKeyID, SigningKeyID: trust.IssuerKeyID,
		HandoffID: env.HandoffID, OperationID: env.OperationID,
		DestinationID: trust.DestinationID, DestinationRevision: trust.DestinationRevision,
		TargetID: trust.Target.ID, App: trust.Target.App, Provider: trust.Target.Provider, Account: trust.Target.Account,
		Slot: trust.Target.Slot, UpdateMethod: trust.Target.UpdateMethod, Activation: trust.Target.Activation,
		SourceRef: trust.Target.SourceRef, SourceRevision: trust.Target.SourceRevision,
	}, ed25519.PublicKey(trust.IssuerPublicKey), private)
	if err != nil {
		fatal("capsule rejected by recipient-local identity or issuer trust")
	}
	defer zeroBytes(opened.Credential)
	if err := trust.Target.Validate(); err != nil || opened.App != trust.Target.App || opened.UpdateMethod != trust.Target.UpdateMethod {
		fatal("recipient has no qualified adapter for this registered application target")
	}
	receiptKey, err := capsule.LoadReceiptPrivate(trust.ReceiptPrivateKey)
	must(err)
	if !bytes.Equal(receiptKey.Public().(ed25519.PublicKey), trust.ReceiptPublicKey) {
		fatal("recipient receipt signing key no longer matches local trust")
	}
	defer zeroBytes(receiptKey)
	appAdapter, err := apptarget.NewRecipientAdapter(trust.Target, currentUser.HomeDir, apptarget.RecipientOptions{
		OpenCodeCommand: trust.OpenCodeCommand, CodexCommand: trust.CodexCommand, CodexHome: trust.CodexHome,
		FIGatewaySocket: trust.FIGatewaySocket, FIGatewayPeerUID: trust.FIGatewayPeerUID,
	})
	must(err)
	// The registration directory is created and ownership-checked during
	// enrollment. Keeping the journal beneath that protected directory avoids
	// creating a chain of state directories while processing courier input.
	journalDir := filepath.Join(filepath.Dir(trustPath), "journal")
	journal, err := transfer.NewOperationJournal(journalDir)
	must(err)
	committer := &apptarget.TransferCommitter{Target: trust.Target, Adapter: appAdapter}
	consumer, err := transfer.NewApplicationConsumer(journal, committer)
	must(err)
	acceptance, acceptErr := consumer.Accept(context.Background(), transfer.Delivery{
		OperationID: env.HandoffID, DataKind: "api_key", Payload: opened.Credential, Target: &trust.Target,
	})
	entry, found, journalErr := journal.Load(env.HandoffID)
	if journalErr != nil || !found {
		fatal("recipient application result was not durably journaled")
	}
	state := "uncertain"
	if acceptErr == nil && acceptance.State == transfer.StateApplied {
		state = "applied"
	} else if acceptErr == nil && acceptance.State == transfer.StateRejected {
		state = "rejected"
	}
	entry.ReceiptOperationID = env.OperationID
	entry.ReceiptHandoffID = env.HandoffID
	entry.ReceiptDigest = transfer.DigestPayload(string(encoded))
	entry.ReceiptBytes = len(encoded)
	entry.State = acceptance.State
	entry.Applied = state == "applied"
	must(journal.Upsert(entry))
	receiptData, err := capsule.SignReceipt(capsule.Receipt{
		ReceiptKeyID: trust.ReceiptKeyID, OperationID: env.OperationID,
		HandoffID: env.HandoffID, DestinationID: env.DestinationID,
		DestinationRevision: trust.DestinationRevision, CapsuleDigest: entry.ReceiptDigest,
		CapsuleBytes: len(encoded), State: state, IssuedAt: time.Now().UTC(),
	}, receiptKey)
	must(err)
	entry.RecipientReceipt = receiptData
	must(journal.Upsert(entry))
	if err := writeReceiptFile(*receiptOutput, receiptData); err != nil {
		fatal("could not write signed recipient receipt")
	}
	if trust.BrokerSocket != "" {
		client, receiptErr := ipc.Dial(trust.BrokerSocket)
		if receiptErr == nil {
			_, receiptErr = client.Call(ipc.MethodHandoffComplete, map[string]interface{}{
				"op_id": env.OperationID, "handoff_id": env.HandoffID,
				"digest": entry.ReceiptDigest, "state": state, "bytes": len(encoded),
			})
			_ = client.Close()
		}
		if receiptErr != nil {
			fmt.Printf("recipient result %s; signed receipt saved for relay: %s\n", state, *receiptOutput)
			return
		}
	}
	if state != "applied" {
		fatal("capsule was not verified as applied; signed receipt saved")
	}
	if trust.BrokerSocket == "" {
		fmt.Printf("sealed handoff applied; signed receipt saved for relay: %s\n", *receiptOutput)
		return
	}
	fmt.Printf("sealed handoff applied and receipted: %s\n", env.OperationID)
}

func writeReceiptFile(path string, data []byte) error {
	if validateNewReceiptPath(path) != nil || len(data) == 0 || len(data) > 16*1024 {
		return fmt.Errorf("invalid receipt output")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func validateNewReceiptPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("receipt output path must be absolute")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("receipt output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// recipientCapsuleReceipt exports the signed result kept in the local journal.
// It also reconstructs the same authenticated fields after a crash between
// application commit and receipt persistence; no credential is read or needed.
func recipientCapsuleReceipt(args []string) {
	fs := flag.NewFlagSet("recipient capsule receipt", flag.ExitOnError)
	destinationID := fs.String("destination-id", "", "registered logical destination ID")
	handoffID := fs.String("handoff-id", "", "sealed capsule handoff ID")
	output := fs.String("output", "", "write a signed receipt to a new file")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *destinationID == "" || *handoffID == "" || *output == "" {
		fatal("recipient capsule receipt --destination-id ID --handoff-id ID --output FILE")
	}
	currentUser, err := user.Current()
	must(err)
	trustPath, err := capsule.DefaultRecipientTrustPath(currentUser.HomeDir, *destinationID)
	must(err)
	trust, err := capsule.LoadRecipientTrust(trustPath)
	if err != nil || trust.DestinationID != *destinationID {
		fatal("recipient destination has no valid local trust registration")
	}
	journal, err := transfer.NewOperationJournal(filepath.Join(filepath.Dir(trustPath), "journal"))
	must(err)
	entry, found, err := journal.Load(*handoffID)
	must(err)
	if !found || entry.ReceiptOperationID == "" || entry.ReceiptHandoffID != *handoffID || entry.ReceiptDigest == "" || entry.ReceiptBytes <= 0 {
		fatal("no durable capsule receipt exists for that handoff")
	}
	receiptData := entry.RecipientReceipt
	if len(receiptData) == 0 {
		state := "uncertain"
		if entry.Applied && entry.State == transfer.StateApplied {
			state = "applied"
		} else if entry.State == transfer.StateRejected {
			state = "rejected"
		}
		private, err := capsule.LoadReceiptPrivate(trust.ReceiptPrivateKey)
		must(err)
		receiptData, err = capsule.SignReceipt(capsule.Receipt{
			ReceiptKeyID: trust.ReceiptKeyID, OperationID: entry.ReceiptOperationID,
			HandoffID: entry.ReceiptHandoffID, DestinationID: trust.DestinationID,
			DestinationRevision: trust.DestinationRevision, CapsuleDigest: entry.ReceiptDigest,
			CapsuleBytes: entry.ReceiptBytes, State: state, IssuedAt: time.Now().UTC(),
		}, private)
		zeroBytes(private)
		must(err)
		entry.RecipientReceipt = receiptData
		must(journal.Upsert(entry))
	}
	private, err := capsule.LoadReceiptPrivate(trust.ReceiptPrivateKey)
	must(err)
	public, ok := private.Public().(ed25519.PublicKey)
	zeroBytes(private)
	if !ok || !bytes.Equal(public, trust.ReceiptPublicKey) {
		fatal("recipient receipt key is unusable")
	}
	verified, err := capsule.VerifyReceipt(receiptData, trust.ReceiptKeyID, public)
	if err != nil || verified.OperationID != entry.ReceiptOperationID || verified.HandoffID != entry.ReceiptHandoffID || verified.DestinationID != trust.DestinationID || verified.DestinationRevision != trust.DestinationRevision || verified.CapsuleDigest != entry.ReceiptDigest || verified.CapsuleBytes != entry.ReceiptBytes {
		fatal("durable capsule receipt is malformed")
	}
	if err := writeReceiptFile(*output, receiptData); err != nil {
		fatal("could not write signed recipient receipt")
	}
	fmt.Printf("signed recipient receipt exported: %s\n", *output)
}

func readIssuerPublicKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("issuer public key path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("issuer public key file is invalid")
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) != ed25519.PublicKeySize {
		zeroBytes(b)
		return nil, fmt.Errorf("issuer public key must be exactly 32 bytes")
	}
	return b, nil
}
