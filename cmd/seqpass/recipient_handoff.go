package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/secretbridge/secretbridge/internal/apptarget"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

// recipientHandoffCmd is the pull-side client. It receives the approved
// payload only on the recipient-only socket and commits it with the same
// durable ApplicationConsumer used by the push protocol.
func recipientHandoffCmd(args []string) {
	base := loadBase()
	fs := flag.NewFlagSet("recipient handoff", flag.ExitOnError)
	socket := fs.String("broker-socket", base.RecipientSocket, "recipient-only broker socket")
	ticket := fs.String("ticket", "", "opaque one-use ticket ID")
	nonce := fs.String("nonce", "", "ticket nonce returned by agent handoff issue")
	completeOp := fs.String("complete-op", "", "retry completion using the local operation journal")
	journalDir := fs.String("journal", "", "durable plaintext-free operation journal")
	opencodeCommand := fs.String("opencode-command", "", "recipient-local absolute OpenCode v2 executable path (required for v2 auth storage)")
	codexCommand := fs.String("codex-command", "", "recipient-local absolute Codex executable path")
	codexHome := fs.String("codex-home", "", "recipient-local CODEX_HOME (defaults to ~/.codex)")
	fiGatewaySocket := fs.String("fi-gateway-socket", "", "recipient-local FI Gateway credential socket")
	fiGatewayPeerUIDText := fs.String("fi-gateway-peer-uid", "", "expected FI Gateway socket peer UID (defaults to this recipient UID)")
	_ = fs.Parse(args)
	var fiGatewayPeerUID *uint32
	if *fiGatewayPeerUIDText != "" {
		parsed, parseErr := strconv.ParseUint(*fiGatewayPeerUIDText, 10, 32)
		if parseErr != nil {
			fatal("FI Gateway peer UID must be an unsigned 32-bit integer")
		}
		uid := uint32(parsed)
		fiGatewayPeerUID = &uid
	}
	if *socket == "" || *journalDir == "" || (*ticket == "" && *completeOp == "") || (*ticket != "" && *nonce == "") {
		fatal("recipient handoff --ticket ID --nonce NONCE --journal DIR [--broker-socket PATH]")
	}
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not disable core dumps: %v\n", err)
	}
	journal, err := transfer.NewOperationJournal(*journalDir)
	must(err)
	cli, err := ipc.Dial(*socket)
	must(err)
	defer cli.Close()
	if *completeOp != "" {
		entry, ok, err := journal.Load(*completeOp)
		must(err)
		if !ok {
			fatal("no durable recipient completion exists for that operation")
		}
		opID, digest, byteCount := entry.ReceiptOperationID, entry.ReceiptDigest, entry.ReceiptBytes
		if opID == "" { // Mode A compatibility: receipt fields predate capsule ledger support.
			opID, digest, byteCount = entry.OperationID, entry.Digest, entry.ByteCount
		}
		if opID == "" || digest == "" || byteCount <= 0 {
			fatal("no durable recipient receipt exists for that operation")
		}
		state := "uncertain"
		if entry.State == transfer.StateApplied {
			state = "applied"
		} else if entry.State == transfer.StateRejected {
			state = "rejected"
		}
		receipt := map[string]interface{}{"op_id": opID, "digest": digest, "state": state, "bytes": byteCount}
		if entry.ReceiptHandoffID != "" {
			receipt["handoff_id"] = entry.ReceiptHandoffID
		}
		_, err = cli.Call(ipc.MethodHandoffComplete, receipt)
		must(err)
		fmt.Printf("handoff receipt recorded: %s\n", opID)
		return
	}
	raw, err := cli.Call(ipc.MethodHandoffRedeem, map[string]interface{}{"ticket_id": *ticket, "nonce": *nonce})
	must(err)
	encoded, err := json.Marshal(raw)
	must(err)
	var delivery types.HandoffDelivery
	must(json.Unmarshal(encoded, &delivery))
	if delivery.OperationID == "" || delivery.DestinationID == "" || delivery.Target.ID == "" || len(delivery.Payload) == 0 || len(delivery.Payload) > 512*1024 {
		zeroBytes(delivery.Payload)
		fatal("broker returned an invalid handoff")
	}
	if transfer.DigestPayload(string(delivery.Payload)) != delivery.PayloadDigest {
		zeroBytes(delivery.Payload)
		fatal("broker handoff digest mismatch")
	}
	if err := delivery.Target.Validate(); err != nil {
		zeroBytes(delivery.Payload)
		fatal("recipient has no qualified adapter for the registered application target")
	}
	currentUser, err := user.Current()
	must(err)
	appAdapter, err := apptarget.NewRecipientAdapter(delivery.Target, currentUser.HomeDir, apptarget.RecipientOptions{
		OpenCodeCommand: *opencodeCommand, CodexCommand: *codexCommand, CodexHome: *codexHome,
		FIGatewaySocket: *fiGatewaySocket, FIGatewayPeerUID: fiGatewayPeerUID,
	})
	must(err)
	committer := &apptarget.TransferCommitter{Target: delivery.Target, Adapter: appAdapter}
	consumer, err := transfer.NewApplicationConsumer(journal, committer)
	must(err)
	acceptance, acceptErr := consumer.Accept(nilContext(), transfer.Delivery{OperationID: delivery.OperationID, DataKind: "api_key", Payload: delivery.Payload, Target: &delivery.Target})
	state := string(acceptance.State)
	if acceptErr != nil {
		state = "uncertain"
	} else if acceptance.State == transfer.StateRejected {
		state = "rejected"
	} else if acceptance.State != transfer.StateApplied {
		state = "uncertain"
	}
	bytes := len(delivery.Payload)
	zeroBytes(delivery.Payload)
	_, completeErr := cli.Call(ipc.MethodHandoffComplete, map[string]interface{}{
		"op_id": delivery.OperationID, "digest": delivery.PayloadDigest, "state": state, "bytes": bytes,
	})
	if completeErr != nil {
		fatal("handoff applied locally but broker receipt could not be recorded; retry with recipient handoff --complete-op OP --journal DIR --broker-socket PATH")
	}
	if acceptErr != nil || state != "applied" {
		fatal("handoff was not verified as applied")
	}
	fmt.Printf("handoff applied: %s\n", delivery.OperationID)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// nilContext returns a non-canceling context without storing request state.
func nilContext() context.Context { return context.Background() }
