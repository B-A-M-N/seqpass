// capsule_issuer is a test-only issuer process for the cross-UID qualification.
// It reads a synthetic credential from stdin and emits only the signed
// recipient-encrypted envelope on stdout.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/secretbridge/secretbridge/internal/capsule"
)

func main() {
	fs := flag.NewFlagSet("capsule-issuer", flag.ExitOnError)
	privateSeed := fs.String("issuer-seed", "", "issuer-only Ed25519 seed")
	issuerKeyID := fs.String("issuer-key-id", "", "pinned issuer key ID")
	recipientPublic := fs.String("recipient-public-key", "", "registered recipient X25519 public key")
	recipientKeyID := fs.String("recipient-key-id", "", "pinned recipient key ID")
	destinationID := fs.String("destination-id", "", "registered destination ID")
	destinationRevision := fs.Int("destination-revision", 1, "registered destination revision")
	account := fs.String("account", "qual", "registered OpenCode account")
	operationID := fs.String("operation-id", "qual-operation-1", "approved operation ID")
	handoffID := fs.String("handoff-id", "qual-handoff-1", "unique handoff ID")
	age := fs.Duration("age", 0, "age issuance time to qualify expiry rejection")
	_ = fs.Parse(os.Args[1:])
	if *privateSeed == "" || *issuerKeyID == "" || *recipientPublic == "" || *recipientKeyID == "" || *destinationID == "" {
		fail("missing issuer or recipient registration")
	}
	credential, err := io.ReadAll(io.LimitReader(os.Stdin, 512*1024+1))
	if err != nil || len(credential) == 0 || len(credential) > 512*1024 {
		clear(credential)
		fail("invalid credential input")
	}
	defer clear(credential)
	issuer, err := capsule.LoadIssuerPrivate(*privateSeed)
	if err != nil {
		fail("issuer signing key unavailable")
	}
	defer clear(issuer)
	publicBytes, err := os.ReadFile(*recipientPublic)
	if err != nil || len(publicBytes) != 32 {
		clear(publicBytes)
		fail("recipient public key invalid")
	}
	public, err := capsule.RecipientPublicHandle(publicBytes)
	clear(publicBytes)
	if err != nil {
		fail("recipient public key invalid")
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-*age)
	target := capsule.Payload{
		HandoffID: *handoffID, OperationID: *operationID, DestinationID: *destinationID,
		DestinationRevision: *destinationRevision,
		TargetID:            "opencode:" + *account + ":api_key", App: "opencode", Account: *account,
		Slot: "api_key", UpdateMethod: "opencode-auth-json-v1", SourceRef: "qual/synthetic",
		SourceRevision: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute),
		Credential: credential,
	}
	envelope, err := capsule.Seal(target, *recipientKeyID, *issuerKeyID, public, issuer)
	if err != nil {
		fail("capsule sealing failed")
	}
	encoded, err := capsule.Marshal(envelope)
	if err != nil {
		fail("capsule encoding failed")
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fail("capsule output failed")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
