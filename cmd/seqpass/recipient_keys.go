package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/secretbridge/secretbridge/internal/capsule"
)

func recipientKeysCmd(args []string) {
	if len(args) == 0 || args[0] != "generate" {
		fatal("recipient keys generate --private-key FILE --public-key FILE --receipt-private-key FILE --receipt-public-key FILE")
	}
	fs := flag.NewFlagSet("recipient keys generate", flag.ExitOnError)
	privatePath := fs.String("private-key", "", "recipient-owned HPKE private keyset path (0400)")
	publicPath := fs.String("public-key", "", "public HPKE key path for SeqPass registration")
	receiptPrivatePath := fs.String("receipt-private-key", "", "separate recipient Ed25519 receipt seed path (0400; optional pair)")
	receiptPublicPath := fs.String("receipt-public-key", "", "recipient Ed25519 receipt public key path (optional pair)")
	_ = fs.Parse(args[1:])
	if *privatePath == "" || *publicPath == "" {
		fatal("recipient keys generate requires --private-key and --public-key")
	}
	if (*receiptPrivatePath == "") != (*receiptPublicPath == "") {
		fatal("recipient receipt keys require both --receipt-private-key and --receipt-public-key")
	}
	if *receiptPrivatePath == "" {
		fatal("recipient keys generate requires separate receipt keys for sealed handoffs")
	}
	publicKey, err := capsule.GenerateRecipientKeys(*privatePath, *publicPath)
	must(err)
	fingerprint := sha256.Sum256(publicKey)
	fmt.Printf("recipient HPKE key generated; public SHA-256 %s\nprivate key: %s\npublic key: %s\n", hex.EncodeToString(fingerprint[:]), *privatePath, *publicPath)
	if *receiptPrivatePath != "" {
		receiptPublic, err := capsule.GenerateReceiptKeys(*receiptPrivatePath, *receiptPublicPath)
		must(err)
		receiptFingerprint := sha256.Sum256(receiptPublic)
		fmt.Printf("recipient receipt key generated; public SHA-256 %s\nprivate key: %s\npublic key: %s\n", hex.EncodeToString(receiptFingerprint[:]), *receiptPrivatePath, *receiptPublicPath)
	}
}
