package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/secretbridge/secretbridge/internal/transfer"
)

// The trusted recipient endpoint (objective 3). This is the process that
// actually consumes a delivered credential: it runs under its own UID, owns
// its own socket, verifies the broker's identity before reading a frame,
// validates payload/digest agreement, and commits the secret through a
// destination-specific committer.
//
// Two consumer modes are explicit and cannot be confused:
//
//	--consumer file      commit to an owner-only file store and verify the
//	                     intended effect by reading it back (production-shaped)
//	--consumer reference metadata-only fixture: journals durable acceptance
//	                     but applies nothing. Development and wire tests only.
//
// There is no mode that echoes the secret to stdout.

func recipientCmd(args []string) {
	fs := flag.NewFlagSet("recipient", flag.ExitOnError)
	sock := fs.String("socket", "", "recipient Unix socket path (required)")
	journalDir := fs.String("journal", "", "durable plaintext-free operation journal directory (required)")
	consumerDir := fs.String("consumer-dir", "", "file consumer destination directory (required for --consumer file)")
	mode := fs.String("consumer", "", "consumer mode (required): file (commits and verifies the credential) or reference (metadata-only fixture that applies nothing)")
	sockMode := fs.Uint("socket-mode", 0600, "socket permission bits (octal)")
	socketUID := fs.Int("socket-uid", 0, "socket owner UID (>0 to set; requires privilege)")
	socketGID := fs.Int("socket-gid", 0, "socket group GID (>0 to set; requires privilege)")
	trusted := fs.String("trust-broker-uid", "", "comma-separated broker UIDs permitted to connect (default: this process's UID only)")
	_ = fs.Parse(args)

	// §11: the recipient holds plaintext in memory during commit; a
	// core dump would persist it outside the journal's guards.
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not disable core dumps: %v (ensure ulimit -c 0)\n", err)
	}

	if *sock == "" || *journalDir == "" {
		fmt.Fprintln(os.Stderr, "recipient: --socket and --journal are required")
		os.Exit(2)
	}
	// The consumer must be chosen explicitly: silently defaulting to the
	// metadata-only fixture would durably journal acceptance for a
	// credential that was never applied.
	if *mode == "" {
		fmt.Fprintln(os.Stderr, "recipient: --consumer is required (file or reference); there is no default")
		os.Exit(2)
	}

	journal, err := transfer.NewOperationJournal(*journalDir)
	must(err)

	var consumer transfer.SecretConsumer
	switch *mode {
	case "file":
		if *consumerDir == "" {
			fmt.Fprintln(os.Stderr, "recipient: --consumer file requires --consumer-dir")
			os.Exit(2)
		}
		committer, err := transfer.NewFileCommitter(*consumerDir)
		must(err)
		ac, err := transfer.NewApplicationConsumer(journal, committer)
		must(err)
		consumer = ac
	case "reference":
		fmt.Fprintln(os.Stderr, "WARNING: reference consumer applies nothing; it is a fixture, not a credential destination")
		rr, err := transfer.NewReferenceRecipient(journal)
		must(err)
		consumer = rr
	default:
		fmt.Fprintf(os.Stderr, "recipient: unknown consumer mode %q\n", *mode)
		os.Exit(2)
	}

	srv, err := transfer.NewRecipientServer(transfer.RecipientServerConfig{
		SocketPath:        *sock,
		SocketMode:        os.FileMode(*sockMode),
		SocketUID:         *socketUID,
		SocketGID:         *socketGID,
		TrustedCallerUIDs: mustUIDs("trust-broker-uid", *trusted),
		Consumer:          consumer,
	})
	must(err)
	fmt.Fprintf(os.Stderr, "seqpass recipient listening on %s (consumer=%s)\n", *sock, *mode)
	srv.Serve()
}
