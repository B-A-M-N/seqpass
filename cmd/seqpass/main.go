// Command seqpass is the single native binary.
//
//	seqpass broker  - run protected credential storage, policy and operations
//	seqpass mcp     - start MCP stdio adapter for a coding harness
//	seqpass admin   - trusted operator terminal (credentials, destinations, approvals)
//	seqpass status  - local health without revealing secrets
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/secretbridge/secretbridge/internal/approval"
	"github.com/secretbridge/secretbridge/internal/capsule"
	"github.com/secretbridge/secretbridge/internal/config"
	"github.com/secretbridge/secretbridge/internal/daemon"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/isolation"
	mcpserver "github.com/secretbridge/secretbridge/internal/mcp"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/tui"
	"github.com/secretbridge/secretbridge/internal/types"
)

// defaultPaths is the single source of default endpoints, shared by every
// command so a client cannot talk to a different installation than the
// broker it was started with.
func defaultPaths() (db, sock, admin, intake string) {
	d := loadBase()
	return d.DBPath, d.SocketPath, d.AdminSocket, d.IntakeSocket
}

// loadBase resolves the installation-wide configuration (config file +
// defaults, before environment and flags). Every surface that creates or
// verifies broker-owned objects — broker, init, doctor, install — must
// consult it, because those surfaces run under different UIDs and a
// home-relative default silently splits the installation. A malformed
// configuration is a hard error: the surfaces would otherwise disagree
// about where the installation lives, which is a boundary problem.
func loadBase() config.Deployment {
	d, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "seqpass: %v\n", err)
		os.Exit(1)
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "broker":
		brokerCmd(os.Args[2:])
	case "mcp":
		mcpCmd(os.Args[2:])
	case "admin":
		adminCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "relay":
		relayCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "recipient":
		recipientCmd(os.Args[2:])
	case "tui":
		tuiCmd(os.Args[2:])
	case "doctor":
		doctorCmd(os.Args[2:])
	case "init":
		initCmd(os.Args[2:])
	case "install":
		installCmd(os.Args[2:])
	case "resolve-helper":
		// Trusted-executor-internal (P0-1): spawned by the broker per
		// approved resolve. Deliberately absent from usage(): agents have
		// no reason to invoke it, and it is not an agent surface.
		resolveHelperCmd(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "seqpass - native secret broker for coding harnesses")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault aegiskeys --aegiskeys-resolve-helper PATH --aegiskeys-resolve-helper-sha256 SHA256 [--assurance isolated] [--db PATH] [--socket PATH] [--admin-uid UID,...] [--agent-uid UID,...] [--intake-uid UID,...] [--intake-group GROUP] [--host-socket PATH] [--auto-execute]")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault relay-only --assurance isolated  # production relay service without a credential backend")
	fmt.Fprintln(os.Stderr, "  seqpass mcp [--socket PATH]   # stdio adapter; register in Codex/Claude/Hermes")
	fmt.Fprintln(os.Stderr, "  seqpass admin <catalog|pending|show|approve|reject|add-secret|add-dest|add-policy|set-policy|update-dest|execute|host-binding> ...")
	fmt.Fprintln(os.Stderr, "  seqpass relay <inbox|fulfill|status|cancel|request|credential-save> ...  # trusted human handoff (intake socket)")
	fmt.Fprintln(os.Stderr, "  seqpass agent <capabilities|request|status|cancel> ...  # generic agent adapter over the broker socket")
	fmt.Fprintln(os.Stderr, "  seqpass recipient --socket PATH --journal DIR [--consumer-dir DIR]  # trusted credential consumer endpoint")
	fmt.Fprintln(os.Stderr, "  seqpass tui [--intake-socket PATH]  # persistent native inbox TUI (own terminal, never the agent's)")
	fmt.Fprintln(os.Stderr, "  seqpass doctor [--topology]  # honest health + live isolation boundary report")
	fmt.Fprintln(os.Stderr, "  seqpass init [--vault aegiskeys] ...  # create the 0700 state dir + database, print next steps")
	fmt.Fprintln(os.Stderr, "  seqpass install opencode|pi|mcp [--print] [--out FILE] [--force]  # write the adapter's endpoint config (never credentials)")
	fmt.Fprintln(os.Stderr, "  seqpass status")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "MCP registration:")
	fmt.Fprintln(os.Stderr, "  Codex:  [mcp_servers.seqpass] command=\"/usr/local/bin/seqpass\" args=[\"mcp\"]")
	fmt.Fprintln(os.Stderr, "  Claude: claude mcp add --scope user seqpass -- /usr/local/bin/seqpass mcp")
}

func brokerCmd(args []string) {
	// §8: the broker must land on the same installation the operator and
	// the agent see, so its endpoint defaults come from the shared
	// configuration file rather than root's (or the service UID's) home.
	base := loadBase()
	fs := flag.NewFlagSet("broker", flag.ExitOnError)
	dbF := fs.String("db", base.DBPath, "SQLite path")
	sockF := fs.String("socket", base.SocketPath, "Broker socket")
	adminF := fs.String("admin-socket", base.AdminSocket, "Admin socket")
	intakeF := fs.String("intake-socket", base.IntakeSocket, "Trusted human intake socket (owner-only unless --intake-group is set)")
	recipientF := fs.String("recipient-socket", base.RecipientSocket, "optional recipient-only ticket redemption socket")
	recipientUIDs := fs.String("recipient-uid", joinUIDs(base.RecipientUIDs), "comma-separated registered application recipient UIDs")
	recipientGroup := fs.String("recipient-group", base.RecipientGroup, "optional recipient Unix group for cross-UID access")
	intakeUIDs := fs.String("intake-uid", joinUIDs(base.IntakeUIDs), "comma-separated human intake UIDs (default: admin UIDs; list agent UIDs here only for same-user best-effort mode)")
	intakeGroup := fs.String("intake-group", base.IntakeGroup, "optional trusted intake socket group; must differ from agent group and exclude agent UIDs")
	hostF := fs.String("host-socket", base.HostSocket, "optional display-only native-host adapter socket; owner-only, separate directory required")
	vaultF := fs.String("vault", base.VaultType, "required: aegiskeys|relay-only|memory-test")
	devF := fs.Bool("dev", base.Dev, "allow memory-test ephemeral vault (development only, never production)")
	autoF := fs.Bool("auto-execute", base.AutoExecute, "run trusted worker executing authorized ops without manual admin execute")
	noRelayF := fs.Bool("no-relay-auto-deliver", base.NoRelayAutoDeliver, "disable the default broker-managed relay delivery queue (F05); with it set, fulfilled relays need --auto-execute or manual admin execute")
	aegisSock := fs.String("aegiskeys-socket", base.AegisKeysSocket, "AegisKeys broker socket")
	aegisDir := fs.String("aegiskeys-dir", base.AegisKeysDir, "AegisKeys config dir")
	// P0-1: trusted credential-resolution helper (isolated deployments).
	// Operator configuration only — never agent-supplied.
	helperF := fs.String("aegiskeys-resolve-helper", base.AegisKeysResolveHelper, "trusted resolve helper executable (required for isolated AegisKeys)")
	helperHashF := fs.String("aegiskeys-resolve-helper-sha256", base.AegisKeysResolveHelperSHA256, "expected SHA-256 of the trusted resolve helper executable (required for isolated AegisKeys)")
	// P0-1 restart strategy, stable-key mode: the attest seed is read from
	// a provisioned secret file (systemd LoadCredentialEncrypted credential
	// or a root-owned 0400 file) and never persisted or logged by SeqPass.
	attestSeedF := fs.String("aegiskeys-attest-seed", "", "path to the 32-byte executor attest seed (systemd encrypted credential or root-owned 0400 file); enables the stable-key restart mode where the grant's attest_key pin survives restarts; empty = fresh key per start with rotation detection")
	handoffKeyIDF := fs.String("handoff-signing-key-id", "", "operator-pinned Ed25519 issuer identity for sealed handoff capsules")
	handoffSeedF := fs.String("handoff-signing-seed", "", "path to the separate 32-byte sealed-handoff Ed25519 seed (private 0400 file)")
	adminUIDs := fs.String("admin-uid", joinUIDs(base.AdminUIDs), "comma-separated admin UIDs (default: broker euid)")
	agentUIDs := fs.String("agent-uid", joinUIDs(base.AgentUIDs), "comma-separated approved agent UIDs (default: broker euid only)")
	sockGroup := fs.String("socket-group", base.SocketGroup, "agent Unix group owning the agent socket+dir (required for multi-user deployments)")
	opTTL := fs.Duration("default-op-ttl", base.DefaultOpTTL, "approval window for new requests (default 5m, clamped 1m-24h)")
	maxConc := fs.Int("max-concurrent-ops", base.MaxConcurrentOps, "auto-worker execution pool size (1-32)")
	assurance := fs.String("assurance", base.AssuranceMode, "topology label: empty (production default: isolated), isolated, or best-effort (development only, always reported unverified)")
	_ = fs.Parse(args)

	// F15/§11: the broker holds relay payloads in memory. A crash must
	// never write them to a core file: disable core dumps for this
	// process and every child (pinned drivers, recipients) it may spawn.
	// Best effort: an RLIMIT_CORE refusal is a startup warning, not a
	// hard failure — the deployment's own ulimit may already be 0.
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not disable core dumps: %v (ensure ulimit -c 0)\n", err)
	}

	// Explicit provider configuration (C14): no silent ephemeral vault.
	if *vaultF == "" {
		fmt.Fprintln(os.Stderr, "broker requires --vault aegiskeys or --vault relay-only (production), or --vault memory-test --dev (development only)")
		os.Exit(1)
	}
	if *vaultF == "memory-test" || *vaultF == "memory" {
		if !*devF {
			fmt.Fprintln(os.Stderr, "memory-test vault requires --dev (development only, never production credentials)")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "WARNING: ephemeral memory vault (--dev); production credentials must use --vault aegiskeys")
	}

	_ = os.MkdirAll(filepath.Dir(*dbF), 0700)
	// Objective 8: UID lists fail closed. A malformed or duplicated UID is a
	// startup error, never a silently narrowed identity set.
	intakeUIDList := mustUIDs("intake-uid", *intakeUIDs)
	recipientUIDList := mustUIDs("recipient-uid", *recipientUIDs)
	adminUIDList := mustUIDs("admin-uid", *adminUIDs)
	agentUIDList := mustUIDs("agent-uid", *agentUIDs)
	d, err := daemon.New(daemon.Config{
		AssuranceMode:   *assurance,
		DBPath:          *dbF,
		VaultType:       *vaultF,
		SocketPath:      *sockF,
		AdminSocket:     *adminF,
		IntakeSocket:    *intakeF,
		RecipientSocket: *recipientF,
		RecipientUIDs:   recipientUIDList,
		RecipientGroup:  *recipientGroup,
		HostSocket:      *hostF,
		IntakeUIDs:      intakeUIDList,
		AdminUIDs:       adminUIDList,
		AgentUIDs:       agentUIDList, SocketGroup: *sockGroup, AegisKeysSocket: *aegisSock,
		IntakeGroup:                  *intakeGroup,
		NoRelayAutoDeliver:           *noRelayF,
		AegisKeysDir:                 *aegisDir,
		AegisKeysResolveHelper:       *helperF,
		AegisKeysResolveHelperSHA256: *helperHashF,
		AegisKeysAttestSeedPath:      *attestSeedF,
		HandoffSigningKeyID:          *handoffKeyIDF,
		HandoffSigningSeedPath:       *handoffSeedF,
		AutoExecute:                  *autoF,
		DefaultOpTTL:                 *opTTL,
		MaxConcurrentOps:             *maxConc,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "broker failed: %v\n", err)
		os.Exit(1)
	}
	label := daemon.AssuranceLabel(d.AssuranceMode())
	if *assurance == "" {
		label += " (default)"
	}
	fmt.Fprintf(os.Stderr, "seqpass broker uid=%d assurance=%s (%s) on %s (admin %s admin-uids=%v agent-uids=%v op-ttl=%s max-concurrent-ops=%d)\n", os.Geteuid(), d.AssuranceMode(), label, *sockF, *adminF, adminUIDList, agentUIDList, (*opTTL).String(), *maxConc)
	if err := d.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "broker error: %v\n", err)
		os.Exit(1)
	}
}

func mcpCmd(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	_, sock, _, _ := defaultPaths()
	sockF := fs.String("socket", sock, "Broker socket")
	_ = fs.Parse(args)
	if env := config.EnvEndpoint(config.EnvSocket); env != "" {
		*sockF = env
	}
	srv := mcpserver.NewServer(*sockF)
	// Exits when the harness closes stdio; broker keeps running.
	if err := srv.StartStdio(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
		os.Exit(1)
	}
}

func adminSock() string {
	if env := config.EnvEndpoint(config.EnvAdminSocket); env != "" {
		return env
	}
	_, _, admin, _ := defaultPaths()
	return admin
}

func adminClient() *ipc.Client {
	cli, err := ipc.Dial(adminSock())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach broker admin socket %s: %v\nIs `seqpass broker` running?\n", adminSock(), err)
		os.Exit(1)
	}
	return cli
}

func adminCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "admin subcommands: catalog|pending|show|approve|reject|verify|recipient-status|add-secret|stage-secret|add-dest|execute|host-binding")
		os.Exit(1)
	}
	if args[0] == "handoff-issuer-keygen" {
		fs := flag.NewFlagSet("admin handoff-issuer-keygen", flag.ExitOnError)
		privatePath := fs.String("private-seed", "", "broker-owned Ed25519 seed path (0400), separate from AegisKeys attest key")
		publicPath := fs.String("public-key", "", "issuer public key file to provision out-of-band to recipients")
		_ = fs.Parse(args[1:])
		if *privatePath == "" || *publicPath == "" {
			fatal("admin handoff-issuer-keygen --private-seed FILE --public-key FILE")
		}
		publicKey, err := capsule.GenerateIssuerKeys(*privatePath, *publicPath)
		must(err)
		fingerprint := sha256.Sum256(publicKey)
		fmt.Printf("handoff issuer key generated; public SHA-256 %s\nprivate seed: %s\npublic key: %s\n", hex.EncodeToString(fingerprint[:]), *privatePath, *publicPath)
		return
	}
	cli := adminClient()
	defer cli.Close()
	switch args[0] {
	case "catalog":
		data, err := cli.Call(ipc.MethodCatalog, nil)
		must(err)
		printJSON(data)
	case "pending":
		data, err := cli.Call(ipc.MethodOpsPending, nil)
		must(err)
		// Render trusted-terminal approval prompts (references only, no secrets).
		raw, _ := json.Marshal(data)
		var pending struct {
			Uses      []*types.UseRequest      `json:"uses"`
			Transfers []*types.TransferRequest `json:"transfers"`
		}
		_ = json.Unmarshal(raw, &pending)
		// Ready view (G03) is fetched regardless: authorized work must
		// stay visible even when nothing awaits approval.
		ready, err := cli.Call(ipc.MethodOpsReady, nil)
		must(err)
		rawReady, _ := json.Marshal(ready)
		var readyOps struct {
			Uses      []*types.UseRequest      `json:"uses"`
			Transfers []*types.TransferRequest `json:"transfers"`
		}
		_ = json.Unmarshal(rawReady, &readyOps)
		if len(pending.Uses) == 0 && len(pending.Transfers) == 0 &&
			len(readyOps.Uses) == 0 && len(readyOps.Transfers) == 0 {
			fmt.Println("No pending operations.")
			return
		}
		for _, u := range pending.Uses {
			fmt.Println(approval.FormatUse(u))
			fmt.Println("---")
		}
		for _, t := range pending.Transfers {
			fmt.Println(approval.FormatTransfer(t))
			fmt.Println("---")
		}
		if len(readyOps.Uses) > 0 || len(readyOps.Transfers) > 0 {
			fmt.Println("READY (authorized, awaiting execution — admin execute):")
			for _, u := range readyOps.Uses {
				fmt.Println(approval.FormatUse(u))
				fmt.Println("---")
			}
			for _, t := range readyOps.Transfers {
				fmt.Println(approval.FormatTransfer(t))
				fmt.Println("---")
			}
		}
	case "show":
		fs := flag.NewFlagSet("show", flag.ExitOnError)
		typ := fs.String("type", "use", "use|transfer")
		id := fs.String("id", "", "operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("show --type use|transfer --id ID")
		}
		data, err := cli.Call(ipc.MethodOpShow, map[string]interface{}{"op_type": *typ, "op_id": *id})
		must(err)
		printJSON(data)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		typ := fs.String("type", "use", "use|transfer")
		id := fs.String("id", "", "operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("verify --type use|transfer --id ID")
		}
		// Independent postcondition check (SC-14): observes resulting
		// state separately from execution; never rewrites the receipt.
		vdata, err := cli.Call(ipc.MethodVerifyOutcome, map[string]interface{}{"op_type": *typ, "op_id": *id})
		must(err)
		printJSON(vdata)
	case "recipient-status":
		fs := flag.NewFlagSet("recipient-status", flag.ExitOnError)
		id := fs.String("id", "", "transfer operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("recipient-status --id OPID")
		}
		// Reconciliation readback (CV-10): asks the recipient what
		// happened to one transfer — unknown | received |
		// durably_accepted | applied | rejected. Tells accepted data
		// apart from applied data after an uncertain delivery.
		data, err := cli.Call(ipc.MethodRecipientStatus, map[string]interface{}{"op_id": *id})
		must(err)
		printJSON(data)
	case "approve":
		fs := flag.NewFlagSet("approve", flag.ExitOnError)
		typ := fs.String("type", "use", "use|transfer")
		id := fs.String("id", "", "operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("approve --type use|transfer --id ID")
		}
		// Reviewed-intent binding (SC-02): display the exact canonical
		// envelope first, then approve with compare-and-swap on the
		// reviewed revision. Any concurrent change fails closed.
		reviewed, err := cli.Call(ipc.MethodOpShow, map[string]interface{}{"op_type": *typ, "op_id": *id})
		must(err)
		printJSON(reviewed)
		rev := -1
		if m, ok := reviewed.(map[string]interface{}); ok {
			if f, ok := m["revision"].(float64); ok {
				rev = int(f)
			}
		}
		fmt.Printf("reviewed revision=%d digest=%v epoch=%v; approving exactly this artifact\n", rev, fieldOf(reviewed, "op_hash"), fieldOf(reviewed, "auth_epoch"))
		method := ipc.MethodApproveUse
		if *typ == "transfer" {
			method = ipc.MethodApproveTransfer
		}
		_, err = cli.Call(method, map[string]interface{}{"op_id": *id, "expect_revision": rev})
		must(err)
		fmt.Println("authorized:", *id)
	case "reject":
		fs := flag.NewFlagSet("reject", flag.ExitOnError)
		typ := fs.String("type", "use", "use|transfer")
		id := fs.String("id", "", "operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("reject --type use|transfer --id ID")
		}
		method := ipc.MethodRejectUse
		if *typ == "transfer" {
			method = ipc.MethodRejectTransfer
		}
		_, err := cli.Call(method, map[string]interface{}{"op_id": *id})
		must(err)
		fmt.Println("rejected:", *id)
	case "add-secret":
		fs := flag.NewFlagSet("add-secret", flag.ExitOnError)
		name := fs.String("name", "", "reference name")
		desc := fs.String("desc", "", "description")
		binding := fs.String("binding", "", "AegisKeys binding (authoritative store)")
		_ = fs.Parse(args[1:])
		if *name == "" {
			fatal("add-secret --name NAME [--binding aegis/binding]")
		}
		data, err := cli.Call(ipc.MethodSecretAdd, map[string]interface{}{"name": *name, "description": *desc, "binding": *binding})
		must(err)
		printJSON(data)
	case "stage-secret":
		// Bounded trusted intake from the operator terminal (SC-08):
		// reads the payload from a file (never the shell history),
		// admin socket only, dev-mode spool only.
		fs := flag.NewFlagSet("stage-secret", flag.ExitOnError)
		ref := fs.String("ref", "", "unbound secret ref ID")
		file := fs.String("file", "", "payload file (max 64 KiB)")
		_ = fs.Parse(args[1:])
		if *ref == "" || *file == "" {
			fatal("stage-secret --ref REF --file PATH")
		}
		payload, err := os.ReadFile(*file)
		must(err)
		_, err = cli.Call(ipc.MethodSecretStage, map[string]interface{}{
			"ref_id": *ref, "payload_b64": base64.StdEncoding.EncodeToString(payload),
		})
		must(err)
		fmt.Println("staged:", *ref)
	case "add-dest":
		fs := flag.NewFlagSet("add-dest", flag.ExitOnError)
		name := fs.String("name", "", "name")
		typ := fs.String("type", "recipient-socket", "recipient-socket | sealed-capsule | http-pinned | process-pinned | git-pinned")
		ep := fs.String("endpoint", "", "recipient-socket: unix socket path; http-pinned: pinned origin (https://host[:port]); process-pinned: absolute executable path; git-pinned: pinned git remote URL (https://host[:port]/path.git)")
		src := fs.String("source-repo", "", "git-pinned only: absolute source repository path to pin for git.push (pushed content is a registration fact, never an agent parameter)")
		handoffMode := fs.String("handoff-mode", "direct-socket", "direct-socket|recipient-pull|sealed-capsule")
		recipientKeyID := fs.String("recipient-key-id", "", "sealed-capsule recipient public-key identity")
		recipientKeyFile := fs.String("recipient-public-key", "", "sealed-capsule raw 32-byte X25519 public key file")
		receiptKeyID := fs.String("receipt-key-id", "", "recipient Ed25519 receipt key identity")
		receiptKeyFile := fs.String("receipt-public-key", "", "raw 32-byte recipient Ed25519 receipt public key file")
		issuerKeyID := fs.String("issuer-key-id", "", "out-of-band pinned issuer signing key identity")
		issuerPublicFile := fs.String("issuer-public-key", "", "raw 32-byte Ed25519 issuer public key file")
		app := fs.String("app", "", "sealed-capsule target app ID")
		appProvider := fs.String("app-provider", "", "FI Gateway target upstream provider ID")
		account := fs.String("account", "", "sealed-capsule target account ID")
		slot := fs.String("slot", "", "sealed-capsule target credential slot")
		updateMethod := fs.String("update-method", "", "sealed-capsule target adapter method")
		sourceRef := fs.String("source-ref", "", "sealed-capsule pinned credential source ID")
		sourceRevision := fs.Int("source-revision", 0, "sealed-capsule pinned credential source revision")
		activation := fs.String("activation", "", "sealed-capsule target activation policy")
		expectUID := fs.Int("expect-uid", -1, "pinned trusted recipient UID (required for recipient handoffs)")
		expectGID := fs.Int("expect-gid", -1, "pinned recipient GID (optional, socket recipients only)")
		_ = fs.Parse(args[1:])
		params := map[string]interface{}{"name": *name, "type": *typ, "endpoint": *ep, "handoff_mode": *handoffMode}
		if *handoffMode == "recipient-pull" || *handoffMode == "sealed-capsule" {
			if *app == "" || *account == "" || *slot == "" || *updateMethod == "" || *sourceRef == "" || *sourceRevision <= 0 {
				fatal("recipient handoff requires --app APP --account ACCOUNT --slot SLOT --update-method METHOD --source-ref REF --source-revision N")
			}
			targetID := *app + ":" + *account + ":" + *slot
			target := map[string]interface{}{"id": targetID, "app": *app, "account": *account, "slot": *slot, "update_method": *updateMethod, "source_ref": *sourceRef, "source_revision": *sourceRevision, "activation": *activation}
			if *app == "fi-gateway" {
				if *appProvider == "" || *slot != "api_key" {
					fatal("FI Gateway targets require --app-provider PROVIDER and --slot api_key")
				}
				target["provider"] = *appProvider
				target["id"] = "fi-gateway:" + *appProvider + ":" + *account + ":api_key"
			}
			params["credential_target"] = target
		}
		if *handoffMode == "sealed-capsule" {
			if *recipientKeyID == "" || *recipientKeyFile == "" || *receiptKeyID == "" || *receiptKeyFile == "" || *issuerKeyID == "" || *issuerPublicFile == "" {
				fatal("sealed-capsule requires recipient HPKE, recipient receipt, and issuer key IDs and public-key files")
			}
			publicKey, err := os.ReadFile(*recipientKeyFile)
			must(err)
			if len(publicKey) != 32 {
				fatal("recipient public key must be a raw 32-byte X25519 key")
			}
			params["recipient_key_id"] = *recipientKeyID
			params["recipient_public_key_b64"] = base64.StdEncoding.EncodeToString(publicKey)
			receiptPublic, err := os.ReadFile(*receiptKeyFile)
			must(err)
			if len(receiptPublic) != 32 {
				fatal("recipient receipt public key must be a raw 32-byte Ed25519 key")
			}
			params["receipt_key_id"] = *receiptKeyID
			params["receipt_public_key_b64"] = base64.StdEncoding.EncodeToString(receiptPublic)
			params["issuer_key_id"] = *issuerKeyID
			issuerPublic, err := os.ReadFile(*issuerPublicFile)
			must(err)
			if len(issuerPublic) != 32 {
				fatal("issuer public key must be a raw 32-byte Ed25519 key")
			}
			params["issuer_public_key_b64"] = base64.StdEncoding.EncodeToString(issuerPublic)
		}
		switch *typ {
		case "recipient-socket":
			if *name == "" || *ep == "" || *expectUID < 0 {
				fatal("add-dest --name N --type recipient-socket --endpoint SOCK --expect-uid UID [--expect-gid GID]")
			}
			params["expected_uid"] = *expectUID
			if *expectGID >= 0 {
				params["expected_gid"] = *expectGID
			}
		case "sealed-capsule":
			if *name == "" || *expectUID < 0 {
				fatal("add-dest --name N --type sealed-capsule --expect-uid UID --handoff-mode sealed-capsule")
			}
			params["expected_uid"] = *expectUID
		case "http-pinned":
			if *name == "" || *ep == "" {
				fatal("add-dest --name N --type http-pinned --endpoint https://host[:port]")
			}
		case "process-pinned":
			if *name == "" || *ep == "" {
				fatal("add-dest --name N --type process-pinned --endpoint /absolute/executable (pin fixed flags with a wrapper script)")
			}
		case "git-pinned":
			if *name == "" || *ep == "" {
				fatal("add-dest --name N --type git-pinned --endpoint https://host[:port]/path.git (remote pinned at registration; agents only choose the branch) [--source-repo /abs/repo to pin the push source]")
			}
			if *src != "" {
				params["source_repo"] = *src
			}
		default:
			fatal("add-dest: unsupported type " + *typ)
		}
		data, err := cli.Call(ipc.MethodDestAdd, params)
		must(err)
		printJSON(data)
	case "add-policy":
		fs := flag.NewFlagSet("add-policy", flag.ExitOnError)
		name := fs.String("name", "", "policy name")
		rules := fs.String("rules", "", `rules JSON, e.g. '[{"principal":"uid:1000","secret_refs":["<ref>"],"ops":["transfer"],"dest_ids":["*"]}]'`)
		_ = fs.Parse(args[1:])
		if *name == "" || *rules == "" {
			fatal("add-policy --name N --rules JSON")
		}
		data, err := cli.Call(ipc.MethodPolicyAdd, map[string]interface{}{"name": *name, "rules": *rules})
		must(err)
		printJSON(data)
	case "set-policy":
		fs := flag.NewFlagSet("set-policy", flag.ExitOnError)
		id := fs.String("id", "", "policy ID")
		en := fs.String("enabled", "", "true|false")
		_ = fs.Parse(args[1:])
		if *id == "" || (*en != "true" && *en != "false") {
			fatal("set-policy --id ID --enabled true|false (bumps epoch, revokes outstanding approvals)")
		}
		_, err := cli.Call(ipc.MethodPolicySet, map[string]interface{}{"id": *id, "enabled": *en == "true"})
		must(err)
		fmt.Println("policy updated:", *id)
	case "update-dest":
		fs := flag.NewFlagSet("update-dest", flag.ExitOnError)
		id := fs.String("id", "", "destination ID")
		ep := fs.String("endpoint", "", "new recipient socket path")
		expectUID := fs.Int("expect-uid", -1, "re-pin recipient UID")
		expectGID := fs.Int("expect-gid", -1, "re-pin recipient GID")
		handoffMode := fs.String("handoff-mode", "", "direct-socket|recipient-pull|sealed-capsule (rotates target/key and invalidates approvals)")
		recipientKeyID := fs.String("recipient-key-id", "", "new sealed-capsule recipient key ID")
		recipientKeyFile := fs.String("recipient-public-key", "", "new raw 32-byte X25519 public-key file")
		receiptKeyID := fs.String("receipt-key-id", "", "new recipient Ed25519 receipt key ID")
		receiptKeyFile := fs.String("receipt-public-key", "", "new raw 32-byte recipient Ed25519 receipt public-key file")
		issuerKeyID := fs.String("issuer-key-id", "", "new sealed-capsule issuer key ID")
		issuerPublicFile := fs.String("issuer-public-key", "", "new raw 32-byte Ed25519 issuer public-key file")
		app := fs.String("app", "", "registered target app ID")
		appProvider := fs.String("app-provider", "", "FI Gateway target upstream provider ID")
		account := fs.String("account", "", "registered target account ID")
		slot := fs.String("slot", "", "registered target credential slot")
		updateMethod := fs.String("update-method", "", "registered target adapter method")
		sourceRef := fs.String("source-ref", "", "registered source reference")
		sourceRevision := fs.Int("source-revision", 0, "registered source revision")
		activation := fs.String("activation", "", "registered target activation policy")
		_ = fs.Parse(args[1:])
		if *id == "" || (*ep == "" && *handoffMode == "") {
			fatal("update-dest --id ID (--endpoint SOCK | --handoff-mode MODE ...)")
		}
		params := map[string]interface{}{"id": *id}
		if *ep != "" {
			params["endpoint"] = *ep
		}
		if *expectUID >= 0 {
			params["expected_uid"] = *expectUID
		}
		if *expectGID >= 0 {
			params["expected_gid"] = *expectGID
		}
		if *handoffMode != "" {
			params["handoff_mode"] = *handoffMode
			if *handoffMode == "recipient-pull" || *handoffMode == "sealed-capsule" {
				if *app == "" || *account == "" || *slot == "" || *updateMethod == "" || *sourceRef == "" || *sourceRevision <= 0 {
					fatal("recipient handoff update requires --app --account --slot --update-method --source-ref --source-revision")
				}
				targetID := *app + ":" + *account + ":" + *slot
				target := map[string]interface{}{"id": targetID, "app": *app, "account": *account, "slot": *slot, "update_method": *updateMethod, "source_ref": *sourceRef, "source_revision": *sourceRevision, "activation": *activation}
				if *app == "fi-gateway" {
					if *appProvider == "" || *slot != "api_key" {
						fatal("FI Gateway targets require --app-provider PROVIDER and --slot api_key")
					}
					target["provider"] = *appProvider
					target["id"] = "fi-gateway:" + *appProvider + ":" + *account + ":api_key"
				}
				params["credential_target"] = target
			}
			if *handoffMode == "sealed-capsule" {
				if *recipientKeyID == "" || *recipientKeyFile == "" || *receiptKeyID == "" || *receiptKeyFile == "" || *issuerKeyID == "" || *issuerPublicFile == "" {
					fatal("sealed-capsule rotation requires recipient HPKE, recipient receipt, and issuer key IDs and public-key files")
				}
				pub, err := os.ReadFile(*recipientKeyFile)
				must(err)
				if len(pub) != 32 {
					fatal("recipient public key must be a raw 32-byte X25519 key")
				}
				params["recipient_key_id"] = *recipientKeyID
				params["recipient_public_key_b64"] = base64.StdEncoding.EncodeToString(pub)
				receiptPublic, err := os.ReadFile(*receiptKeyFile)
				must(err)
				if len(receiptPublic) != 32 {
					fatal("recipient receipt public key must be a raw 32-byte Ed25519 key")
				}
				params["receipt_key_id"] = *receiptKeyID
				params["receipt_public_key_b64"] = base64.StdEncoding.EncodeToString(receiptPublic)
				params["issuer_key_id"] = *issuerKeyID
				issuerPublic, err := os.ReadFile(*issuerPublicFile)
				must(err)
				if len(issuerPublic) != 32 {
					fatal("issuer public key must be a raw 32-byte Ed25519 key")
				}
				params["issuer_public_key_b64"] = base64.StdEncoding.EncodeToString(issuerPublic)
			}
		}
		_, err := cli.Call(ipc.MethodDestUpdate, params)
		must(err)
		fmt.Println("destination updated:", *id)
	case "execute":
		// Operator-triggered execution of an authorized op (broker claims atomically).
		fs := flag.NewFlagSet("execute", flag.ExitOnError)
		typ := fs.String("type", "use", "use|transfer")
		id := fs.String("id", "", "operation ID")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal("execute --type use|transfer --id ID")
		}
		method := ipc.MethodExecuteUse
		if *typ == "transfer" {
			method = ipc.MethodExecuteTransfer
		}
		data, err := cli.Call(method, map[string]interface{}{"op_id": *id})
		must(err)
		printJSON(data)
	case "host-binding":
		hostBindingCmd(args[1:], cli)
	default:
		fmt.Fprintln(os.Stderr, "unknown admin subcommand:", args[0])
		os.Exit(1)
	}
}

// hostBindingCmd provisions, inspects, renews, and revokes trusted
// human-to-agent host principal bindings via the admin socket (SP-02).
func hostBindingCmd(args []string, cli *ipc.Client) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "host-binding subcommands: create|inspect|renew|revoke")
		fmt.Fprintln(os.Stderr, "  create --human UID --agent UID --kind KIND --ttl-seconds SECONDS")
		fmt.Fprintln(os.Stderr, "  inspect --human UID --kind KIND")
		fmt.Fprintln(os.Stderr, "  renew   --human UID --agent UID --kind KIND --ttl-seconds SECONDS")
		fmt.Fprintln(os.Stderr, "  revoke  --human UID --agent UID --kind KIND")
		os.Exit(1)
	}
	action := args[0]
	fs := flag.NewFlagSet("host-binding "+action, flag.ExitOnError)
	human := fs.String("human", "", "trusted human principal (e.g. uid:1000)")
	agent := fs.String("agent", "", "approved agent principal (e.g. uid:2001)")
	kind := fs.String("kind", "", "host kind (e.g. codex, opencode)")
	ttl := fs.Int("ttl-seconds", 0, "binding TTL in seconds (required for create/renew)")
	_ = fs.Parse(args[1:])
	params := map[string]interface{}{"action": action, "host_kind": *kind}
	if *human != "" {
		params["human_principal"] = *human
	}
	if *agent != "" {
		params["agent_principal"] = *agent
	}
	if *ttl > 0 {
		params["ttl_seconds"] = uint64(*ttl)
	}
	data, err := cli.Call(ipc.MethodHostBindingCreate, params)
	must(err)
	printJSON(data)
}

func statusCmd(args []string) {
	_ = args
	sock := config.EnvEndpoint(config.EnvSocket)
	if sock == "" {
		_, sock, _, _ = defaultPaths()
	}
	cli, err := ipc.Dial(sock)
	if err != nil {
		fmt.Println("broker: unreachable (is `seqpass broker` running?)")
		os.Exit(1)
	}
	defer cli.Close()
	data, err := cli.Call(ipc.MethodHealth, nil)
	if err != nil {
		fmt.Println("broker: error:", err)
		os.Exit(1)
	}
	printJSON(data)
	_ = service.Config{}
}

// tuiCmd launches the persistent native inbox TUI (F06). It must run in
// the operator's own terminal session — never launched by the agent
// inside its instrumented terminal.
func tuiCmd(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	_, _, _, di := defaultPaths()
	if env := config.EnvEndpoint(config.EnvIntakeSocket); env != "" {
		di = env
	}
	intakeF := fs.String("intake-socket", di, "Broker intake socket")
	_ = fs.Parse(args)
	// §11: the TUI transiently holds the user's credential during entry;
	// a core dump would persist it in terminal-adjacent crash output.
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not disable core dumps: %v (ensure ulimit -c 0)\n", err)
	}
	if err := runTUI(*intakeF); err != nil {
		var ie *tui.InterruptError
		if errors.As(err, &ie) {
			// The terminal has already been restored; report the
			// conventional 128+signal status so a shell can tell an
			// interruption from a failure.
			os.Exit(128 + int(ie.Signal))
		}
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}

func runTUI(intakeSock string) error {
	return tui.Run(tui.Config{IntakeSocket: intakeSock})
}

// doctorCmd reports the honest state of an installation. Without --topology
// it asks a running broker; with --topology it evaluates the configured
// boundary live, before anything is started.
func doctorCmd(args []string) {
	// §8: consult the installation-wide configuration file so the doctor
	// evaluates the same endpoints the broker and the operator use, even
	// when it runs under a different UID.
	base := loadBase()
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	sock, admin, intake := base.SocketPath, base.AdminSocket, base.IntakeSocket
	topology := fs.Bool("topology", false, "evaluate the configured topology live instead of asking a running broker")
	requireVerified := fs.Bool("require-verified", false, "exit non-zero unless the boundary is verified")
	sockF := fs.String("socket", sock, "broker socket")
	adminF := fs.String("admin-socket", admin, "admin socket")
	intakeF := fs.String("intake-socket", intake, "trusted intake socket")
	recipientF := fs.String("recipient-socket", base.RecipientSocket, "optional recipient-only handoff socket")
	recipientUIDsF := fs.String("recipient-uid", joinUIDs(base.RecipientUIDs), "registered application recipient UIDs")
	recipientGroupF := fs.String("recipient-group", base.RecipientGroup, "recipient Unix socket group")
	dbF := fs.String("db", base.DBPath, "database path")
	vaultF := fs.String("vault", base.VaultType, "vault type: aegiskeys|relay-only|memory-test")
	devF := fs.Bool("dev", base.Dev, "memory-test vault acknowledgement (development only)")
	assuranceF := fs.String("assurance", base.AssuranceMode, "topology claim: isolated|best-effort (default: derived from the vault)")
	agentUIDsF := fs.String("agent-uid", joinUIDs(base.AgentUIDs), "comma-separated approved agent UIDs")
	adminUIDsF := fs.String("admin-uid", joinUIDs(base.AdminUIDs), "comma-separated admin UIDs")
	intakeUIDsF := fs.String("intake-uid", joinUIDs(base.IntakeUIDs), "comma-separated trusted intake UIDs")
	groupF := fs.String("socket-group", base.SocketGroup, "agent socket group")
	intakeGroupF := fs.String("intake-group", base.IntakeGroup, "trusted intake socket group")
	hostF := fs.String("host-socket", base.HostSocket, "display-only native-host adapter socket")
	aegisSock := fs.String("aegiskeys-socket", base.AegisKeysSocket, "AegisKeys broker socket")
	aegisDir := fs.String("aegiskeys-dir", base.AegisKeysDir, "AegisKeys config dir")
	helperF := fs.String("aegiskeys-resolve-helper", base.AegisKeysResolveHelper, "trusted resolve helper executable")
	helperHashF := fs.String("aegiskeys-resolve-helper-sha256", base.AegisKeysResolveHelperSHA256, "trusted resolve helper SHA-256 pin")
	_ = fs.Parse(args)

	if !*topology {
		cli, err := ipc.Dial(*sockF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "doctor: broker unreachable at %s: %v\n", *sockF, err)
			os.Exit(1)
		}
		defer cli.Close()
		data, err := cli.Call(ipc.MethodHealth, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "doctor: health call failed: %v\n", err)
			os.Exit(1)
		}
		printJSON(data)
		// A running broker's own health is the honest source. Only the
		// explicit requirement turns an unverified label into a failure,
		// because best-effort is unverified by design.
		if *requireVerified && !healthVerified(data) {
			fmt.Fprintln(os.Stderr, "doctor: boundary is not verified")
			os.Exit(1)
		}
		return
	}

	db := base.DBPath
	if *dbF != "" {
		db = *dbF
	}
	d := base
	d.DBPath = db
	d.SocketPath = *sockF
	d.AdminSocket = *adminF
	d.IntakeSocket = *intakeF
	d.RecipientSocket = *recipientF
	d.RecipientUIDs = mustUIDs("recipient-uid", *recipientUIDsF)
	d.RecipientGroup = *recipientGroupF
	d.HostSocket = *hostF
	d.VaultType = *vaultF
	d.Dev = *devF
	d.AssuranceMode = *assuranceF
	d.SocketGroup = *groupF
	d.IntakeGroup = *intakeGroupF
	d.AegisKeysSocket = *aegisSock
	d.AegisKeysDir = *aegisDir
	d.AegisKeysResolveHelper = *helperF
	d.AegisKeysResolveHelperSHA256 = *helperHashF
	d.AgentUIDs = mustUIDs("agent-uid", *agentUIDsF)
	d.AdminUIDs = mustUIDs("admin-uid", *adminUIDsF)
	d.IntakeUIDs = mustUIDs("intake-uid", *intakeUIDsF)

	if err := d.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "doctor: configuration is not usable: %v\n", err)
		os.Exit(2)
	}
	// BrokerPID is 0 and the check is a preflight: this is before the broker
	// starts, so there is no process to inspect and the objects it will
	// create do not exist yet. The report says so rather than pretending
	// those checks passed.
	rep, err := isolation.Doctor(d.IsolationPreflight())
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: cannot evaluate the topology: %v\n", err)
		os.Exit(2)
	}
	printJSON(rep)

	// A preflight verdict is "nothing is provably wrong", never "verified":
	// the broker is not serving, so the process boundary could not be
	// inspected. Exit non-zero only for a real problem, or when the caller
	// explicitly demanded a verified boundary that only a running broker can
	// demonstrate.
	if rep.AnyFailed() {
		fmt.Fprintf(os.Stderr, "doctor: the topology would not satisfy the %s claim: %s\n", d.EffectiveAssurance(), strings.Join(rep.FailedNames(), ", "))
		os.Exit(1)
	}
	if *requireVerified {
		fmt.Fprintln(os.Stderr, "doctor: --require-verified cannot be satisfied by a preflight check; query the running broker (drop --topology)")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "doctor: preflight found no boundary problem for the %s claim; the running broker must confirm it\n", d.EffectiveAssurance())
}

// healthVerified reports whether a broker health response carries the
// verified assurance label. Anything else, including a missing field, is
// unverified: absence of evidence is not evidence of a boundary.
func healthVerified(data interface{}) bool {
	m, ok := data.(map[string]interface{})
	if !ok {
		return false
	}
	label, _ := m["assurance"].(string)
	return label == "verified"
}

// initCmd creates the installation's state directory and database with
// restrictive permissions, then prints the exact command to start the
// broker. It never generates, stores or prints a credential.
//
// With --out it also writes the installation-wide configuration file
// (endpoints, vault type, UID lists — never secrets), so the broker, the
// doctor and `seqpass install` can resolve the installation identically
// from any UID. When running as root, /etc/seqpass/config.json is the
// default target.
func initCmd(args []string) {
	base := loadBase()
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dbF := fs.String("db", base.DBPath, "database path")
	sockF := fs.String("socket", base.SocketPath, "agent broker socket")
	adminF := fs.String("admin-socket", base.AdminSocket, "admin socket")
	intakeF := fs.String("intake-socket", base.IntakeSocket, "trusted intake socket")
	recipientF := fs.String("recipient-socket", base.RecipientSocket, "optional recipient-only handoff socket")
	recipientUIDsF := fs.String("recipient-uid", joinUIDs(base.RecipientUIDs), "registered application recipient UIDs")
	recipientGroupF := fs.String("recipient-group", base.RecipientGroup, "recipient Unix socket group")
	vaultF := fs.String("vault", config.VaultAegisKeys, "vault type: aegiskeys or relay-only (production), or memory-test (development, requires --dev)")
	devF := fs.Bool("dev", base.Dev, "development-only acknowledgement for the memory-test vault")
	assuranceF := fs.String("assurance", base.AssuranceMode, "topology claim: isolated|best-effort (default: derived from the vault)")
	agentUIDsF := fs.String("agent-uid", joinUIDs(base.AgentUIDs), "comma-separated approved agent UIDs (required for a production vault)")
	adminUIDsF := fs.String("admin-uid", joinUIDs(base.AdminUIDs), "comma-separated admin UIDs")
	intakeUIDsF := fs.String("intake-uid", joinUIDs(base.IntakeUIDs), "comma-separated trusted intake UIDs")
	groupF := fs.String("socket-group", base.SocketGroup, "agent socket group (required for a production vault)")
	aegisSockF := fs.String("aegiskeys-socket", base.AegisKeysSocket, "AegisKeys broker socket")
	aegisDirF := fs.String("aegiskeys-dir", base.AegisKeysDir, "AegisKeys config directory")
	helperF := fs.String("aegiskeys-resolve-helper", base.AegisKeysResolveHelper, "trusted resolve helper executable (required for an AegisKeys production vault)")
	helperHashF := fs.String("aegiskeys-resolve-helper-sha256", base.AegisKeysResolveHelperSHA256, "SHA-256 identity pin for the AegisKeys resolve helper")
	outF := fs.String("out", "", "write the installation-wide config file here (default: /etc/seqpass/config.json when running as root)")
	forceF := fs.Bool("force", false, "overwrite an existing, differing config file")
	_ = fs.Parse(args)

	d := base
	d.DBPath = *dbF
	d.SocketPath = *sockF
	d.AdminSocket = *adminF
	d.IntakeSocket = *intakeF
	d.RecipientSocket = *recipientF
	d.RecipientUIDs = mustUIDs("recipient-uid", *recipientUIDsF)
	d.RecipientGroup = *recipientGroupF
	d.VaultType = *vaultF
	d.Dev = *devF
	d.AssuranceMode = *assuranceF
	d.SocketGroup = *groupF
	d.AegisKeysSocket = *aegisSockF
	d.AegisKeysDir = *aegisDirF
	d.AegisKeysResolveHelper = *helperF
	d.AegisKeysResolveHelperSHA256 = *helperHashF
	d.AgentUIDs = mustUIDs("agent-uid", *agentUIDsF)
	d.AdminUIDs = mustUIDs("admin-uid", *adminUIDsF)
	d.IntakeUIDs = mustUIDs("intake-uid", *intakeUIDsF)
	if err := d.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(2)
	}

	// §8: generate the installation-wide configuration. It carries only
	// endpoints, the vault type and UID lists; secrets live in the vault
	// and tokens are minted at runtime, so this file is safe to read.
	if out := *outF; out != "" || os.Geteuid() == 0 {
		target := out
		if target == "" {
			target = config.SystemConfigPath
		}
		writeInstallConfig(target, d, *forceF)
	}

	dir := d.StateDir()
	// The state directory holds the database and the sockets. It must not be
	// group- or world-accessible: the broker refuses untrusted ancestors, and
	// a world-writable parent would let another identity replace a socket.
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot create %s: %v\n", dir, err)
		os.Exit(1)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot restrict %s: %v\n", dir, err)
		os.Exit(1)
	}
	if fi, err := os.Stat(dir); err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot inspect %s: %v\n", dir, err)
		os.Exit(1)
	} else if fi.Mode().Perm()&0077 != 0 {
		fmt.Fprintf(os.Stderr, "init: refusing: %s is accessible to other identities (%v)\n", dir, fi.Mode().Perm())
		os.Exit(1)
	}

	db, err := metadata.NewDB(d.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot initialize the database: %v\n", err)
		os.Exit(1)
	}
	if err := db.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot close the database cleanly: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("state directory: %s (0700)\n", dir)
	fmt.Printf("database:        %s\n", d.DBPath)
	fmt.Printf("assurance:       %s%s\n", d.EffectiveAssurance(), map[bool]string{true: " (default)", false: ""}[*assuranceF == ""])
	fmt.Println()
	fmt.Println("Next steps (run the broker as the dedicated service UID):")
	printNextSteps(d)
}

// writeInstallConfig writes the installation-wide configuration file for d,
// idempotently and never over a differing file without --force. The file
// contains no secret, so 0644 is intentional: every UID involved in the
// installation must be able to read the endpoints it may reach. It is the
// CLI wrapper (os.Exit on refusal) around writeInstallConfigPath, which is
// the testable core.
func writeInstallConfig(path string, d config.Deployment, force bool) {
	data, err := config.RenderConfig(d)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: cannot render the installation config: %v\n", err)
		os.Exit(1)
	}
	if err := writeInstallConfigPath(path, data, force); err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(1)
	}
}

// writeInstallConfigPath is the core of the install-config writer. Refusals
// are returned, not exited, so tests can pin the security properties.
func writeInstallConfigPath(path string, data []byte, force bool) error {
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(data) {
			fmt.Printf("install config: %s (already up to date)\n", path)
			return nil
		}
		if !force {
			return fmt.Errorf("refusing to overwrite differing %s (pass --force)", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("cannot create %s: %w", filepath.Dir(path), err)
	}
	// Write through a sibling temp file and rename, so a crash mid-write
	// can never leave a truncated config that other surfaces would refuse.
	// The temp name is randomized (os.CreateTemp), so a pre-planted
	// path+".tmp" symlink cannot redirect the final rename onto an
	// unrelated target.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("cannot create a temp file in %s: %w", filepath.Dir(path), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot restrict %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot flush %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cannot install %s: %w", path, err)
	}
	fmt.Printf("install config: %s (endpoints, vault and UID lists only — no secrets)\n", path)
	return nil
}

// printNextSteps writes the exact broker and doctor commands for the chosen
// topology. It is separated from initCmd so the printed text can be tested:
// these lines are the installation, and a missing flag in them is a broken
// installation the operator pastes verbatim.
func printNextSteps(d config.Deployment) {
	sock, admin, intake := d.SocketPath, d.AdminSocket, d.IntakeSocket
	// The printed commands must run as printed: the development acknowledgement
	// is required by both the broker and the doctor, whichever claim is used.
	devFlag := map[bool]string{true: " --dev", false: ""}[d.VaultType == config.VaultMemoryTest]
	var helperFlags string
	if d.VaultType == config.VaultAegisKeys {
		if d.AegisKeysSocket != "" {
			helperFlags += " --aegiskeys-socket " + shellSingleQuote(d.AegisKeysSocket)
		}
		if d.AegisKeysDir != "" {
			helperFlags += " --aegiskeys-dir " + shellSingleQuote(d.AegisKeysDir)
		}
		helperFlags += " --aegiskeys-resolve-helper " + shellSingleQuote(d.AegisKeysResolveHelper) +
			" --aegiskeys-resolve-helper-sha256 " + d.AegisKeysResolveHelperSHA256
	}
	var idFlags string
	if d.SocketGroup != "" {
		idFlags += " --socket-group " + d.SocketGroup
	}
	if len(d.AgentUIDs) > 0 {
		idFlags += " --agent-uid " + joinUIDs(d.AgentUIDs)
	}
	if len(d.IntakeUIDs) > 0 {
		idFlags += " --intake-uid " + joinUIDs(d.IntakeUIDs)
	}
	if len(d.AdminUIDs) > 0 {
		idFlags += " --admin-uid " + joinUIDs(d.AdminUIDs)
	}
	if d.RecipientSocket != "" {
		idFlags += " --recipient-socket " + shellSingleQuote(d.RecipientSocket)
		if len(d.RecipientUIDs) > 0 {
			idFlags += " --recipient-uid " + joinUIDs(d.RecipientUIDs)
		}
		if d.RecipientGroup != "" {
			idFlags += " --recipient-group " + d.RecipientGroup
		}
	}
	if d.EffectiveAssurance() == config.AssuranceIsolated {
		fmt.Printf("  seqpass broker --vault %s%s%s --assurance isolated --db %s --socket %s \\\n", d.VaultType, devFlag, helperFlags, shellSingleQuote(d.DBPath), shellSingleQuote(sock))
		fmt.Printf("    --admin-socket %s --intake-socket %s%s\n", shellSingleQuote(admin), shellSingleQuote(intake), idFlags)
	} else {
		// Best-effort still carries the identities the operator declared, so
		// the printed command cannot quietly narrow the authorization to
		// euid-only.
		fmt.Printf("  seqpass broker --vault %s%s%s --assurance best-effort --db %s --socket %s%s\n", d.VaultType, devFlag, helperFlags, shellSingleQuote(d.DBPath), shellSingleQuote(sock), idFlags)
	}
	fmt.Printf("  seqpass doctor --topology --vault %s%s%s --db %s --socket %s --admin-socket %s --intake-socket %s%s\n", d.VaultType, devFlag, helperFlags, shellSingleQuote(d.DBPath), shellSingleQuote(sock), shellSingleQuote(admin), shellSingleQuote(intake), idFlags)
	fmt.Println()
	fmt.Println("Then register the adapter: seqpass mcp (Codex/Claude/Hermes) or seqpass agent.")
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// joinUIDs renders a UID list the way the flags accept it.
func joinUIDs(uids []uint32) string {
	parts := make([]string, 0, len(uids))
	for _, u := range uids {
		parts = append(parts, strconv.FormatUint(uint64(u), 10))
	}
	return strings.Join(parts, ",")
}

// parseUIDs delegates to the single shared parser so the CLI, the doctor and
// the broker cannot disagree about what an identity list means.
func parseUIDs(s string) ([]uint32, error) {
	return config.ParseUIDs(s)
}

// mustUIDs parses a UID list for CLI use, exiting on malformed input.
func mustUIDs(flagName, s string) []uint32 {
	uids, err := parseUIDs(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --%s: %v\n", flagName, err)
		os.Exit(2)
	}
	return uids
}

func printJSON(v interface{}) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(raw))
}

func fieldOf(v interface{}, k string) interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m[k]
	}
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
