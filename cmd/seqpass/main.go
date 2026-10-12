// Command seqpass is the single native binary.
//
//	seqpass broker  - run protected credential storage, policy and operations
//	seqpass mcp     - start MCP stdio adapter for a coding harness
//	seqpass admin   - trusted operator terminal (credentials, destinations, approvals)
//	seqpass status  - local health without revealing secrets
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretbridge/secretbridge/internal/approval"
	"github.com/secretbridge/secretbridge/internal/daemon"
	"github.com/secretbridge/secretbridge/internal/ipc"
	mcpserver "github.com/secretbridge/secretbridge/internal/mcp"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/tui"
	"github.com/secretbridge/secretbridge/internal/types"
)

func defaultPaths() (db, sock, admin, intake string) {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".seqpass")
	sock = filepath.Join(base, "broker.sock")
	return filepath.Join(base, "metadata.db"), sock, sock + ".admin", sock + ".intake"
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
	case "tui":
		tuiCmd(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "seqpass - native secret broker for coding harnesses")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault aegiskeys [--assurance best-effort|isolated] [--db PATH] [--socket PATH] [--admin-uid UID,...] [--agent-uid UID,...] [--intake-uid UID,...] [--intake-group GROUP] [--auto-execute]")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault memory-test --dev  # development only, never production")
	fmt.Fprintln(os.Stderr, "  seqpass mcp [--socket PATH]   # stdio adapter; register in Codex/Claude/Hermes")
	fmt.Fprintln(os.Stderr, "  seqpass admin <catalog|pending|show|approve|reject|add-secret|add-dest|add-policy|set-policy|update-dest|execute> ...")
	fmt.Fprintln(os.Stderr, "  seqpass relay <inbox|fulfill|status|cancel|request> ...  # trusted human handoff (intake socket)")
	fmt.Fprintln(os.Stderr, "  seqpass tui [--intake-socket PATH]  # persistent native inbox TUI (own terminal, never the agent's)")
	fmt.Fprintln(os.Stderr, "  seqpass status")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "MCP registration:")
	fmt.Fprintln(os.Stderr, "  Codex:  [mcp_servers.seqpass] command=\"/usr/local/bin/seqpass\" args=[\"mcp\"]")
	fmt.Fprintln(os.Stderr, "  Claude: claude mcp add --scope user seqpass -- /usr/local/bin/seqpass mcp")
}

func brokerCmd(args []string) {
	fs := flag.NewFlagSet("broker", flag.ExitOnError)
	db, sock, admin, intake := defaultPaths()
	dbF := fs.String("db", db, "SQLite path")
	sockF := fs.String("socket", sock, "Broker socket")
	adminF := fs.String("admin-socket", admin, "Admin socket")
	intakeF := fs.String("intake-socket", intake, "Trusted human intake socket (owner-only unless --intake-group is set)")
	intakeUIDs := fs.String("intake-uid", "", "comma-separated human intake UIDs (default: admin UIDs; list agent UIDs here only for same-user best-effort mode)")
	intakeGroup := fs.String("intake-group", "", "optional trusted intake socket group; must differ from agent group and exclude agent UIDs")
	vaultF := fs.String("vault", "", "required: aegiskeys|memory-test")
	devF := fs.Bool("dev", false, "allow memory-test ephemeral vault (development only, never production)")
	autoF := fs.Bool("auto-execute", false, "run trusted worker executing authorized ops without manual admin execute")
	noRelayF := fs.Bool("no-relay-auto-deliver", false, "disable the default broker-managed relay delivery queue (F05); with it set, fulfilled relays need --auto-execute or manual admin execute")
	aegisSock := fs.String("aegiskeys-socket", "", "AegisKeys broker socket")
	aegisDir := fs.String("aegiskeys-dir", "", "AegisKeys config dir")
	adminUIDs := fs.String("admin-uid", "", "comma-separated admin UIDs (default: broker euid)")
	agentUIDs := fs.String("agent-uid", "", "comma-separated approved agent UIDs (default: broker euid only)")
	sockGroup := fs.String("socket-group", "", "agent Unix group owning the agent socket+dir (required for multi-user deployments)")
	opTTL := fs.Duration("default-op-ttl", 0, "approval window for new requests (default 5m, clamped 1m-24h)")
	maxConc := fs.Int("max-concurrent-ops", 4, "auto-worker execution pool size (1-32)")
	assurance := fs.String("assurance", daemon.AssuranceBestEffort, "topology label: best-effort or isolated (Linux, dedicated broker UID and separate agent UIDs)")
	_ = fs.Parse(args)

	// Explicit provider configuration (C14): no silent ephemeral vault.
	if *vaultF == "" {
		fmt.Fprintln(os.Stderr, "broker requires --vault aegiskeys (production) or --vault memory-test --dev (development only)")
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
	d, err := daemon.New(daemon.Config{
		AssuranceMode: *assurance,
		DBPath:        *dbF,
		VaultType:     *vaultF,
		SocketPath:    *sockF,
		AdminSocket:   *adminF,
		IntakeSocket:  *intakeF,
		IntakeUIDs:    parseUIDs(*intakeUIDs),
		AdminUIDs:     parseUIDs(*adminUIDs),
		AgentUIDs:     parseUIDs(*agentUIDs), SocketGroup: *sockGroup, AegisKeysSocket: *aegisSock,
		IntakeGroup:        *intakeGroup,
		NoRelayAutoDeliver: *noRelayF,
		AegisKeysDir:       *aegisDir,
		AutoExecute:        *autoF,
		DefaultOpTTL:       *opTTL,
		MaxConcurrentOps:   *maxConc,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "broker failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "seqpass broker uid=%d assurance=%s on %s (admin %s admin-uids=%v agent-uids=%v op-ttl=%s max-concurrent-ops=%d)\n", os.Geteuid(), *assurance, *sockF, *adminF, parseUIDs(*adminUIDs), parseUIDs(*agentUIDs), (*opTTL).String(), *maxConc)
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
	if env := os.Getenv("SEQ_PASS_SOCKET"); env != "" {
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
	if env := os.Getenv("SEQ_PASS_ADMIN_SOCKET"); env != "" {
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
		fmt.Fprintln(os.Stderr, "admin subcommands: catalog|pending|show|approve|reject|verify|recipient-status|add-secret|stage-secret|add-dest|execute")
		os.Exit(1)
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
		typ := fs.String("type", "recipient-socket", "recipient-socket")
		ep := fs.String("endpoint", "", "trusted recipient unix socket path")
		expectUID := fs.Int("expect-uid", -1, "pinned recipient UID (required)")
		expectGID := fs.Int("expect-gid", -1, "pinned recipient GID (optional)")
		_ = fs.Parse(args[1:])
		if *name == "" || *ep == "" || *expectUID < 0 {
			fatal("add-dest --name N --type recipient-socket --endpoint SOCK --expect-uid UID [--expect-gid GID]")
		}
		params := map[string]interface{}{"name": *name, "type": *typ, "endpoint": *ep, "expected_uid": *expectUID}
		if *expectGID >= 0 {
			params["expected_gid"] = *expectGID
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
		_ = fs.Parse(args[1:])
		if *id == "" || *ep == "" {
			fatal("update-dest --id ID --endpoint SOCK [--expect-uid UID] (invalidates outstanding approvals)")
		}
		params := map[string]interface{}{"id": *id, "endpoint": *ep}
		if *expectUID >= 0 {
			params["expected_uid"] = *expectUID
		}
		if *expectGID >= 0 {
			params["expected_gid"] = *expectGID
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
	default:
		fmt.Fprintln(os.Stderr, "unknown admin subcommand:", args[0])
		os.Exit(1)
	}
}

func statusCmd(args []string) {
	_ = args
	sock := os.Getenv("SEQ_PASS_SOCKET")
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
	if env := os.Getenv("SEQ_PASS_INTAKE_SOCKET"); env != "" {
		di = env
	}
	intakeF := fs.String("intake-socket", di, "Broker intake socket")
	_ = fs.Parse(args)
	if err := runTUI(*intakeF); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}

func runTUI(intakeSock string) error {
	return tui.Run(tui.Config{IntakeSocket: intakeSock})
}

func parseUIDs(s string) []uint32 {
	if s == "" {
		return nil
	}
	var out []uint32
	for _, part := range strings.Split(s, ",") {
		var u uint32
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &u); err == nil {
			out = append(out, u)
		}
	}
	return out
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
