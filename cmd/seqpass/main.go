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
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/secretbridge/secretbridge/internal/approval"
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
	return config.Paths()
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
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "seqpass - native secret broker for coding harnesses")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault aegiskeys [--assurance best-effort|isolated] [--db PATH] [--socket PATH] [--admin-uid UID,...] [--agent-uid UID,...] [--intake-uid UID,...] [--intake-group GROUP] [--host-socket PATH] [--auto-execute]")
	fmt.Fprintln(os.Stderr, "  seqpass broker --vault memory-test --dev  # development only, never production")
	fmt.Fprintln(os.Stderr, "  seqpass mcp [--socket PATH]   # stdio adapter; register in Codex/Claude/Hermes")
	fmt.Fprintln(os.Stderr, "  seqpass admin <catalog|pending|show|approve|reject|add-secret|add-dest|add-policy|set-policy|update-dest|execute|host-binding> ...")
	fmt.Fprintln(os.Stderr, "  seqpass relay <inbox|fulfill|status|cancel|request> ...  # trusted human handoff (intake socket)")
	fmt.Fprintln(os.Stderr, "  seqpass agent <capabilities|request|status|cancel> ...  # generic agent adapter over the broker socket")
	fmt.Fprintln(os.Stderr, "  seqpass recipient --socket PATH --journal DIR [--consumer-dir DIR]  # trusted credential consumer endpoint")
	fmt.Fprintln(os.Stderr, "  seqpass tui [--intake-socket PATH]  # persistent native inbox TUI (own terminal, never the agent's)")
	fmt.Fprintln(os.Stderr, "  seqpass doctor [--topology]  # honest health + live isolation boundary report")
	fmt.Fprintln(os.Stderr, "  seqpass init [--vault aegiskeys] ...  # create the 0700 state dir + database, print next steps")
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
	hostF := fs.String("host-socket", "", "optional display-only native-host adapter socket; owner-only, separate directory required")
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
	assurance := fs.String("assurance", "", "topology label: empty (production default: isolated), isolated, or best-effort (development only, always reported unverified)")
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
	// Objective 8: UID lists fail closed. A malformed or duplicated UID is a
	// startup error, never a silently narrowed identity set.
	intakeUIDList := mustUIDs("intake-uid", *intakeUIDs)
	adminUIDList := mustUIDs("admin-uid", *adminUIDs)
	agentUIDList := mustUIDs("agent-uid", *agentUIDs)
	d, err := daemon.New(daemon.Config{
		AssuranceMode: *assurance,
		DBPath:        *dbF,
		VaultType:     *vaultF,
		SocketPath:    *sockF,
		AdminSocket:   *adminF,
		IntakeSocket:  *intakeF,
		HostSocket:    *hostF,
		IntakeUIDs:    intakeUIDList,
		AdminUIDs:     adminUIDList,
		AgentUIDs:     agentUIDList, SocketGroup: *sockGroup, AegisKeysSocket: *aegisSock,
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
		typ := fs.String("type", "recipient-socket", "recipient-socket | http-pinned | process-pinned")
		ep := fs.String("endpoint", "", "recipient-socket: unix socket path; http-pinned: pinned origin (https://host[:port]); process-pinned: absolute executable path")
		expectUID := fs.Int("expect-uid", -1, "pinned recipient UID (recipient-socket only)")
		expectGID := fs.Int("expect-gid", -1, "pinned recipient GID (optional, recipient-socket only)")
		_ = fs.Parse(args[1:])
		params := map[string]interface{}{"name": *name, "type": *typ, "endpoint": *ep}
		switch *typ {
		case "recipient-socket":
			if *name == "" || *ep == "" || *expectUID < 0 {
				fatal("add-dest --name N --type recipient-socket --endpoint SOCK --expect-uid UID [--expect-gid GID]")
			}
			params["expected_uid"] = *expectUID
			if *expectGID >= 0 {
				params["expected_gid"] = *expectGID
			}
		case "http-pinned":
			if *name == "" || *ep == "" {
				fatal("add-dest --name N --type http-pinned --endpoint https://host[:port]")
			}
		case "process-pinned":
			if *name == "" || *ep == "" {
				fatal("add-dest --name N --type process-pinned --endpoint /absolute/executable (pin fixed flags with a wrapper script)")
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
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	_, sock, admin, intake := defaultPaths()
	topology := fs.Bool("topology", false, "evaluate the configured topology live instead of asking a running broker")
	requireVerified := fs.Bool("require-verified", false, "exit non-zero unless the boundary is verified")
	sockF := fs.String("socket", sock, "broker socket")
	adminF := fs.String("admin-socket", admin, "admin socket")
	intakeF := fs.String("intake-socket", intake, "trusted intake socket")
	dbF := fs.String("db", "", "database path (defaults to the standard location)")
	vaultF := fs.String("vault", "", "vault type: aegiskeys|memory-test")
	devF := fs.Bool("dev", false, "memory-test vault acknowledgement (development only)")
	assuranceF := fs.String("assurance", "", "topology claim: isolated|best-effort (default: derived from the vault)")
	agentUIDsF := fs.String("agent-uid", "", "comma-separated approved agent UIDs")
	adminUIDsF := fs.String("admin-uid", "", "comma-separated admin UIDs")
	intakeUIDsF := fs.String("intake-uid", "", "comma-separated trusted intake UIDs")
	groupF := fs.String("socket-group", "", "agent socket group")
	intakeGroupF := fs.String("intake-group", "", "trusted intake socket group")
	hostF := fs.String("host-socket", "", "display-only native-host adapter socket")
	aegisSock := fs.String("aegiskeys-socket", "", "AegisKeys broker socket")
	aegisDir := fs.String("aegiskeys-dir", "", "AegisKeys config dir")
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

	db, _, _, _ := defaultPaths()
	if *dbF != "" {
		db = *dbF
	}
	d := config.Defaults()
	d.DBPath = db
	d.SocketPath = *sockF
	d.AdminSocket = *adminF
	d.IntakeSocket = *intakeF
	d.HostSocket = *hostF
	d.VaultType = *vaultF
	d.Dev = *devF
	d.AssuranceMode = *assuranceF
	d.SocketGroup = *groupF
	d.IntakeGroup = *intakeGroupF
	d.AegisKeysSocket = *aegisSock
	d.AegisKeysDir = *aegisDir
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
func initCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dbDefault, _, _, _ := defaultPaths()
	dbF := fs.String("db", dbDefault, "database path")
	vaultF := fs.String("vault", config.VaultAegisKeys, "vault type: aegiskeys (production) or memory-test (development, requires --dev)")
	devF := fs.Bool("dev", false, "development-only acknowledgement for the memory-test vault")
	assuranceF := fs.String("assurance", "", "topology claim: isolated|best-effort (default: derived from the vault)")
	agentUIDsF := fs.String("agent-uid", "", "comma-separated approved agent UIDs (required for a production vault)")
	adminUIDsF := fs.String("admin-uid", "", "comma-separated admin UIDs")
	intakeUIDsF := fs.String("intake-uid", "", "comma-separated trusted intake UIDs")
	groupF := fs.String("socket-group", "", "agent socket group (required for a production vault)")
	_ = fs.Parse(args)

	d := config.Defaults()
	d.DBPath = *dbF
	d.VaultType = *vaultF
	d.Dev = *devF
	d.AssuranceMode = *assuranceF
	d.SocketGroup = *groupF
	d.AgentUIDs = mustUIDs("agent-uid", *agentUIDsF)
	d.AdminUIDs = mustUIDs("admin-uid", *adminUIDsF)
	d.IntakeUIDs = mustUIDs("intake-uid", *intakeUIDsF)
	if err := d.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(2)
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

// printNextSteps writes the exact broker and doctor commands for the chosen
// topology. It is separated from initCmd so the printed text can be tested:
// these lines are the installation, and a missing flag in them is a broken
// installation the operator pastes verbatim.
func printNextSteps(d config.Deployment) {
	_, sock, admin, intake := defaultPaths()
	// The printed commands must run as printed: the development acknowledgement
	// is required by both the broker and the doctor, whichever claim is used.
	devFlag := map[bool]string{true: " --dev", false: ""}[d.VaultType == config.VaultMemoryTest]
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
	if d.EffectiveAssurance() == config.AssuranceIsolated {
		fmt.Printf("  seqpass broker --vault %s%s --assurance isolated --db %s --socket %s \\\n", d.VaultType, devFlag, d.DBPath, sock)
		fmt.Printf("    --admin-socket %s --intake-socket %s%s\n", admin, intake, idFlags)
	} else {
		// Best-effort still carries the identities the operator declared, so
		// the printed command cannot quietly narrow the authorization to
		// euid-only.
		fmt.Printf("  seqpass broker --vault %s%s --assurance best-effort --db %s --socket %s%s\n", d.VaultType, devFlag, d.DBPath, sock, idFlags)
	}
	fmt.Printf("  seqpass doctor --topology --vault %s%s --db %s%s\n", d.VaultType, devFlag, d.DBPath, idFlags)
	fmt.Println()
	fmt.Println("Then register the adapter: seqpass mcp (Codex/Claude/Hermes) or seqpass agent.")
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
