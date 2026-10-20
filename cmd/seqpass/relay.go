package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/secretbridge/secretbridge/internal/config"
	"github.com/secretbridge/secretbridge/internal/ipc"
	"golang.org/x/term"
)

// Trusted human handoff CLI (QR-02). This is the user-side intake
// client: it talks to the intake socket (owner-only, human identities),
// never to agent tool arguments. Plaintext is collected from a no-echo
// terminal or a carefully opened file — never from argv, environment,
// or shell history. There is deliberately no --secret flag.

// maxRelayCLIPayload mirrors the broker bound; the CLI refuses larger
// files before the broker ever sees them.
const maxRelayCLIPayload = 64 * 1024

func resolveIntakeSocket(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := config.EnvEndpoint(config.EnvIntakeSocket); env != "" {
		return env
	}
	_, _, _, di := defaultPaths()
	return di
}

func resolveAgentSocket() string {
	if env := config.EnvEndpoint(config.EnvSocket); env != "" {
		return env
	}
	_, sock, _, _ := defaultPaths()
	return sock
}

func dialIntake(sock string) *ipc.Client {
	cli, err := ipc.Dial(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach broker intake socket %s: %v\nIs `seqpass broker` running with intake enabled?\n", sock, err)
		os.Exit(1)
	}
	return cli
}

func dialAgent() *ipc.Client {
	sock := resolveAgentSocket()
	cli, err := ipc.Dial(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach broker socket %s: %v\nIs `seqpass broker` running?\n", sock, err)
		os.Exit(1)
	}
	return cli
}

func relayCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "relay subcommands: inbox|fulfill|status|cancel|request")
		fmt.Fprintln(os.Stderr, "  inbox                list requests awaiting your input")
		fmt.Fprintln(os.Stderr, "  fulfill <request-id> [--file PATH]   review, enter value, authorize delivery")
		fmt.Fprintln(os.Stderr, "  status <request-id>  check handoff outcome")
		fmt.Fprintln(os.Stderr, "  cancel <request-id>  withdraw a request")
		fmt.Fprintln(os.Stderr, "  request --to DEST --kind KIND [--purpose TEXT] [--ttl 90s] [--file PATH]")
		fmt.Fprintln(os.Stderr, "  credential-save --binding BINDING --kind KIND --service SVC [--mode save_only|save_and_use|use_once|transient_once] [--file PATH]")
		os.Exit(1)
	}
	switch args[0] {
	case "inbox":
		relayInbox(args[1:])
	case "fulfill":
		relayFulfill(args[1:])
	case "status":
		relayStatusCmd(args[1:])
	case "cancel":
		relayCancel(args[1:])
	case "request":
		relayRequestCmd(args[1:])
	case "credential-save":
		credentialSaveCmd(args[1:])
	default:
		fatal("unknown relay subcommand (inbox|fulfill|status|cancel|request|credential-save)")
	}
}

func relayInbox(args []string) {
	fs := flag.NewFlagSet("relay inbox", flag.ExitOnError)
	intakeF := fs.String("intake-socket", resolveIntakeSocket(""), "Broker intake socket")
	_ = fs.Parse(args)
	cli := dialIntake(*intakeF)
	defer cli.Close()
	data, err := cli.Call(ipc.MethodIntakeInspect, nil)
	must(err)
	items, _ := data.([]interface{})
	if len(items) == 0 {
		fmt.Println("No pending requests.")
		return
	}
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		fmt.Printf("%s  from=%v  dest=%v  kind=%v  expires=%v\n    purpose=%v\n",
			m["id"], m["agent_principal"], m["destination_id"], m["data_kind"],
			m["expires_at"], truncPurpose(m["purpose"]))
	}
}

func truncPurpose(v interface{}) string {
	s, _ := v.(string)
	return sanitizeUntrusted(s)
}

// sanitizeUntrusted neutralizes terminal-control attacks in agent-supplied
// text (F10): ANSI escapes, OSC sequences, bidirectional controls and
// other C0/C1 controls are replaced, output is bounded to 120 chars, and
// the caller always labels it UNTRUSTED at the render site.
func sanitizeUntrusted(s string) string {
	if s == "" {
		return "(no reason given)"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case r == 0x1b || r == 0x07 || r < 32 || r == 127:
			b.WriteRune('\uFFFD')
		case r >= 0x80 && r <= 0x9F:
			b.WriteRune('\uFFFD')
		case r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r == 0x200B || r == 0x200E || r == 0x200F || r == 0xFEFF:
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
		if b.Len() > 160 {
			break
		}
	}
	out := b.String()
	runes := []rune(out)
	if len(runes) > 120 {
		return string(runes[:120]) + "…"
	}
	return out
}

// relayFulfill implements the trusted review (SP-TUI-08): verified
// broker fields first — recipient, action, requester, expiry, usage —
// the agent's free-form purpose clearly labeled as UNTRUSTED, and only
// then payload collection. What the user approves is pinned live.
// splitFlag extracts a --name value|path flag from any position (the
// stdlib flag set stops at the first positional, which would force an
// awkward flag-before-ID order on the fulfill/request commands).
func splitFlag(args []string, name string) (string, []string) {
	var rest []string
	val := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--"+name && i+1 < len(args) {
			val = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "--"+name+"=") {
			val = strings.TrimPrefix(a, "--"+name+"=")
			continue
		}
		rest = append(rest, a)
	}
	return val, rest
}

func relayFulfill(args []string) {
	fileF, args := splitFlag(args, "file")
	sockF, args := splitFlag(args, "intake-socket")
	fs := flag.NewFlagSet("relay fulfill", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fatal("usage: seqpass relay fulfill <request-id> [--file PATH] [--intake-socket PATH]")
	}
	reqID := fs.Arg(0)
	intakeSock := resolveIntakeSocket(sockF)
	cli := dialIntake(intakeSock)
	defer cli.Close()
	data, err := cli.Call(ipc.MethodIntakeInspect, map[string]interface{}{"request_id": reqID})
	must(err)
	m, _ := data.(map[string]interface{})
	if m == nil {
		fatal("request not found")
	}
	if st, _ := m["state"].(string); st != "awaiting_user" {
		fatal(fmt.Sprintf("request is %s, not awaiting input", st))
	}
	fmt.Println("REQUEST REVIEW (verified by broker — approve only what is shown here)")
	fmt.Println("Input route: this trusted terminal. Protection depends on broker topology;")
	fmt.Println("same-UID best-effort deployments are NOT protected from the agent.")
	fmt.Printf("  Requester:  %v\n", m["agent_principal"])
	fmt.Printf("  Recipient:  %v (registered destination)\n", m["destination_id"])
	fmt.Printf("  Action:     supply %v\n", m["data_kind"])
	fmt.Printf("  Expires:    %v\n", m["expires_at"])
	fmt.Printf("  Usage:      %v\n", usageLine(m))
	fmt.Printf("  Agent note (UNTRUSTED, not verified): %v\n", truncPurpose(m["purpose"]))
	var payload []byte
	if fileF != "" {
		payload, err = readSecretFile(fileF)
		must(err)
	} else {
		payload, err = readSecretTTY(fmt.Sprintf("Enter %v for %v (input hidden): ", m["data_kind"], m["destination_id"]))
		must(err)
	}
	defer clearCLISecret(payload)
	// F13: explicit final confirmation after the value is entered —
	// declining sends no payload.
	if !confirmTTY("Authorize delivery of the entered value to the recipient shown above? [y/N]: ") {
		fmt.Println("Declined: no payload sent.")
		return
	}
	revision, _ := m["revision"].(float64)
	if revision <= 0 {
		fatal("request revision unavailable; refusing stale fulfill")
	}
	res, err := cli.Call(ipc.MethodIntakeFulfill, map[string]interface{}{
		"request_id":       reqID,
		"request_revision": uint64(revision),
		"payload":          base64.StdEncoding.EncodeToString(payload),
	})
	must(err)
	rm, _ := res.(map[string]interface{})
	fmt.Printf("Authorized. Delivery operation: %v — poll `seqpass relay status %s` for the outcome.\n", rm["op_id"], reqID)
}

func usageLine(m map[string]interface{}) string {
	c, _ := m["consumption"].(string)
	if c == "" {
		c = "single_dispatch"
	}
	mx, _ := m["max_deliveries"].(float64)
	switch c {
	case "reusable_until_expiry":
		if mx <= 0 {
			return "reusable_until_expiry — REUSABLE UNTIL EXPIRY; UNLIMITED authorized deliveries to this recipient"
		}
		return fmt.Sprintf("reusable_until_expiry, up to %d deliveries until expiry", int(mx))
	case "bounded_uses":
		if mx <= 1 {
			return "bounded_uses, one delivery"
		}
		return fmt.Sprintf("bounded_uses, up to %d deliveries", int(mx))
	default:
		if mx > 1 {
			return fmt.Sprintf("%s, up to %d deliveries", c, int(mx))
		}
		return c + ", ONE delivery only"
	}
}

func relayStatusCmd(args []string) {
	fileF, args := splitFlag(args, "file")
	_ = fileF
	sockF, args := splitFlag(args, "intake-socket")
	fs := flag.NewFlagSet("relay status", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fatal("usage: seqpass relay status <request-id>")
	}
	// F13: prefer the agent surface for own-status polling, but fall
	// back to the trusted intake view so a human without agent IPC
	// privileges can still check outcomes.
	if cli, err := ipc.Dial(resolveAgentSocket()); err == nil {
		defer cli.Close()
		if data, err := cli.Call(ipc.MethodRelayStatus, map[string]interface{}{"request_id": fs.Arg(0)}); err == nil {
			printJSON(data)
			return
		}
	}
	icli := dialIntake(resolveIntakeSocket(sockF))
	defer icli.Close()
	data, err := icli.Call(ipc.MethodIntakeInspect, map[string]interface{}{"request_id": fs.Arg(0)})
	must(err)
	printJSON(data)
}

func relayCancel(args []string) {
	sockF, args := splitFlag(args, "intake-socket")
	fs := flag.NewFlagSet("relay cancel", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fatal("usage: seqpass relay cancel <request-id>")
	}
	// F13: agent-side withdraw first; intake fallback for humans
	// without agent IPC privileges.
	if cli, err := ipc.Dial(resolveAgentSocket()); err == nil {
		defer cli.Close()
		if _, err := cli.Call(ipc.MethodRelayCancel, map[string]interface{}{"request_id": fs.Arg(0)}); err == nil {
			fmt.Println("Cancelled.")
			return
		}
	}
	icli := dialIntake(resolveIntakeSocket(sockF))
	defer icli.Close()
	_, err := icli.Call(ipc.MethodIntakeCancel, map[string]interface{}{"request_id": fs.Arg(0)})
	must(err)
	fmt.Println("Cancelled.")
}

// confirmTTY asks a final yes/no on /dev/tty (F13). Default is no.
func confirmTTY(prompt string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	return confirmOnTTY(tty, prompt)
}

// confirmOnTTY asks a final yes/no on an already-open terminal handle.
// The prompt goes to the terminal handle itself (never stderr), so the
// question and answer stay in the trusted terminal session.
func confirmOnTTY(tty *os.File, prompt string) bool {
	fmt.Fprint(tty, prompt)
	rd := bufio.NewReader(tty)
	line, err := rd.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// relayRequestCmd is Workflow B (QR-03): the user knows what to supply.
// One trusted interaction creates the self-scoped relay AND fulfills it.
func relayRequestCmd(args []string) {
	fs := flag.NewFlagSet("relay request", flag.ExitOnError)
	intakeF := fs.String("intake-socket", resolveIntakeSocket(""), "Broker intake socket")
	toF := fs.String("to", "", "registered recipient ID")
	kindF := fs.String("kind", "", "password|one_time_code|api_key|token|pin|text")
	purposeF := fs.String("purpose", "", "why this handoff is needed")
	ttlF := fs.Duration("ttl", 90*time.Second, "how long the handoff stays valid")
	onceF := fs.Bool("once", true, "single delivery (default true)")
	fileF := fs.String("file", "", "read payload from file instead of terminal")
	_ = fs.Parse(args)
	if *toF == "" || *kindF == "" {
		fatal("usage: seqpass relay request --to DEST --kind KIND [--purpose TEXT] [--ttl 90s] [--file PATH]")
	}
	// F13: the human-side client operates without agent IPC privileges —
	// creation and fulfillment both travel over the intake socket.
	icli := dialIntake(*intakeF)
	defer icli.Close()
	var payload []byte
	var err error
	if *fileF != "" {
		payload, err = readSecretFile(*fileF)
		must(err)
	} else {
		fmt.Printf("Enter %s for %s (input hidden):\n", *kindF, *toF)
		payload, err = readSecretTTY(fmt.Sprintf("Enter %s (input hidden): ", *kindF))
		must(err)
	}
	defer clearCLISecret(payload)
	if !*onceF {
		fmt.Println("Note: reusable/multi-delivery grants require explicit trusted-user confirmation here (agent IPC cannot select them).")
		if !confirmTTY("Create a REUSABLE grant for this recipient? [y/N]: ") {
			fmt.Println("Declined: no request created.")
			return
		}
	}
	params := map[string]interface{}{
		"destination_id": *toF, "data_kind": *kindF, "purpose": *purposeF,
		"ttl_seconds": ttlF.Seconds(),
		"payload":     base64.StdEncoding.EncodeToString(payload),
	}
	if !*onceF {
		params["consumption"] = "reusable_until_expiry"
	}
	// Single trusted call: the broker creates and fulfills atomically.
	data, err := icli.Call(ipc.MethodIntakeRequest, params)
	must(err)
	m, _ := data.(map[string]interface{})
	reqID, _ := m["request_id"].(string)
	opID, _ := m["op_id"].(string)
	if reqID == "" {
		fatal("broker refused the request")
	}
	fmt.Printf("Authorized, operation %v. Poll `seqpass relay status %s`.\n", opID, reqID)
}

// credentialSaveCmd is the P0-3 trusted-intake credential persistence
// entry (intake socket): save a submitted credential in AegisKeys
// (save_only), save it and stage the protected-use flow
// (save_and_use), save it for exactly one authorized use with the
// credential RETAINED at the provider (use_once — persisted
// single-use), or stage a genuinely TRANSIENT single-use credential
// that never persists anywhere (transient_once — no AegisKeys record;
// unrecoverable after expiry or restart).
// The value is collected hidden (TTY) or from a 0600 file, crosses the
// wire once as base64 over the trusted intake socket, and is never
// echoed, logged, or persisted by SeqPass — only stable references
// (request ID, record ID, binding ID) come back.
func credentialSaveCmd(args []string) {
	fs := flag.NewFlagSet("relay credential-save", flag.ExitOnError)
	intakeF := fs.String("intake-socket", resolveIntakeSocket(""), "Broker intake socket")
	bindingF := fs.String("binding", "", "AegisKeys binding under which the credential becomes resolvable")
	kindF := fs.String("kind", "", "credential kind (api-key|token|password|...)")
	serviceF := fs.String("service", "", "service identity for the provider record")
	labelF := fs.String("label", "", "human-readable label")
	modeF := fs.String("mode", "save_only", "use_once|save_only|save_and_use|transient_once")
	opsF := fs.String("operations", "", "comma-separated operation scope (required; operation-scoped binding contract)")
	descF := fs.String("description", "", "optional description")
	fileF := fs.String("file", "", "read credential from file instead of terminal")
	requestIDF := fs.String("request-id", "", "durable request ID for retries (default: broker-generated)")
	statusF := fs.Bool("status", false, "reconcile an existing request ID instead of saving")
	_ = fs.Parse(args)
	icli := dialIntake(*intakeF)
	defer icli.Close()

	if *statusF {
		if *requestIDF == "" {
			fatal("usage: seqpass relay credential-save --status --request-id ID")
		}
		data, err := icli.Call(ipc.MethodIntakeProvisionStatus, map[string]interface{}{
			"request_id": *requestIDF,
		})
		must(err)
		printJSON(data)
		return
	}

	if *bindingF == "" || *kindF == "" || *serviceF == "" || *opsF == "" {
		fatal("usage: seqpass relay credential-save --binding BINDING --kind KIND --service SVC --operations OP[,OP...] [--mode MODE] [--file PATH]")
	}
	var ops []string
	for _, op := range strings.Split(*opsF, ",") {
		if op = strings.TrimSpace(op); op != "" {
			ops = append(ops, op)
		}
	}
	var payload []byte
	var err error
	if *fileF != "" {
		payload, err = readSecretFile(*fileF)
		must(err)
	} else {
		payload, err = readSecretTTY(fmt.Sprintf("Enter credential for %s (input hidden): ", *bindingF))
		must(err)
	}
	defer clearCLISecret(payload)
	params := map[string]interface{}{
		"binding": *bindingF, "kind": *kindF, "service": *serviceF,
		"label": *labelF, "mode": *modeF, "operations": ops,
		"value_b64": base64.StdEncoding.EncodeToString(payload),
	}
	if *descF != "" {
		params["description"] = *descF
	}
	if *requestIDF != "" {
		params["request_id"] = *requestIDF
	}
	data, err := icli.Call(ipc.MethodIntakeCredentialSave, params)
	must(err)
	m, _ := data.(map[string]interface{})
	// The durable request ID is the reconciliation anchor for every
	// retry: always surfaced, prominently.
	reqID, _ := m["request_id"].(string)
	fmt.Printf("request_id: %s (reconciliation anchor — reuse with --request-id on retries)\n", reqID)
	printJSON(data)
}

// readSecretTTY collects one hidden field from the user's own terminal
// (QR-02). It drives /dev/tty directly (never stdin, which may be a
// pipe the agent controls), keeps the value out of history, argv and
// environment, and restores the terminal on every path.
func readSecretTTY(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no terminal for secure input (use --file): %w", err)
	}
	defer tty.Close()
	return readSecretFromTTY(tty, prompt)
}

// readSecretFromTTY collects one hidden field on an already-open terminal
// handle (F06 testability: PTY regression tests drive this without a
// human). Library-backed no-echo mode avoids external stty processes and
// is restored on every path. EOF with a partial line is refused: unlike
// x/term's password helper, a truncated value must never be submitted.
func readSecretFromTTY(tty *os.File, prompt string) ([]byte, error) {
	fd := int(tty.Fd())
	saved, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("terminal does not support no-echo input (use --file)")
	}
	// Restore the terminal on every path (C09). MakeRaw's own restore
	// handles normal exits; this handles early returns and interrupts.
	defer func() { _ = term.Restore(fd, saved) }()
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("cannot disable terminal echo (use --file)")
	}
	defer term.Restore(fd, old)
	fmt.Fprint(tty, prompt)
	var line []byte
	buf := make([]byte, 1)
	for {
		n, readErr := tty.Read(buf)
		// C09: partial read on interruption must never submit a truncated
		// value. Cancel and clear the partial bytes.
		if readErr != nil {
			for i := range line {
				line[i] = 0
			}
			return nil, fmt.Errorf("input interrupted: %w", readErr)
		}
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				fmt.Fprint(tty, "\r\n")
				if len(line) == 0 {
					return nil, fmt.Errorf("empty value refused")
				}
				return line, nil
			case 0x03, 0x04: // explicit Ctrl+C / Ctrl+D cancellation
				fmt.Fprint(tty, "\r\n")
				for i := range line {
					line[i] = 0
				}
				return nil, fmt.Errorf("input cancelled")
			case 0x7f, 0x08:
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
			default:
				if buf[0] < 32 {
					continue
				}
				if len(line) >= maxRelayCLIPayload {
					for i := range line {
						line[i] = 0
					}
					return nil, fmt.Errorf("value too large")
				}
				line = append(line, buf[0])
			}
			continue
		}
		if readErr != nil || n == 0 {
			// EOF with a partial line is deliberately refused; unlike
			// x/term's password helper it must not be treated as input.
			for i := range line {
				line[i] = 0
			}
			return nil, fmt.Errorf("input cancelled")
		}
	}
}

// readSecretFile loads a payload file defensively (QR-02): no symlink
// following, regular files only, bounded size, and a warning (not a
// silent accept) when the file is visible beyond its owner. The user's
// source file is never modified or deleted.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open payload file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("payload must be a regular file")
	}
	if fi.Size() == 0 || fi.Size() > maxRelayCLIPayload {
		return nil, fmt.Errorf("payload file must be 1..%d bytes", maxRelayCLIPayload)
	}
	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: payload file is visible beyond its owner (mode %o)\n", perm)
	}
	buf := make([]byte, fi.Size())
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			clearCLISecret(buf)
			return nil, fmt.Errorf("cannot read payload file")
		}
	}
	return buf, nil
}

func clearCLISecret(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
