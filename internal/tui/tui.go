// Package tui is the persistent native inbox for trusted human intake
// (F06). It runs in the operator's OWN terminal session — never inside
// the agent's instrumented terminal — and talks only to the intake
// socket. Pending requests appear automatically via polling; selecting
// one shows the broker-verified envelope (requester, pinned recipient,
// delivery count, expiry) with agent-supplied text labeled UNTRUSTED and
// neutralized before it reaches the layout; approval collects the value
// through a hidden field that is never echoed (so neither the value nor its
// length reaches the terminal transcript) and is zeroed after submission.
//
// Terminal handling uses golang.org/x/term for raw mode and state save and
// restore; every other byte of the protocol (key input, escape sequences,
// bracketed paste) is decoded in this package.
//
// Raw key input is driven through /dev/tty with the terminal mode saved and
// restored on every exit path, including a termination
// signal — the signal path unwinds the same defers rather than exiting the
// process from a goroutine.
package tui

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
	"golang.org/x/term"
)

// InterruptError reports that the session ended because a termination signal
// arrived. The terminal has already been restored when this is returned, so
// the caller only has to choose the exit status: 128+signal, the convention
// every shell understands.
type InterruptError struct{ Signal syscall.Signal }

func (e *InterruptError) Error() string {
	return "interrupted by " + e.Signal.String()
}

// Config for the TUI session.
type Config struct {
	IntakeSocket string
	PollInterval time.Duration
}

// item is one pending request row (payload-free by construction).
type item struct {
	id          string
	agent       string
	dest        string
	kind        string
	expires     string
	consumption string
	max         float64
	purpose     string
	state       string
	revision    uint64
}

// Run starts the fullscreen inbox on the operator's own terminal. It
// returns only on quit or fatal error.
func Run(cfg Config) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("tui needs its own terminal (/dev/tty): %w", err)
	}
	defer tty.Close()
	return RunOnFile(cfg, tty)
}

// RunOnFile drives the inbox on an already-open terminal handle (F06
// testability: PTY regression tests pass a pty slave here and drive the
// full fulfill flow without a human).
func RunOnFile(cfg Config, tty *os.File) error {
	// F06: terminal restoration must survive signals, not just returns. The
	// handler only delivers the signal to the session loop; the loop returns,
	// the deferred restores run, and the caller picks the exit status. An
	// os.Exit in the handler would skip the raw-mode restore, leave the
	// operator's terminal unusable, and make the path untestable.
	termSig := make(chan os.Signal, 1)
	signal.Notify(termSig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(termSig)
	// F06: terminal resize re-renders instead of corrupting the review
	// layout (the loop redraws every tick regardless).
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	return runOnFile(cfg, tty, winch, termSig)
}

// runOnFile installs raw mode and the restore defers, then runs the session.
// The signal channels are parameters so the termination and resize paths can
// be driven deterministically, without signalling the test process.
func runOnFile(cfg Config, tty *os.File, winch, termSig <-chan os.Signal) error {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}

	fd := int(tty.Fd())
	saved, err := term.GetState(fd)
	if err != nil {
		return fmt.Errorf("terminal does not support raw input: %w", err)
	}
	defer func() { _ = term.Restore(fd, saved) }()

	raw, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer func() {
		_ = term.Restore(fd, raw)
		_ = showCursor(tty)
	}()

	return runSession(cfg, tty, winch, termSig)
}

// runSession is the terminal-independent body of a TUI session, without any
// terminal-mode changes.
func runSession(cfg Config, tty *os.File, winch, termSig <-chan os.Signal) error {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	ui := &session{tty: tty, cfg: cfg, sel: 0, winch: winch, term: termSig}
	return ui.loop()
}

type session struct {
	tty      *os.File
	cfg      Config
	items    []item
	sel      int
	status   string
	lastPoll time.Time
	winch    <-chan os.Signal
	term     <-chan os.Signal
	input    <-chan byte
	inputEnd <-chan struct{}
	// stickyUntil, while in the future, prevents the polling loop from
	// replacing a status line the operator needs to read (an authorization
	// outcome or an action failure). Without it the next poll overwrites the
	// one line that explains what just happened.
	stickyUntil time.Time
	// termSignal holds a termination request that arrived while a prompt had
	// the input reader. A prompt must abort on it, and the loop must then end
	// the session with InterruptError: swallowing the signal would leave the
	// terminal in raw mode until a supervisor escalates to SIGKILL, which
	// skips every restore.
	termSignal os.Signal
}

// interrupted reports and clears a termination request that a prompt
// absorbed, if any. Clearing keeps the recorded signal from being re-read as
// a fresh verdict later in the same session.
func (s *session) interrupted() error {
	if sig := s.termSignal; sig != nil {
		s.termSignal = nil
		return &InterruptError{Signal: sigNum(sig)}
	}
	return nil
}

// stickyDuration is how long an operator-action status survives polling.
const stickyDuration = 10 * time.Second

// setSticky sets a status that polling must not overwrite.
func (s *session) setSticky(msg string) {
	s.status = msg
	s.stickyUntil = time.Now().Add(stickyDuration)
}

// setTransient sets the ambient status line, unless a sticky message set by
// an operator action is still current.
func (s *session) setTransient(msg string) {
	if time.Now().Before(s.stickyUntil) {
		return
	}
	s.status = msg
}

// startInput reads raw terminal bytes in the background so the UI loop
// can always select on refresh ticks. Closing the channel or ending the
// reader signals terminal loss; buffered capacity one is enough because
// a keypress is a single byte in this input model.
func startInput(tty *os.File) (<-chan byte, <-chan struct{}) {
	in := make(chan byte, 64)
	end := make(chan struct{})
	go func() {
		defer close(end)
		defer close(in)
		var buf [1]byte
		for {
			n, err := tty.Read(buf[:])
			if err != nil || n == 0 {
				return
			}
			select {
			case in <- buf[0]:
			case <-end:
				return
			}
		}
	}()
	return in, end
}

func (s *session) loop() error {
	s.input, s.inputEnd = startInput(s.tty)
	s.refresh()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		s.render()
		if time.Since(s.lastPoll) >= s.cfg.PollInterval {
			s.refresh()
		}
		var b byte
		var ok bool
		select {
		case <-tick.C:
			continue
		case <-s.winch:
			continue
		case sig := <-s.term:
			s.clearScreen()
			return &InterruptError{Signal: sigNum(sig)}
		case b, ok = <-s.input:
			if !ok {
				return fmt.Errorf("terminal input lost")
			}
		}
		// Handle escape sequences (arrows) minimally.
		if b == 0x1b {
			var seq [2]byte
			select {
			case c, ok := <-s.input:
				seq[0] = c
				if !ok {
					return fmt.Errorf("terminal input lost")
				}
			case <-s.inputEnd:
				return fmt.Errorf("terminal input lost")
			}
			select {
			case c, ok := <-s.input:
				seq[1] = c
				if !ok {
					return fmt.Errorf("terminal input lost")
				}
			case <-s.inputEnd:
				return fmt.Errorf("terminal input lost")
			}
			e1, e2 := error(nil), error(nil)
			c1, c2 := seq[0], seq[1]
			if e1 == nil && e2 == nil && c1 == '[' {
				switch c2 {
				case 'A':
					b = 'k'
				case 'B':
					b = 'j'
				default:
					continue
				}
			} else {
				continue
			}
		}
		switch b {
		case 'q', 0x03: // q or Ctrl+C: cancel, never submit partial state
			s.clearScreen()
			return nil
		case 'j':
			if s.sel+1 < len(s.items) {
				s.sel++
			}
		case 'k':
			if s.sel > 0 {
				s.sel--
			}
		case 'R':
			s.refresh()
		case 'r':
			if err := s.doReject(); err != nil {
				return err
			}
		case 's':
			if err := s.doCredentialSave(); err != nil {
				return err
			}
		case '\r', '\n':
			if err := s.doFulfill(); err != nil {
				return err
			}
		}
		// A termination request absorbed by a prompt ends the session through
		// the same unwind as a signal in the loop itself.
		if err := s.interrupted(); err != nil {
			s.clearScreen()
			return err
		}
	}
}

func (s *session) dial() (*ipc.Client, error) {
	return ipc.Dial(s.cfg.IntakeSocket)
}

func (s *session) refresh() {
	cli, err := s.dial()
	if err != nil {
		s.setTransient("broker unreachable: " + err.Error())
		return
	}
	defer cli.Close()
	data, err := cli.Call(ipc.MethodIntakeInspect, nil)
	if err != nil {
		s.setTransient("inbox error: " + err.Error())
		return
	}
	raw, _ := data.([]interface{})
	var items []item
	for _, it := range raw {
		m, _ := it.(map[string]interface{})
		if m == nil {
			continue
		}
		id := str(m["id"])
		rev, ok := uintField(m["revision"])
		if id == "" || !ok {
			// Without a stable id and revision the row cannot be acted on
			// safely (the broker would reject a stale revision), so it is
			// not shown as selectable. It is also not a panic: a broker
			// response is untrusted input at this boundary.
			continue
		}
		mx, _ := m["max_deliveries"].(float64)
		items = append(items, item{
			id:          id,
			agent:       str(m["agent_principal"]),
			dest:        str(m["destination_id"]),
			kind:        str(m["data_kind"]),
			expires:     str(m["expires_at"]),
			consumption: str(m["consumption"]),
			max:         mx,
			revision:    rev,
			purpose:     str(m["purpose"]),
			state:       str(m["state"]),
		})
	}
	s.items = items
	if s.sel >= len(s.items) && len(s.items) > 0 {
		s.sel = len(s.items) - 1
	}
	if s.sel < 0 {
		s.sel = 0
	}
	s.lastPoll = time.Now()
	s.setTransient(fmt.Sprintf("%d pending — auto-refresh %s", len(items), s.cfg.PollInterval))
}

func (s *session) doReject() error {
	if len(s.items) == 0 {
		return nil
	}
	it := s.items[s.sel]
	if !s.confirm("Reject " + neutralize(it.id) + "? [y/N]: ") {
		if err := s.interrupted(); err != nil {
			return err
		}
		s.setSticky("reject cancelled")
		return nil
	}
	cli, err := s.dial()
	if err != nil {
		s.setSticky("broker unreachable")
		return nil
	}
	defer cli.Close()
	if _, err := cli.Call(ipc.MethodIntakeReject, map[string]interface{}{
		"request_id":       it.id,
		"request_revision": it.revision,
	}); err != nil {
		s.setSticky("reject failed: " + err.Error())
		return nil
	}
	s.setSticky("rejected " + neutralize(it.id))
	s.refresh()
	return nil
}

func (s *session) doFulfill() error {
	if len(s.items) == 0 {
		return nil
	}
	it := s.items[s.sel]
	s.renderDetail(it)
	secret, err := s.readMasked("Value for " + neutralize(it.kind) + " (hidden, not echoed; Enter accepts, Ctrl+C cancels): ")
	if err != nil {
		// A termination request absorbed by the prompt must end the session,
		// not be misread as the operator declining.
		if ie := s.interrupted(); ie != nil {
			return ie
		}
		s.setSticky("cancelled: no payload sent")
		return nil
	}
	defer clearBytes(secret)
	if len(secret) == 0 {
		s.setSticky("empty value refused")
		return nil
	}
	if !s.confirm("Deliver to " + neutralize(it.dest) + "? [y/N]: ") {
		if ie := s.interrupted(); ie != nil {
			return ie
		}
		s.setSticky("declined: no payload sent")
		return nil
	}
	cli, err := s.dial()
	if err != nil {
		s.setSticky("broker unreachable")
		return nil
	}
	defer cli.Close()
	res, err := cli.Call(ipc.MethodIntakeFulfill, map[string]interface{}{
		"request_id":       it.id,
		"request_revision": it.revision,
		"payload":          base64.StdEncoding.EncodeToString(secret),
	})
	if err != nil {
		s.setSticky("fulfill failed: " + err.Error())
		return nil
	}
	m, _ := res.(map[string]interface{})
	// The outcome is sticky: the next poll must not replace it with the
	// pending count before the operator has read it.
	s.setSticky(fmt.Sprintf("authorized %s op=%v — watch status view", neutralize(it.id), neutralize(str(m["op_id"]))))
	// Render immediately so the message appears without waiting for a tick,
	// then poll: the sticky status survives the poll.
	s.render()
	s.refresh()
	return nil
}

// render draws the inbox. It never prints secret material: this view only
// ever holds payload-free rows. Hidden input is never echoed at all, so
// neither the value nor its length can reach the terminal transcript.
func (s *session) render() {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear (fullscreen, no scrollback growth)
	b.WriteString("SeqPass trusted intake — j/k move, Enter fulfill, r reject, s credential-save, R refresh, q quit\r\n")
	b.WriteString("Input route: external TTY. Protection depends on broker topology;\r\n")
	b.WriteString("same-UID best-effort deployments are NOT protected from the agent.\r\n")
	b.WriteString("Agent purpose lines below are UNTRUSTED agent text (neutralized).\r\n")
	b.WriteString("──────────────────────────────────────────────\r\n")
	if len(s.items) == 0 {
		b.WriteString("(no pending requests)\r\n")
	}
	for i, it := range s.items {
		mark := "  "
		if i == s.sel {
			mark = "> "
		}
		fmt.Fprintf(&b, "%s%s kind=%s dest=%s usage=%s expires=%s\r\n", mark,
			neutralize(it.id), neutralize(it.kind), neutralize(it.dest), usage(it), expiresLabel(it.expires))
		fmt.Fprintf(&b, "    from=%s purpose=%s\r\n", neutralize(it.agent), sanitize(it.purpose))
	}
	b.WriteString("──────────────────────────────────────────────\r\n")
	b.WriteString("status: " + neutralize(s.status) + "\r\n")
	fmt.Fprint(s.tty, b.String())
}

func (s *session) renderDetail(it item) {
	fmt.Fprintf(s.tty, "\r\nREQUEST REVIEW (broker-verified — approve only what is shown)\r\n  Requester: %s\r\n  Recipient: %s (registered destination)\r\n  Action:    supply %s\r\n  Usage:     %s\r\n  Expires:   %s\r\n  Agent note (UNTRUSTED): %s\r\n",
		neutralize(it.agent), neutralize(it.dest), neutralize(it.kind), usage(it), expiresLabel(it.expires), sanitize(it.purpose))
}

// readLine collects one visible single-line field from the shared input
// channel (TUI credentials-save form fields — never secret material; the
// secret uses readMasked). Empty string = cancelled/empty field.
func (s *session) readLine(prompt string) string {
	fmt.Fprint(s.tty, "\r\n"+prompt)
	defer s.clearScreen()
	var line []byte
	for {
		b, ok := <-s.input
		if !ok {
			return ""
		}
		switch b {
		case 0x03: // Ctrl+C
			return ""
		case '\r', '\n':
			return string(line)
		case 0x7f, 0x08: // backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				fmt.Fprint(s.tty, "\b \b")
			}
		default:
			if b >= 0x20 && b < 0x7f && len(line) < 256 {
				line = append(line, b)
				fmt.Fprint(s.tty, string(b))
			}
		}
	}
}

// doCredentialSave is the P0-3 trusted-intake persistence action (key
// 's'): collect a credential via the EXISTING masked-input capability and
// submit it through intake.credential_save. The TUI reuses the same
// trusted envelope discipline as fulfillment: the value crosses once as
// base64 over the intake socket and is never echoed, logged, or persisted
// by SeqPass — only stable references (request ID, record ID, binding ID)
// come back. Persistence is a trusted-operator decision with an explicit
// confirmation; the agent surface has no equivalent capability.
func (s *session) doCredentialSave() error {
	binding := s.readLine("Binding (e.g. seqpass/deploy-token): ")
	if binding == "" {
		s.setSticky("cancelled: binding required")
		return nil
	}
	kind := s.readLine("Kind (api-key|token|password|...): ")
	if kind == "" {
		s.setSticky("cancelled: kind required")
		return nil
	}
	serviceName := s.readLine("Service identity: ")
	if serviceName == "" {
		s.setSticky("cancelled: service required")
		return nil
	}
	ops := s.readLine("Operation scope (comma-separated, e.g. http.request): ")
	if ops == "" {
		s.setSticky("cancelled: operation scope required (operation-scoped binding contract)")
		return nil
	}
	mode := s.readLine("Persistence mode (save_only|save_and_use|use_once) [save_only]: ")
	if mode == "" {
		mode = "save_only"
	}
	secret, err := s.readMasked("Credential value (hidden, not echoed; Enter accepts, Ctrl+C cancels): ")
	if err != nil {
		// A termination request absorbed by the prompt must end the session,
		// not be misread as the operator declining.
		if ie := s.interrupted(); ie != nil {
			return ie
		}
		s.setSticky("cancelled: no credential sent")
		return nil
	}
	defer clearBytes(secret)
	if len(secret) == 0 {
		s.setSticky("empty value refused")
		return nil
	}
	if !s.confirm(fmt.Sprintf("Save credential for %s in AegisKeys (mode %s)? [y/N]: ", neutralize(binding), neutralize(mode))) {
		if ie := s.interrupted(); ie != nil {
			return ie
		}
		s.setSticky("declined: no credential sent")
		return nil
	}
	cli, err := s.dial()
	if err != nil {
		s.setSticky("broker unreachable")
		return nil
	}
	defer cli.Close()
	var opList []interface{}
	for _, op := range strings.Split(ops, ",") {
		if op = strings.TrimSpace(op); op != "" {
			opList = append(opList, op)
		}
	}
	res, err := cli.Call(ipc.MethodIntakeCredentialSave, map[string]interface{}{
		"binding":    binding,
		"kind":       kind,
		"service":    serviceName,
		"label":      serviceName,
		"mode":       mode,
		"operations": opList,
		"value_b64":  base64.StdEncoding.EncodeToString(secret),
	})
	if err != nil {
		// The durable reference may still exist (write-ahead): surface the
		// reconciliation anchor so the operator can retry/reconcile.
		s.setSticky("save failed: " + err.Error() + " (retry reuses the same request ID)")
		return nil
	}
	m, _ := res.(map[string]interface{})
	if saved, _ := m["saved"].(bool); !saved {
		s.setSticky("not saved: " + neutralize(str(m["provider_status"])))
		return nil
	}
	reqID := neutralize(str(m["request_id"]))
	if use, ok := m["use_outcome"].(map[string]interface{}); ok {
		if executed, _ := use["executed"].(bool); executed {
			s.setSticky(fmt.Sprintf("saved + used (request %s)", reqID))
		} else {
			s.setSticky(fmt.Sprintf("SAVED, authorization pending (request %s) — approve the staged grant, then submit the protected-use request", reqID))
		}
		return nil
	}
	s.setSticky(fmt.Sprintf("saved, authorization pending (request %s) — approve the staged resolver grant before resolves succeed", reqID))
	return nil
}

// confirm reads a y/N answer through the shared input channel, so no
// bytes are stranded in a second reader between prompts. A termination
// request is recorded on the session: the caller checks it and ends the
// session, so a signal cannot be mistaken for the operator answering no.
func (s *session) confirm(prompt string) bool {
	fmt.Fprint(s.tty, "\r\n"+prompt)
	var line []byte
	for {
		var c byte
		var ok bool
		select {
		case sig := <-s.term:
			// A termination request must abort a pending prompt, not be
			// queued behind it or read as a "no".
			s.termSignal = sig
			return false
		case <-s.inputEnd:
			return false
		case c, ok = <-s.input:
			if !ok {
				return false
			}
		}
		if c == '\n' || c == '\r' {
			break
		}
		line = append(line, c)
	}
	text := strings.TrimSpace(strings.ToLower(string(line)))
	return text == "y" || text == "yes"
}

// readMasked collects one hidden field from the shared input channel. The
// decoding lives in maskedInput, which is unit-tested without a terminal.
// Ctrl+C / Ctrl+D / termination / EOF aborts with no partial submission; the
// returned buffer is owned by the caller and must be cleared.
//
// Nothing is echoed while the operator types: not the characters (they would
// land in scrollback) and not a placeholder per character (that would
// disclose the length of the value).
func (s *session) readMasked(prompt string) ([]byte, error) {
	fmt.Fprint(s.tty, "\r\n"+prompt)
	st := &maskedInput{}
	for {
		var c byte
		var ok bool
		select {
		case sig := <-s.term:
			// Record the signal so the caller ends the session: returning
			// ErrInterrupted alone would read as an operator cancel.
			s.termSignal = sig
			clearBytes(st.buf)
			return nil, ErrInterrupted
		case <-s.inputEnd:
			clearBytes(st.buf)
			return nil, ErrCancelled
		case c, ok = <-s.input:
			if !ok {
				clearBytes(st.buf)
				return nil, ErrCancelled
			}
		}
		if st.feed(c) {
			break
		}
	}
	fmt.Fprint(s.tty, "\r\n")
	if st.err != nil {
		clearBytes(st.buf)
		return nil, st.err
	}
	return st.buf, nil
}

func (s *session) clearScreen() {
	fmt.Fprint(s.tty, "\x1b[H\x1b[2J")
}

func usage(it item) string {
	switch it.consumption {
	case "reusable_until_expiry":
		if it.max <= 0 {
			return "REUSABLE UNTIL EXPIRY; UNLIMITED deliveries"
		}
		return fmt.Sprintf("reusable, up to %d", int(it.max))
	case "bounded_uses":
		if it.max > 1 {
			return fmt.Sprintf("bounded, up to %d", int(it.max))
		}
		return "bounded, one delivery"
	default:
		return "ONE delivery only"
	}
}

// sanitize neutralizes agent-supplied text and substitutes a placeholder when
// the agent gave no reason. It is applied at render time, never to the values
// the broker is called with.
func sanitize(s string) string {
	out := neutralize(s)
	if strings.TrimSpace(out) == "" {
		return "(no reason given)"
	}
	return out
}

// neutralize mirrors the CLI neutralizer (F10): no ANSI/OSC/bidi/control may
// reshape the trusted review layout. Every field that comes from the broker
// passes through here before it is written to the terminal, including the
// fields the agent influences (data kind, purpose, principal).
func neutralize(s string) string {
	if s == "" {
		return ""
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
	if r := []rune(out); len(r) > 120 {
		return string(r[:120]) + "…"
	}
	return out
}

// expiresLabel renders a deadline as the time remaining. A raw RFC3339
// timestamp is long enough to push the rest of the review line off the
// screen, and the operator's question is always "how long do I have".
func expiresLabel(raw string) string {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return neutralize(raw)
	}
	d := time.Until(t)
	if d <= 0 {
		return "EXPIRED"
	}
	return "in " + d.Round(time.Second).String()
}

// uintField reads a JSON number as a uint64 without ever panicking on a
// missing, null or non-numeric field.
func uintField(v interface{}) (uint64, bool) {
	f, ok := v.(float64)
	if !ok || f < 0 || f != f || f > 1<<53 {
		return 0, false
	}
	return uint64(f), true
}

// sigNum reports the signal number for the conventional 128+signal status.
func sigNum(sig os.Signal) syscall.Signal {
	if s, ok := sig.(syscall.Signal); ok {
		return s
	}
	return syscall.SIGINT
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func showCursor(tty *os.File) error {
	_, err := fmt.Fprint(tty, "\x1b[?25h")
	return err
}
