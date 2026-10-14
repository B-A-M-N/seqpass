// Package tui is the persistent native inbox for trusted human intake
// (F06). It runs in the operator's OWN terminal session — never inside
// the agent's instrumented terminal — and talks only to the intake
// socket. Pending requests appear automatically via polling; selecting
// one shows the broker-verified envelope (requester, pinned recipient,
// delivery count, expiry) with the agent's purpose labeled UNTRUSTED and
// sanitized; approval collects the value through a masked field that is
// cleared after submission and never echoed into scrollback.
//
// stdlib-only: raw key input is driven through /dev/tty with the terminal
// mode saved and restored on every exit path (including signals).
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
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}

	fd := int(tty.Fd())
	saved, err := term.GetState(fd)
	if err != nil {
		return fmt.Errorf("terminal does not support raw input: %w", err)
	}
	restore := func() { _ = term.Restore(fd, saved) }
	defer restore()

	// F06: terminal restoration must survive signals, not just returns.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigc)
	// F06: terminal resize re-renders instead of corrupting the review
	// layout (the loop redraws every tick regardless).
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		<-sigc
		restore()
		_ = showCursor(tty)
		os.Exit(130)
	}()

	raw, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer func() {
		_ = term.Restore(fd, raw)
		_ = showCursor(tty)
	}()

	ui := &session{tty: tty, cfg: cfg, sel: 0, winch: winch}
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
	input    <-chan byte
	inputEnd <-chan struct{}
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
			s.doReject()
		case '\r', '\n':
			s.doFulfill()
		}
	}
}

func (s *session) dial() (*ipc.Client, error) {
	return ipc.Dial(s.cfg.IntakeSocket)
}

func (s *session) refresh() {
	cli, err := s.dial()
	if err != nil {
		s.status = "broker unreachable: " + err.Error()
		return
	}
	defer cli.Close()
	data, err := cli.Call(ipc.MethodIntakeInspect, nil)
	if err != nil {
		s.status = "inbox error: " + err.Error()
		return
	}
	raw, _ := data.([]interface{})
	var items []item
	for _, it := range raw {
		m, _ := it.(map[string]interface{})
		if m == nil {
			continue
		}
		mx, _ := m["max_deliveries"].(float64)
		items = append(items, item{
			id:          str(m["id"]),
			agent:       str(m["agent_principal"]),
			dest:        str(m["destination_id"]),
			kind:        str(m["data_kind"]),
			expires:     str(m["expires_at"]),
			consumption: str(m["consumption"]),
			max:         mx,
			purpose:     sanitize(str(m["purpose"])),
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
	s.status = fmt.Sprintf("%d pending — auto-refresh %s", len(items), s.cfg.PollInterval)
}

func (s *session) doReject() {
	if len(s.items) == 0 {
		return
	}
	it := s.items[s.sel]
	if !s.confirm("Reject " + it.id + "? [y/N]: ") {
		s.status = "reject cancelled"
		return
	}
	cli, err := s.dial()
	if err != nil {
		s.status = "broker unreachable"
		return
	}
	defer cli.Close()
	if _, err := cli.Call(ipc.MethodIntakeReject, map[string]interface{}{"request_id": it.id}); err != nil {
		s.status = "reject failed: " + err.Error()
		return
	}
	s.status = "rejected " + it.id
	s.refresh()
}

func (s *session) doFulfill() {
	if len(s.items) == 0 {
		return
	}
	it := s.items[s.sel]
	s.renderDetail(it)
	secret, err := s.readMasked("Value for " + it.kind + " (hidden, Ctrl+C cancels): ")
	if err != nil {
		s.status = "cancelled: no payload sent"
		return
	}
	defer clearBytes(secret)
	if len(secret) == 0 {
		s.status = "empty value refused"
		return
	}
	if !s.confirm("Deliver to " + it.dest + "? [y/N]: ") {
		s.status = "declined: no payload sent"
		return
	}
	cli, err := s.dial()
	if err != nil {
		s.status = "broker unreachable"
		return
	}
	defer cli.Close()
	res, err := cli.Call(ipc.MethodIntakeFulfill, map[string]interface{}{
		"request_id": it.id,
		"payload":    base64.StdEncoding.EncodeToString(secret),
	})
	if err != nil {
		s.status = "fulfill failed: " + err.Error()
		return
	}
	m, _ := res.(map[string]interface{})
	s.status = fmt.Sprintf("authorized %s op=%v — watch status view", it.id, m["op_id"])
	// Render the success message before refreshing so it is visible
	// in the terminal transcript before the next poll overwrites it.
	s.render()
	s.refresh()
}

// render draws the inbox. It never prints secret material: this view only
// ever holds payload-free rows, and masked input echoes '*' per rune.
func (s *session) render() {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear (fullscreen, no scrollback growth)
	b.WriteString("SeqPass trusted intake — j/k move, Enter fulfill, r reject, R refresh, q quit\r\n")
	b.WriteString("Input route: external TTY. Protection depends on broker topology;\r\n")
	b.WriteString("same-UID best-effort deployments are NOT protected from the agent.\r\n")
	b.WriteString("Agent purpose lines below are UNTRUSTED agent text (sanitized).\r\n")
	b.WriteString("──────────────────────────────────────────────\r\n")
	if len(s.items) == 0 {
		b.WriteString("(no pending requests)\r\n")
	}
	for i, it := range s.items {
		mark := "  "
		if i == s.sel {
			mark = "> "
		}
		fmt.Fprintf(&b, "%s%s kind=%s dest=%s usage=%s expires=%s\r\n", mark, it.id, it.kind, it.dest, usage(it), it.expires)
		fmt.Fprintf(&b, "    from=%s purpose=%s\r\n", it.agent, it.purpose)
	}
	b.WriteString("──────────────────────────────────────────────\r\n")
	b.WriteString("status: " + s.status + "\r\n")
	fmt.Fprint(s.tty, b.String())
}

func (s *session) renderDetail(it item) {
	fmt.Fprintf(s.tty, "\r\nREQUEST REVIEW (broker-verified — approve only what is shown)\r\n  Requester: %s\r\n  Recipient: %s (registered destination)\r\n  Action:    supply %s\r\n  Usage:     %s\r\n  Expires:   %s\r\n  Agent note (UNTRUSTED): %s\r\n", it.agent, it.dest, it.kind, usage(it), it.expires, it.purpose)
}

// confirm reads a y/N answer through the shared input channel, so no
// bytes are stranded in a second reader between prompts.
func (s *session) confirm(prompt string) bool {
	fmt.Fprint(s.tty, "\r\n"+prompt)
	var line []byte
	for {
		var c byte
		var ok bool
		select {
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

// readMasked collects one hidden field with '*' echo from the shared
// input channel. Ctrl+C / EOF aborts with no partial submission; the
// buffer is owned by the caller. Using the same channel as the main
// loop prevents one reader from consuming bytes intended for another.
func (s *session) readMasked(prompt string) ([]byte, error) {
	fmt.Fprint(s.tty, "\r\n"+prompt)
	var buf []byte
	for {
		var c byte
		var ok bool
		select {
		case <-s.inputEnd:
			clearBytes(buf)
			return nil, fmt.Errorf("input cancelled")
		case c, ok = <-s.input:
			if !ok {
				clearBytes(buf)
				return nil, fmt.Errorf("input cancelled")
			}
		}
		if c == '\n' || c == '\r' {
			fmt.Fprint(s.tty, "\r\n")
			break
		}
		if c == 0x03 || c == 0x04 { // Ctrl+C / Ctrl+D
			fmt.Fprint(s.tty, "\r\n")
			clearBytes(buf)
			return nil, fmt.Errorf("input cancelled")
		}
		if c == 0x7f || c == 0x08 { // backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
			continue
		}
		if c < 32 {
			continue
		}
		if len(buf) >= 64*1024 {
			clearBytes(buf)
			return nil, fmt.Errorf("value too large")
		}
		buf = append(buf, c)
	}
	return buf, nil
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

// sanitize mirrors the CLI neutralizer (F10): no ANSI/OSC/bidi/control
// may reshape the trusted review layout.
func sanitize(s string) string {
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
	if r := []rune(out); len(r) > 120 {
		return string(r[:120]) + "…"
	}
	return out
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
