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
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
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

	saved, err := sttyMode(tty)
	if err != nil {
		return fmt.Errorf("terminal does not support raw input: %w", err)
	}
	restore := func() { _ = restoreMode(tty, saved) }
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

	if err := setRaw(tty); err != nil {
		return err
	}
	defer func() { _ = showCursor(tty) }()

	ui := &session{tty: tty, cfg: cfg, sel: 0, winch: winch}
	return ui.loop(saved)
}

type session struct {
	tty      *os.File
	cfg      Config
	items    []item
	sel      int
	status   string
	lastPoll time.Time
	winch    <-chan os.Signal
}

func (s *session) loop(saved string) error {
	_ = saved
	s.refresh()
	reader := bufio.NewReader(s.tty)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	// A dead terminal (EOF/EIO on every read) exits instead of spinning:
	// read deadlines are routine timeouts, but consecutive REAL input
	// errors mean the operator's terminal is gone (F06 EOF semantics).
	deadReads := 0
	for {
		s.render()
		if time.Since(s.lastPoll) >= s.cfg.PollInterval {
			s.refresh()
		}
		select {
		case <-tick.C:
		case <-s.winch:
		default:
		}
		_ = s.tty.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		b, err := reader.ReadByte()
		_ = s.tty.SetReadDeadline(time.Time{})
		if err != nil {
			if os.IsTimeout(err) {
				continue // routine tick: re-render / re-poll
			}
			deadReads++
			if deadReads >= 5 {
				return fmt.Errorf("terminal input lost")
			}
			continue
		}
		deadReads = 0
		// Handle escape sequences (arrows) minimally.
		if b == 0x1b {
			_ = s.tty.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			c1, e1 := reader.ReadByte()
			c2, e2 := reader.ReadByte()
			_ = s.tty.SetReadDeadline(time.Time{})
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
	s.refresh()
}

// render draws the inbox. It never prints secret material: this view only
// ever holds payload-free rows, and masked input echoes '*' per rune.
func (s *session) render() {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear (fullscreen, no scrollback growth)
	b.WriteString("SeqPass trusted intake — j/k move, Enter fulfill, r reject, R refresh, q quit\r\n")
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

// confirm reads a y/N answer in cooked-restore mode on /dev/tty.
func (s *session) confirm(prompt string) bool {
	_ = setCooked(s.tty)
	fmt.Fprint(s.tty, "\r\n"+prompt)
	rd := bufio.NewReader(s.tty)
	line, _ := rd.ReadString('\n')
	_ = setRaw(s.tty)
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// readMasked collects one hidden field with '*' echo. Ctrl+C / EOF aborts
// with no partial submission; the buffer is owned by the caller.
func (s *session) readMasked(prompt string) ([]byte, error) {
	_ = setCooked(s.tty)
	defer setRaw(s.tty)
	fmt.Fprint(s.tty, "\r\n"+prompt)
	// Disable echo for the secret line, restore right after.
	saved, err := sttyMode(s.tty)
	if err != nil {
		return nil, err
	}
	off := exec.Command("stty", "-echo")
	off.Stdin = s.tty
	if err := off.Run(); err != nil {
		return nil, fmt.Errorf("cannot disable echo")
	}
	defer restoreMode(s.tty, saved)
	rd := bufio.NewReader(s.tty)
	var buf []byte
	for {
		c, err := rd.ReadByte()
		if err != nil {
			clearBytes(buf)
			return nil, fmt.Errorf("input cancelled")
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

// --- terminal modes (library-free, no external stty dependency for the
// steady state; stty is used only for one-shot save/restore/echo toggles).
func sttyMode(tty *os.File) (string, error) {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = tty
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func restoreMode(tty *os.File, saved string) error {
	cmd := exec.Command("stty", saved)
	cmd.Stdin = tty
	return cmd.Run()
}

func setRaw(tty *os.File) error {
	cmd := exec.Command("stty", "-echo", "-icanon", "min", "1", "time", "0")
	cmd.Stdin = tty
	return cmd.Run()
}

func setCooked(tty *os.File) error {
	cmd := exec.Command("stty", "echo", "icanon")
	cmd.Stdin = tty
	return cmd.Run()
}

func showCursor(tty *os.File) error {
	_, err := fmt.Fprint(tty, "\x1b[?25h")
	return err
}
