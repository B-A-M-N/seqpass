package tui

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/ptytest"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/types"
)

// testBroker starts a service plus an intake-socket IPC server, returning
// the service and intake path. The agent principal below is arbitrary;
// intake authorizes the broker euid (same-user test topology).
func testBroker(t *testing.T) (*service.Service, string) {
	t.Helper()
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return nil, ""
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Config{
		DBPath: filepath.Join(dir, "meta.db"), VaultType: "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	euid := uint32(os.Geteuid())
	uid := euid
	if err := svc.AddDestination(&types.Destination{
		ID: "rd1", Name: "rcpt", Type: "recipient-socket",
		Endpoint: filepath.Join(dir, "recipient.sock"), ExpectedUID: &uid,
	}); err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(svc,
		filepath.Join(dir, "agent.sock"), "",
		nil, &ipc.UIDAuthorizer{
			AdminUIDs:  map[uint32]bool{euid: true},
			AgentUIDs:  map[uint32]bool{euid: true},
			IntakeUIDs: map[uint32]bool{euid: true},
		})
	intake := filepath.Join(dir, "intake.sock")
	srv.IntakeSocket = intake
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return svc, intake
}

// F06: the full trusted flow over a real terminal — inbox render, review,
// masked entry, explicit confirm, authorized submit — with a session
// recording proving the plaintext never appears in terminal output.
func TestTUIFulfillFlowNoPlaintext(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	svc, intake := testBroker(t)
	reqID, err := svc.RelayRequest("uid:agent-9", "rd1", "password", "tui e2e login", 0, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	done := make(chan error, 1)
	go func() {
		done <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 200 * time.Millisecond}, pt.Slave)
	}()
	if out := pt.WaitFor("SeqPass trusted intake", 10*time.Second); !bytes.Contains(out, []byte("SeqPass trusted intake")) {
		t.Fatalf("no TUI banner: %q", out)
	}
	if out := pt.WaitFor(reqID, 10*time.Second); !bytes.Contains(out, []byte(reqID)) {
		t.Fatalf("pending request never rendered: %q", out)
	}
	const secret = "tui-pty-secret-13579"
	if _, err := pt.Master.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("Value for", 10*time.Second); !bytes.Contains(out, []byte("Value for")) {
		t.Fatalf("no masked prompt: %q", out)
	}
	if _, err := pt.Master.Write([]byte(secret + "\n")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("Deliver to", 10*time.Second); !bytes.Contains(out, []byte("Deliver to")) {
		t.Fatalf("no final confirm: %q", out)
	}
	if _, err := pt.Master.Write([]byte("y\n")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("authorized", 10*time.Second); !bytes.Contains(out, []byte("authorized")) {
		t.Fatalf("no authorized status: %q", out)
	}
	if _, err := pt.Master.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tui quit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("tui did not quit")
	}
	transcript := pt.ReadAvailable(500 * time.Millisecond)
	if bytes.Contains(transcript, []byte(secret)) {
		t.Fatalf("plaintext reached agent-observable terminal output")
	}
	got, err := svc.DB().GetRelay(reqID)
	if err != nil || got == nil {
		t.Fatal("relay row lost")
	}
	if got.State != types.RelayAuthorized || got.OpID == "" {
		t.Fatalf("relay state = %s op = %q, want authorized with op", got.State, got.OpID)
	}
}

// F06: copy-pasted values arrive wrapped in bracketed-paste markers. They are
// terminal protocol, not content: the value must be unaffected by them, and
// the secret must still never reach terminal output.
func TestTUIFulfillBracketedPasteNoPlaintext(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	svc, intake := testBroker(t)
	reqID, err := svc.RelayRequest("uid:agent-9", "rd1", "password", "paste a value", 0, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	done := make(chan error, 1)
	go func() {
		done <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 200 * time.Millisecond}, pt.Slave)
	}()
	if out := pt.WaitFor(reqID, 10*time.Second); !bytes.Contains(out, []byte(reqID)) {
		t.Fatalf("pending request never rendered: %q", out)
	}
	if _, err := pt.Master.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("hidden, not echoed", 10*time.Second); !bytes.Contains(out, []byte("hidden, not echoed")) {
		t.Fatalf("no hidden prompt: %q", out)
	}
	// A trailing newline inside the paste is what "copy one line" produces;
	// it must not submit a truncated value, so the confirm prompt proves the
	// whole paste was consumed as content.
	const secret = "pasted-secret-98765"
	if _, err := pt.Master.Write([]byte("\x1b[200~" + secret + "\n\x1b[201~" + "\r")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("Deliver to", 10*time.Second); !bytes.Contains(out, []byte("Deliver to")) {
		t.Fatalf("no final confirm after paste: %q", out)
	}
	if _, err := pt.Master.Write([]byte("y\n")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("authorized", 10*time.Second); !bytes.Contains(out, []byte("authorized")) {
		t.Fatalf("no authorized status: %q", out)
	}
	if _, err := pt.Master.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tui quit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("tui did not quit")
	}
	if transcript := pt.ReadAvailable(500 * time.Millisecond); bytes.Contains(transcript, []byte(secret)) {
		t.Fatal("plaintext reached terminal output")
	}
	got, err := svc.DB().GetRelay(reqID)
	if err != nil || got == nil {
		t.Fatal("relay row lost")
	}
	if got.State != types.RelayAuthorized {
		t.Fatalf("relay state = %s, want authorized", got.State)
	}
}

// F06: the authorization outcome must survive the polling that follows it.
// Before this was a sticky status the very next poll replaced the line with
// the pending count, so the operator could miss what happened.
func TestTUIOutcomeSurvivesPolling(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	svc, intake := testBroker(t)
	reqID, err := svc.RelayRequest("uid:agent-9", "rd1", "password", "sticky check", 0, "single_dispatch", 1)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	done := make(chan error, 1)
	go func() {
		done <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 100 * time.Millisecond}, pt.Slave)
	}()
	if out := pt.WaitFor(reqID, 10*time.Second); !bytes.Contains(out, []byte(reqID)) {
		t.Fatalf("request never rendered: %q", out)
	}
	if _, err := pt.Master.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("Value for", 10*time.Second); !bytes.Contains(out, []byte("Value for")) {
		t.Fatalf("no prompt: %q", out)
	}
	if _, err := pt.Master.Write([]byte("sticky-secret\n")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("Deliver to", 10*time.Second); !bytes.Contains(out, []byte("Deliver to")) {
		t.Fatalf("no confirm: %q", out)
	}
	if _, err := pt.Master.Write([]byte("y\n")); err != nil {
		t.Fatal(err)
	}
	if out := pt.WaitFor("authorized", 10*time.Second); !bytes.Contains(out, []byte("authorized")) {
		t.Fatalf("no authorized status: %q", out)
	}
	// Let several poll intervals elapse; every render in that window must
	// still carry the outcome.
	latest := pt.ReadAvailable(1500 * time.Millisecond)
	if !bytes.Contains(latest, []byte("authorized")) {
		t.Fatalf("polling overwrote the authorization outcome: %q", latest)
	}
	if _, err := pt.Master.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("tui did not quit")
	}
}

// F06: a termination signal unwinds through the normal return path, so the
// terminal (raw mode and cursor) is restored before control returns. The
// previous implementation called os.Exit from a goroutine, which skipped the
// restores and was impossible to observe from a test.
func TestTUITerminationRestoresTerminal(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()

	before, err := ptytest.EchoOn(pt.Slave)
	if err != nil {
		t.Fatal(err)
	}
	if !before {
		t.Skip("pty fixture starts without ECHO")
	}

	term := make(chan os.Signal, 1)
	winch := make(chan os.Signal, 1)
	// No broker is needed: the session renders before it polls, and this test
	// is about the exit path.
	done := make(chan error, 1)
	go func() {
		done <- runOnFile(Config{IntakeSocket: filepath.Join(t.TempDir(), "absent.sock"), PollInterval: 100 * time.Millisecond}, pt.Slave, winch, term)
	}()
	if out := pt.WaitFor("SeqPass trusted intake", 10*time.Second); !bytes.Contains(out, []byte("SeqPass trusted intake")) {
		t.Fatalf("no banner: %q", out)
	}
	term <- syscall.SIGTERM
	select {
	case err := <-done:
		var ie *InterruptError
		if !errors.As(err, &ie) {
			t.Fatalf("termination returned %v, want *InterruptError", err)
		}
		if ie.Signal != syscall.SIGTERM {
			t.Fatalf("signal = %v, want SIGTERM", ie.Signal)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("session ignored the termination signal")
	}
	// Raw mode is off again: the pty echoes as it did before the session.
	if on, err := ptytest.EchoOn(pt.Slave); err != nil || !on {
		t.Fatalf("terminal left in raw mode after termination (echo=%v err=%v)", on, err)
	}
	// And the cursor was restored, so the operator's shell is usable.
	if out := pt.ReadAvailable(500 * time.Millisecond); !bytes.Contains(out, []byte("\x1b[?25h")) {
		t.Fatalf("cursor not restored on termination: %q", out)
	}
}

// F06: Ctrl+C at the inbox quits cleanly, submitting nothing.
func TestTUICtrlCQuits(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	_, intake := testBroker(t)
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	done := make(chan error, 1)
	go func() {
		done <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 200 * time.Millisecond}, pt.Slave)
	}()
	if out := pt.WaitFor("SeqPass trusted intake", 10*time.Second); !bytes.Contains(out, []byte("SeqPass trusted intake")) {
		t.Fatalf("no TUI banner: %q", out)
	}
	if _, err := pt.Master.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ctrl+c quit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("tui ignored Ctrl+C")
	}
}

// F06: resize and EOF semantics — SIGWINCH re-renders without harm, and a
// dead terminal exits instead of spinning forever.
func TestTUIResizeAndEOF(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	_, intake := testBroker(t)
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 200 * time.Millisecond}, pt.Slave)
	}()
	if out := pt.WaitFor("SeqPass trusted intake", 10*time.Second); !bytes.Contains(out, []byte("SeqPass trusted intake")) {
		t.Fatalf("no TUI banner: %q", out)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("sigwinch: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	// Session still alive after resize: quit cleanly.
	if _, err := pt.Master.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("quit after resize: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("tui died on resize")
	}

	// Dead terminal: closing the master must end the session with an
	// error, never a silent spin.
	pt2, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	done2 := make(chan error, 1)
	go func() {
		done2 <- RunOnFile(Config{IntakeSocket: intake, PollInterval: 200 * time.Millisecond}, pt2.Slave)
	}()
	if out := pt2.WaitFor("SeqPass trusted intake", 10*time.Second); !bytes.Contains(out, []byte("SeqPass trusted intake")) {
		t.Fatalf("no TUI banner: %q", out)
	}
	_ = pt2.Master.Close()
	pt2.Master = nil
	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("dead terminal returned success")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dead terminal spun forever")
	}
	pt2.Close()
}
