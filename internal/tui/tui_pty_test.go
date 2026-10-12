package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/ptytest"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// testBroker starts a service plus an intake-socket IPC server, returning
// the service and intake path. The agent principal below is arbitrary;
// intake authorizes the broker euid (same-user test topology).
func testBroker(t *testing.T) (*service.Service, string) {
	t.Helper()
	dir := t.TempDir()
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
		Endpoint: "/tmp/tui-test-no-recipient.sock", ExpectedUID: &uid,
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
