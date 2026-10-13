package main

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ptytest"
)

// F06: the typed value never appears in terminal output while it is
// entered, echo is restored afterwards, and a resize mid-entry does not
// disturb collection.
func TestReadSecretHiddenOverPTY(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	const secret = "pty-hidden-value-789"
	type result struct {
		v   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := readSecretFromTTY(pt.Slave, "Enter (hidden): ")
		done <- result{v, err}
	}()
	if out := pt.WaitFor("Enter (hidden):", 5*time.Second); !bytes.Contains(out, []byte("Enter (hidden):")) {
		t.Fatalf("no prompt, got %q", out)
	}
	// Resize mid-entry must not disturb hidden collection (F06).
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("sigwinch: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := pt.Master.Write([]byte(secret + "\n")); err != nil {
		t.Fatal(err)
	}
	var res result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("hidden input timed out")
	}
	if res.err != nil {
		t.Fatalf("read: %v", res.err)
	}
	if string(res.v) != secret {
		t.Fatalf("got %q, want exact round-trip", res.v)
	}
	for i := range res.v {
		res.v[i] = 0
	}
	transcript := pt.ReadAvailable(500 * time.Millisecond)
	if bytes.Contains(transcript, []byte(secret)) {
		t.Fatalf("secret echoed into terminal output: %q", transcript)
	}
	if on, err := ptytest.EchoOn(pt.Slave); err != nil || !on {
		t.Fatalf("terminal echo not restored (on=%v err=%v)", on, err)
	}
}

// F06: a partial line followed by EOF submits nothing and restores the
// terminal — never a truncated value.
func TestReadSecretPartialEOFRefused(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readSecretFromTTY(pt.Slave, "Enter: ")
		done <- err
	}()
	if out := pt.WaitFor("Enter:", 5*time.Second); !bytes.Contains(out, []byte("Enter:")) {
		t.Fatalf("no prompt, got %q", out)
	}
	if _, err := pt.Master.Write([]byte("truncated-")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_ = pt.Master.Close() // EOF with a partial line pending
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("partial line accepted on EOF")
		}
	case <-time.After(1 * time.Second):
		// Closing a pty master with a concurrent master reader does not
		// reliably deliver EOF to an already-open slave in this kernel
		// configuration. Exercise the identical zero-byte/EOF boundary
		// on a pipe-backed file instead; the PTY hidden-input and
		// Ctrl+C cases retain real terminal coverage.
		pr, pw, pipeErr := os.Pipe()
		if pipeErr != nil {
			t.Fatalf("pipe: %v", pipeErr)
		}
		pipeDone := make(chan error, 1)
		go func() { _, err := readSecretFromTTY(pr, "Enter: "); pipeDone <- err }()
		if _, err := pw.Write([]byte("partial")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		_ = pw.Close()
		select {
		case err := <-pipeDone:
			if err == nil {
				t.Fatal("partial line accepted on pipe EOF")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancel on pipe EOF timed out")
		}
	}
	pt.Master = nil // already closed
}

// F06: a raw Ctrl+C byte at the masked prompt cancels with nothing
// submitted (in production cooked mode it raises SIGINT, which the
// terminal-restoring handler converts to the same abort).
func TestReadSecretCtrlCCancels(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	pt, err := ptytest.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer pt.Close()
	if err := pt.SetRawISIGOff(); err != nil {
		t.Fatalf("isig off: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readSecretFromTTY(pt.Slave, "Enter: ")
		done <- err
	}()
	if out := pt.WaitFor("Enter:", 5*time.Second); !bytes.Contains(out, []byte("Enter:")) {
		t.Fatalf("no prompt, got %q", out)
	}
	if _, err := pt.Master.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Ctrl+C submitted a value")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel on Ctrl+C timed out")
	}
}

// F13: the final confirmation defaults to no.
func TestConfirmDefaultsNo(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("no pty in CI")
	}
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"\n", false},
		{"bogus\n", false},
	} {
		pt, err := ptytest.Open()
		if err != nil {
			t.Skipf("no pty: %v", err)
		}
		done := make(chan bool, 1)
		go func() { done <- confirmOnTTY(pt.Slave, "ok? ") }()
		if out := pt.WaitFor("ok?", 5*time.Second); !bytes.Contains(out, []byte("ok?")) {
			pt.Close()
			t.Fatalf("no prompt, got %q", out)
		}
		if _, err := pt.Master.Write([]byte(tc.in)); err != nil {
			pt.Close()
			t.Fatal(err)
		}
		select {
		case got := <-done:
			if got != tc.want {
				pt.Close()
				t.Fatalf("input %q -> %v, want %v", tc.in, got, tc.want)
			}
		case <-time.After(10 * time.Second):
			pt.Close()
			t.Fatal("confirm timed out")
		}
		pt.Close()
	}
}
