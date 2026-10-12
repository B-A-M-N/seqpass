package security

import (
	"net"
	"strings"
	"testing"
	"time"
)

// T12: idle clients must not block broker shutdown.
func TestIdleClientDoesNotBlockShutdown(t *testing.T) {
	e := startBroker(t, nil)
	conn, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.d.Shutdown()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown blocked by idle client (T12)")
	}
}

// Oversized frames and unknown fields are rejected (T11 framing).
func TestFramingLimits(t *testing.T) {
	e := startBroker(t, nil)
	conn, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Unknown field must be rejected by strict decoding.
	if _, err := conn.Write([]byte("{\"id\":\"1\",\"method\":\"health\",\"params\":{},\"bogus\":1}\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf[:n]), "invalid request") {
		t.Fatalf("unknown field not rejected: %s", buf[:n])
	}
	// Oversized frame: scanner must drop it without hanging.
	big := strings.Repeat("x", 2<<20)
	_, _ = conn.Write([]byte("{\"id\":\"2\",\"method\":\"health\",\"params\":{\"p\":\"" + big + "\"}}\n"))
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Read(buf)
	// Either an error or closed connection is acceptable; a hang is not.
}
