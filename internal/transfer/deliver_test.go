package transfer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/testruntime"
	"github.com/secretbridge/secretbridge/internal/types"
)

func destOf(t *testing.T, typ, ep string) *types.Destination {
	t.Helper()
	uid := uint32(os.Geteuid())
	return &types.Destination{ID: "d", Name: "d", Type: typ, Endpoint: ep, ExpectedUID: &uid}
}

// sockDir returns a recipient-shaped runtime dir: owner-only, so the SC-06
// directory trust check passes for fixtures owned by the test user.
func sockDir(t *testing.T) string {
	t.Helper()
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return ""
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func destOfUID(t *testing.T, typ, ep string, uid uint32) *types.Destination {
	t.Helper()
	u := uid
	return &types.Destination{ID: "d", Name: "d", Type: typ, Endpoint: ep, ExpectedUID: &u}
}

// T18: recipient accepts bytes but the ack is lost -> uncertain, no retry.
func TestUncertainOnLostAck(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf) // consume, then close without ack
	}()
	d := NewDeliverer()
	_, err = d.Deliver(context.Background(), "op-1", "payload", destOf(t, "recipient-socket", sock))
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("expected uncertain, got %v", err)
	}
}

// Removed destination types are rejected outright.
func TestLegacyTypesRejected(t *testing.T) {
	d := NewDeliverer()
	victim := filepath.Join(sockDir(t), "victim")
	_ = os.WriteFile(victim, []byte("x"), 0600)
	for _, typ := range []string{"file", "http-pinned", "ssh", "s3"} {
		if _, err := d.Deliver(context.Background(), "op-1", "p", destOf(t, typ, victim)); err == nil {
			t.Fatalf("type %q accepted", typ)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "x" {
		t.Fatal("victim modified")
	}
}

// Oversized payloads rejected before any I/O.
func TestPayloadBound(t *testing.T) {
	d := NewDeliverer()
	big := make([]byte, maxPayload+1)
	if _, err := d.Deliver(context.Background(), "op-1", string(big), destOf(t, "recipient-socket", "/tmp/nope.sock")); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

// readEnvelope is the test-recipient side of the wire protocol: length-prefixed
// JSON envelope.
func readEnvelope(t *testing.T, c net.Conn) map[string]interface{} {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var lb [4]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatalf("envelope length: %v", err)
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n == 0 || n > 2<<20 {
		t.Fatalf("bad envelope length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("envelope body: %v", err)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(buf, &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	return env
}

func writeAck(t *testing.T, c net.Conn, v interface{}) {
	t.Helper()
	raw, _ := json.Marshal(v)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
	_, _ = c.Write(lb[:])
	_, _ = c.Write(raw)
}

// C05: a recipient socket owned by an unexpected UID receives nothing.
// The owner check fails before connect, so no payload byte is disclosed.
func TestRecipientImpersonationDenied(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	connected := make(chan struct{}, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		connected <- struct{}{}
	}()
	// Socket is owned by euid; the destination pins a different UID.
	d := NewDeliverer()
	_, err = d.Deliver(context.Background(), "op-9", "payload", destOfUID(t, "recipient-socket", sock, uint32(os.Geteuid())+100000))
	if err == nil {
		t.Fatal("delivery to identity-mismatched recipient succeeded")
	}
	select {
	case <-connected:
		t.Fatal("broker connected to an identity-mismatched recipient")
	case <-time.After(300 * time.Millisecond):
	}
}

// SC-06: the recipient directory is part of the trust decision. A socket in
// a group-writable or symlinked directory is refused BEFORE connect, so no
// payload byte can reach a substituted recipient.
func TestRecipientDirUntrusted(t *testing.T) {
	mkSock := func(t *testing.T, dir string) (string, chan struct{}) {
		t.Helper()
		sock := filepath.Join(dir, "r.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		connected := make(chan struct{}, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			connected <- struct{}{}
		}()
		return sock, connected
	}
	d := NewDeliverer()

	// Group-writable directory.
	gw := sockDir(t)
	if err := os.Chmod(gw, 0770); err != nil {
		t.Fatal(err)
	}
	sock, connected := mkSock(t, gw)
	if _, err := d.Deliver(context.Background(), "op-d", "payload", destOf(t, "recipient-socket", sock)); err == nil {
		t.Fatal("delivery via group-writable recipient dir succeeded (SC-06)")
	}
	select {
	case <-connected:
		t.Fatal("broker connected despite untrusted recipient dir")
	case <-time.After(300 * time.Millisecond):
	}

	// Symlinked directory.
	base := sockDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	sock2, connected2 := mkSock(t, link)
	if _, err := d.Deliver(context.Background(), "op-e", "payload", destOf(t, "recipient-socket", sock2)); err == nil {
		t.Fatal("delivery via symlinked recipient dir succeeded (SC-06)")
	}
	select {
	case <-connected2:
		t.Fatal("broker connected despite symlinked recipient dir")
	case <-time.After(300 * time.Millisecond):
	}
}

// C05: delivery without a pinned recipient identity fails closed.
func TestRecipientIdentityRequired(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d := NewDeliverer()
	bare := &types.Destination{ID: "d", Name: "d", Type: "recipient-socket", Endpoint: sock}
	if _, err := d.Deliver(context.Background(), "op-1", "p", bare); err == nil {
		t.Fatal("delivery without pinned recipient UID succeeded")
	}
}

// C05: happy path carries a bound envelope and accepts a bound ack.
func TestBoundEnvelopeRoundTrip(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Cannot use t inside goroutine safely for Fatal; simplified.
		var lb [4]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n == 0 || n > 2<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		var env struct {
			V       uint32 `json:"v"`
			OpID    string `json:"op_id"`
			Digest  string `json:"digest"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(buf, &env) != nil {
			return
		}
		if env.V != 1 || env.OpID != "op-7" || env.Payload != "hello" || env.Digest == "" {
			return
		}
		raw, _ := json.Marshal(map[string]interface{}{
			"accepted": true, "op_id": env.OpID, "digest": env.Digest, "bytes": len(env.Payload),
		})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}()
	d := NewDeliverer()
	receipt, err := d.Deliver(context.Background(), "op-7", "hello", destOf(t, "recipient-socket", sock))
	if err != nil {
		t.Fatalf("bound delivery failed: %v", err)
	}
	if receipt["delivered"] != true {
		t.Fatalf("bad receipt: %v", receipt)
	}
}

// §10: an authenticated recipient that returns a well-formed refusal
// bound to the exact (op_id, digest, bytes) produces a DETERMINISTIC
// rejection — not lost-ack uncertainty. The broker knows no acceptance
// occurred, so the operator can act (fix the recipient, request a fresh
// code) instead of investigating an ambiguous dispatch.
func TestBoundRefusalIsRejectedNotUncertain(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [4]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n == 0 || n > 2<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		var env struct {
			V       uint32 `json:"v"`
			OpID    string `json:"op_id"`
			Digest  string `json:"digest"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(buf, &env) != nil {
			return
		}
		// Bind the refusal to the exact received envelope.
		raw, _ := json.Marshal(map[string]interface{}{
			"accepted": false, "op_id": env.OpID, "digest": env.Digest, "bytes": len(env.Payload),
		})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}()
	d := NewDeliverer()
	_, err = d.Deliver(context.Background(), "op-refuse", "secret-code", destOf(t, "recipient-socket", sock))
	if !errors.Is(err, ErrRecipientRejected) {
		t.Fatalf("bound refusal must be ErrRecipientRejected, got %v", err)
	}
	if errors.Is(err, ErrUncertain) {
		t.Fatal("bound refusal must not be classified uncertain")
	}
}

// §10 negative shape: a refusal that does NOT bind the exact envelope
// (here: wrong byte count) is unauthenticated and stays uncertain —
// the broker cannot prove what an unbound peer actually did.
func TestUnboundRefusalStaysUncertain(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [4]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n == 0 || n > 2<<20 {
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(n))
		raw, _ := json.Marshal(map[string]interface{}{
			"accepted": false, "op_id": "op-refuse2", "digest": "aa", "bytes": 1,
		})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}()
	d := NewDeliverer()
	_, err = d.Deliver(context.Background(), "op-refuse2", "secret-code", destOf(t, "recipient-socket", sock))
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("unbound refusal must stay ErrUncertain, got %v", err)
	}
}

// C05: a forged ack (wrong digest) cannot mark the transfer completed.
func TestForgedAckUncertain(t *testing.T) {
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [4]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n == 0 || n > 2<<20 {
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(n))
		raw, _ := json.Marshal(map[string]interface{}{
			"accepted": true, "op_id": "op-3", "digest": "forged", "bytes": 7,
		})
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}()
	d := NewDeliverer()
	_, err = d.Deliver(context.Background(), "op-3", "payload", destOf(t, "recipient-socket", sock))
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("forged ack must be uncertain, got %v", err)
	}
}
