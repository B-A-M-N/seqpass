package transfer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testRecipientServer starts a recipient endpoint backed by the metadata-only
// fixture consumer. It is skipped only when the environment cannot bind a
// Unix socket at all; the durable journal is exercised separately.
func testRecipientServer(t *testing.T) (*RecipientServer, *ReferenceRecipient, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "seqpass-recipient-")
	if err != nil {
		t.Skipf("no temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewOperationJournal(filepath.Join(dir, "records"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewReferenceRecipient(journal)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "recipient.sock")
	srv, err := NewRecipientServer(RecipientServerConfig{
		SocketPath: sock,
		Consumer:   consumer,
	})
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, consumer, sock
}

func writeRequest(t *testing.T, conn net.Conn, req interface{}) {
	t.Helper()
	frame, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

// writeRequestTolerant writes a framed request without failing the test when
// the peer has already closed. A refused caller is expected to see either a
// broken pipe on write or an EOF on read.
func writeRequestTolerant(conn net.Conn, req interface{}) (int, error) {
	frame, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if n, err := conn.Write(lenBuf[:]); err != nil {
		return n, err
	}
	return conn.Write(frame)
}

func readResponse(t *testing.T, conn net.Conn) map[string]interface{} {
	t.Helper()
	var lenBuf [4]byte
	if _, err := readFullN(conn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := readFullN(conn, buf); err != nil {
		t.Fatal(err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}
func readFullN(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func dialRecipient(t *testing.T, sock string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRecipientServerDeliveryAndLookup(t *testing.T) {
	_, consumer, sock := testRecipientServer(t)

	payload := []byte("payload")
	digest := PayloadDigest(payload)
	conn := dialRecipient(t, sock)
	writeRequest(t, conn, map[string]interface{}{
		"v": 1, "op_id": "op1", "digest": digest, "payload": string(payload),
	})
	resp := readResponse(t, conn)
	if resp["accepted"] != true {
		t.Fatalf("delivery not accepted: %+v", resp)
	}
	if resp["digest"] != digest || resp["bytes"].(float64) != float64(len(payload)) {
		t.Fatalf("ack does not bind the payload: %+v", resp)
	}
	_ = conn.Close()

	conn = dialRecipient(t, sock)
	writeRequest(t, conn, map[string]interface{}{
		"kind": "lookup", "v": 1, "op_id": "op1", "digest": digest,
	})
	resp = readResponse(t, conn)
	if resp["status"] != RecipientDurablyAccepted {
		t.Fatalf("unexpected lookup status: %+v", resp)
	}
	_ = conn.Close()

	// Duplicate is idempotent (one request per connection, like the broker).
	conn = dialRecipient(t, sock)
	writeRequest(t, conn, map[string]interface{}{
		"v": 1, "op_id": "op1", "digest": digest, "payload": string(payload),
	})
	resp = readResponse(t, conn)
	if resp["accepted"] != true {
		t.Fatalf("duplicate not accepted: %+v", resp)
	}
	records, _ := consumer.journal.List()
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
}

// A delivery whose payload does not match its claimed digest is refused and
// nothing is journalled.
func TestRecipientServerDigestMismatchRefused(t *testing.T) {
	_, consumer, sock := testRecipientServer(t)
	conn := dialRecipient(t, sock)
	writeRequest(t, conn, map[string]interface{}{
		"v": 1, "op_id": "op2", "digest": PayloadDigest([]byte("expected")), "payload": "tampered",
	})
	resp := readResponse(t, conn)
	if resp["accepted"] == true {
		t.Fatalf("tampered payload accepted: %+v", resp)
	}
	if records, _ := consumer.journal.List(); len(records) != 0 {
		t.Fatalf("tampered delivery was journalled: %+v", records)
	}
}

// An operation id that could escape the record directory is refused before
// any side effect.
func TestRecipientServerRejectsUnsafeOpID(t *testing.T) {
	_, _, sock := testRecipientServer(t)
	conn := dialRecipient(t, sock)
	payload := []byte("payload")
	writeRequest(t, conn, map[string]interface{}{
		"v": 1, "op_id": "../escape", "digest": PayloadDigest(payload), "payload": string(payload),
	})
	resp := readResponse(t, conn)
	if resp["accepted"] == true {
		t.Fatalf("unsafe op id accepted: %+v", resp)
	}
}

func TestRecipientServerLookupUnknown(t *testing.T) {
	_, _, sock := testRecipientServer(t)
	conn := dialRecipient(t, sock)
	writeRequest(t, conn, map[string]interface{}{
		"kind": "lookup", "v": 1, "op_id": "unknownop", "digest": PayloadDigest([]byte("x")),
	})
	resp := readResponse(t, conn)
	if resp["status"] != RecipientUnknown {
		t.Fatalf("unexpected unknown status: %+v", resp)
	}
}

// An unsupported envelope version is refused rather than guessed.
func TestRecipientServerRejectsUnknownVersion(t *testing.T) {
	_, consumer, sock := testRecipientServer(t)
	conn := dialRecipient(t, sock)
	payload := []byte("payload")
	writeRequest(t, conn, map[string]interface{}{
		"v": 99, "op_id": "opv", "digest": PayloadDigest(payload), "payload": string(payload),
	})
	resp := readResponse(t, conn)
	if resp["accepted"] == true {
		t.Fatalf("unknown version accepted: %+v", resp)
	}
	if records, _ := consumer.journal.List(); len(records) != 0 {
		t.Fatalf("unknown version journalled: %+v", records)
	}
}

// The server-side caller allowlist is enforced before any frame is read: a
// caller whose OS identity is not listed is refused, and nothing is
// journalled.
func TestRecipientServerRefusesUntrustedCallerUID(t *testing.T) {
	server := func(t *testing.T, trusted []uint32) (*ReferenceRecipient, string) {
		t.Helper()
		dir, err := os.MkdirTemp("", "seqpass-recipient-")
		if err != nil {
			t.Skipf("no temp dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		journal, err := NewOperationJournal(filepath.Join(dir, "records"))
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := NewReferenceRecipient(journal)
		if err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "recipient.sock")
		srv, err := NewRecipientServer(RecipientServerConfig{
			SocketPath:        sock,
			Consumer:          consumer,
			TrustedCallerUIDs: trusted,
		})
		if err != nil {
			t.Skipf("unix socket unavailable: %v", err)
		}
		go srv.Serve()
		t.Cleanup(func() { _ = srv.Close() })
		return consumer, sock
	}

	// A caller identity that is not the recipient's own UID must be refused
	// before the payload is even read. The refusal may surface either as a
	// write failure (the peer already closed) or as a read failure.
	foreign := uint32(os.Geteuid()) + 1
	consumer, sock := server(t, []uint32{foreign})
	conn := dialRecipient(t, sock)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("payload")
	_, _ = writeRequestTolerant(conn, map[string]interface{}{
		"v": 1, "op_id": "opdenied", "digest": PayloadDigest(payload), "payload": string(payload),
	})
	var lenBuf [4]byte
	if _, err := readFullN(conn, lenBuf[:]); err == nil {
		t.Fatal("untrusted caller received a response instead of being refused")
	}
	_ = conn.Close()
	if records, _ := consumer.journal.List(); len(records) != 0 {
		t.Fatalf("untrusted caller's delivery was journalled: %+v", records)
	}

	// Listing the caller's real identity is the positive control: the same
	// frame is accepted.
	consumer2, sock2 := server(t, []uint32{uint32(os.Geteuid())})
	conn2 := dialRecipient(t, sock2)
	writeRequest(t, conn2, map[string]interface{}{
		"v": 1, "op_id": "opallowed", "digest": PayloadDigest(payload), "payload": string(payload),
	})
	resp := readResponse(t, conn2)
	if resp["accepted"] != true {
		t.Fatalf("allowlisted caller refused: %+v", resp)
	}
	_ = conn2.Close()
	if records, _ := consumer2.journal.List(); len(records) != 1 {
		t.Fatalf("allowlisted delivery not journalled: %+v", records)
	}
}

// Accept backoff is bounded and resets, so a saturated accept loop cannot
// spin at full speed.
func TestNextAcceptBackoffBounded(t *testing.T) {
	d := time.Duration(0)
	prev := time.Duration(0)
	for i := 0; i < 40; i++ {
		d = nextAcceptBackoff(d)
		if d <= 0 {
			t.Fatalf("backoff not positive at step %d", i)
		}
		if d > time.Second {
			t.Fatalf("backoff exceeded its bound: %v", d)
		}
		if i > 0 && d < prev {
			t.Fatalf("backoff decreased without a successful accept: %v -> %v", prev, d)
		}
		prev = d
	}
	if nextAcceptBackoff(time.Second) != time.Second {
		t.Fatal("backoff did not saturate at its bound")
	}
}

// The fixture consumer must not be usable as a production credential
// destination: it journals durably_accepted and never reports applied.
func TestReferenceRecipientNeverReportsApplied(t *testing.T) {
	j, err := NewOperationJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReferenceRecipient(j)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("secret")
	acc, err := r.Accept(context.Background(), Delivery{OperationID: "opfix", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if acc.State != StateDurablyAccepted {
		t.Fatalf("fixture state = %q, want durably_accepted", acc.State)
	}
	state, err := r.Lookup(context.Background(), "opfix")
	if err != nil {
		t.Fatal(err)
	}
	if state == StateApplied {
		t.Fatal("metadata-only fixture must never report applied")
	}
}
