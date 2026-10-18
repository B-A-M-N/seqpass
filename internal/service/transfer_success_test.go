package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
	"github.com/secretbridge/secretbridge/internal/testruntime"
)

const successMarker = "SECRET-MARKER-success-9f8e7d6c5b4a"

// testRecipient runs a trusted recipient socket speaking the v1 envelope
// protocol: reads a length-prefixed JSON envelope, verifies it, and replies
// with a bound ack (op_id + digest) only after acceptance (C05).
func testRecipient(t *testing.T, sock string, got *[]byte) {
	t.Helper()
	_ = os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lb [4]byte
		if _, err := readFull(conn, lb[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n == 0 || n > 1<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := readFull(conn, buf); err != nil {
			return
		}
		var env struct {
			V       uint32 `json:"v"`
			OpID    string `json:"op_id"`
			Digest  string `json:"digest"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(buf, &env) != nil || env.V != 1 || env.Payload == "" {
			return
		}
		*got = []byte(env.Payload)
		ack, _ := json.Marshal(map[string]interface{}{
			"accepted": true, "op_id": env.OpID, "digest": env.Digest, "bytes": len(env.Payload),
		})
		var alb [4]byte
		binary.BigEndian.PutUint32(alb[:], uint32(len(ack)))
		_, _ = conn.Write(alb[:])
		_, _ = conn.Write(ack)
	}()
}

// recipientDir returns a recipient-shaped runtime dir (owner-only) so the
// SC-06 directory trust check passes for fixtures owned by the test user.
func recipientDir(t *testing.T) string {
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

func readFull(conn net.Conn, b []byte) (int, error) {
	off := 0
	for off < len(b) {
		n, err := conn.Read(b[off:])
		if err != nil {
			return off, err
		}
		off += n
	}
	return off, nil
}

// setupTransferFixture stages a ref + payload + recipient + policy and
// returns an approved transfer ready for execution.
func setupTransferFixture(t *testing.T, svc *Service) string {
	t.Helper()
	sr := &types.SecretReference{ID: "cert1", Name: "cert", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("cert1", []byte(successMarker+"-payload")); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(recipientDir(t), "recipient.sock")
	var got []byte
	testRecipient(t, sock, &got)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{ID: "d1", Name: "r", Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "cert1", "transfer", "d1")
	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveTransfer(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	return id
}

// C13: the trusted auto worker executes authorized ops through the same
// claim path, while pending ops still wait for approval.
func TestAutoWorkerExecutesAuthorized(t *testing.T) {
	svc := testService(t)
	id := setupTransferFixture(t, svc)
	svc.runWorkerOnce(context.Background())
	tr, _ := svc.DB().GetTransfer(id)
	if tr.Status != types.StatusCompleted {
		t.Fatalf("auto worker did not complete authorized op: %s", tr.Status)
	}
	// A pending op is untouched by the worker.
	id2, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.runWorkerOnce(context.Background())
	tr2, _ := svc.DB().GetTransfer(id2)
	if tr2.Status == types.StatusCompleted || tr2.Status == types.StatusExecuting {
		t.Fatalf("worker executed an unapproved op: %s", tr2.Status)
	}
}

// Full success path in-process: submit -> approve -> claim -> deliver.
// Receipt must not contain the secret marker; recipient must ack exact bytes.
func TestTransferSuccessNoLeak(t *testing.T) {
	svc := testService(t)

	sr := &types.SecretReference{ID: "cert1", Name: "cert", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	// Trusted intake stages the payload (operator path, never MCP).
	if err := svc.vault.Store("cert1", []byte(successMarker+"-payload")); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(recipientDir(t), "recipient.sock")
	var got []byte
	testRecipient(t, sock, &got)
	uid := uint32(os.Geteuid())
	dest := &types.Destination{ID: "d1", Name: "r", Type: "recipient-socket", Endpoint: sock, ExpectedUID: &uid}
	if err := svc.AddDestination(dest); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "cert1", "transfer", "d1")

	id, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{
		SecretRef: "cert1", DestinationID: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := svc.DB().GetTransfer(id)
	if stored.Status == types.StatusAuthorized {
		t.Fatal("must not auto-authorize")
	}
	if err := svc.ApproveTransfer(id, "operator", -1); err != nil {
		t.Fatal(err)
	}

	res, err := svc.ExecuteTransfer(context.Background(), id, "op")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), successMarker) {
		t.Fatal("secret marker leaked in receipt")
	}
	if string(got) != successMarker+"-payload" {
		t.Fatal("recipient payload mismatch")
	}

	// C12: the submitting agent retrieves status + durable sanitized receipt.
	detail, err := svc.StatusDetail("uid:1000", "transfer", id)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != types.StatusCompleted || !detail.HasReceipt {
		t.Fatalf("agent cannot retrieve completed receipt: %+v", detail)
	}
	if strings.Contains(detail.Result, successMarker) {
		t.Fatal("secret marker leaked in agent-visible receipt")
	}
	// Another principal learns nothing, not even existence.
	if _, err := svc.StatusDetail("uid:9999", "transfer", id); err == nil {
		t.Fatal("foreign principal read another agent's receipt")
	}

	// Second execution must fail (already completed, claim fails).
	if _, err := svc.ExecuteTransfer(context.Background(), id, "op"); err == nil {
		t.Fatal("completed op re-executed")
	}

	// Audit contains metadata only.
	logs, _ := svc.DB().ListAuditLogs(50)
	for _, l := range logs {
		if strings.Contains(l.Metadata+string(l.Action)+string(l.Outcome), successMarker) {
			t.Fatal("marker in audit log")
		}
	}
}
