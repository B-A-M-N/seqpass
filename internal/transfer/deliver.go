package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

var (
	// ErrUncertain marks "may have succeeded, ack lost": never auto-retry
	// without a verified idempotency mechanism.
	ErrUncertain = errors.New("delivery uncertain")
)

const (
	maxPayload = 1 << 20 // 1 MiB: SeqPass is not a general file store.
	dialTO     = 10 * time.Second
	ioTO       = 30 * time.Second

	// envelopeVersion is the broker->recipient wire version. Recipients must
	// reject unknown versions rather than guessing the framing.
	envelopeVersion = 1
)

type Deliverer struct{}

func NewDeliverer() *Deliverer { return &Deliverer{} }

// Deliver transmits plaintext broker->recipient over a protected local
// recipient socket. Plaintext never returns to the agent; the caller gets a
// receipt only.
//
// Supported destination types:
//   - recipient-socket: unix socket where a trusted receiving application
//     accepts a length-prefixed JSON envelope and replies with a bound ack.
//     Arbitrary file and network destinations are rejected: path-based
//     delivery inside a privileged executor enables truncation, symlink and
//     substitution attacks (F03).
//
// Recipient authentication (C05/SC-06): the endpoint pathname is validated
// (socket, no symlink, expected owner, trusted parent directory) and the
// connected peer's UID/GID is verified against the destination's pinned
// identity BEFORE any payload byte is sent. A substituted socket or process
// receives nothing. The peer credential identifies the OS principal, so the
// recipient must run as a dedicated UID for the guarantee to mean one
// application.
func (d *Deliverer) Deliver(ctx context.Context, opID, plaintext string, dest *types.Destination) (map[string]interface{}, error) {
	if dest == nil {
		return nil, errors.New("unknown destination")
	}
	if opID == "" {
		return nil, errors.New("missing operation id")
	}
	if plaintext == "" {
		return nil, errors.New("empty payload")
	}
	if len(plaintext) > maxPayload {
		return nil, errors.New("payload too large")
	}
	switch dest.Type {
	case "recipient-socket":
		return d.deliverSocket(ctx, opID, plaintext, dest)
	default:
		return nil, fmt.Errorf("unsupported destination type %q", dest.Type)
	}
}

// envelope is the broker->recipient frame. The digest binds the payload;
// the recipient must persist the payload under (op_id, digest) and only
// then issue an ack quoting both back.
type envelope struct {
	Version uint32 `json:"v"`
	OpID    string `json:"op_id"`
	Digest  string `json:"digest"`
	Payload string `json:"payload"`
}

// ack is the recipient->broker reply. It counts only when op_id and digest
// equal the sent envelope: a byte count alone proves neither identity nor
// durable acceptance (C05). An ack attests durable acceptance (persisted
// under the (op_id, digest) idempotency key), NOT downstream application of
// the payload — "applied" state requires independent outcome verification
// (SC-14). A lost ack may cause redelivery of the same (op_id, digest);
// recipients must ack duplicates without re-applying side effects.
type ack struct {
	Accepted bool   `json:"accepted"`
	OpID     string `json:"op_id"`
	Digest   string `json:"digest"`
	Bytes    int    `json:"bytes"`
	Error    string `json:"error,omitempty"`
}

func payloadDigest(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// DigestPayload computes the trusted-protocol integrity digest of a
// payload. It is used inside the delivery protocol and the broker-private
// dispatch record only — never published on agent-visible surfaces (G01).
func DigestPayload(payload string) string {
	return payloadDigest([]byte(payload))
}

// writeFull loops until the whole buffer is delivered. A single conn.Write
// may write short; assuming otherwise splits the envelope and leaves the
// outcome ambiguous.
func writeFull(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("short write")
		}
		buf = buf[n:]
	}
	return nil
}

// checkEndpoint validates the socket pathname before connecting: it must be
// a real socket (never a symlink), owned by the expected recipient UID, in
// a directory that is itself not a symlink, owned by the recipient UID or
// root, and not group/other-writable. A hostile directory would allow
// socket substitution between validation and connect, so the directory is
// part of the trust decision, not just the socket (SC-06). A pathname is
// not trusted merely because it was registered earlier (C05).
//
// NOTE: UID/GID pinning authenticates the OS principal, not a specific
// application binary. Recipients MUST run under isolated service identities
// (a dedicated UID no other process shares); any same-UID process can
// otherwise impersonate the recipient. See the wire-protocol docs.
func checkEndpoint(path string, dest *types.Destination) error {
	if path == "" {
		return errors.New("recipient socket missing")
	}
	if dest.ExpectedUID == nil {
		return errors.New("recipient identity not configured")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recipient unavailable")
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("recipient socket is a symlink")
	}
	if fi.Mode().Type() != os.ModeSocket {
		return errors.New("recipient path is not a socket")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != *dest.ExpectedUID {
			return errors.New("recipient socket owner mismatch")
		}
	}
	dir := filepath.Dir(path)
	dfi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("recipient unavailable")
	}
	if dfi.Mode()&os.ModeSymlink != 0 {
		return errors.New("recipient socket dir is a symlink")
	}
	if !dfi.IsDir() {
		return errors.New("recipient socket dir is not a directory")
	}
	if dst, ok := dfi.Sys().(*syscall.Stat_t); ok {
		if dst.Uid != *dest.ExpectedUID && dst.Uid != 0 {
			return errors.New("recipient socket dir owner mismatch")
		}
	}
	if dfi.Mode().Perm()&0022 != 0 {
		return errors.New("recipient socket dir is group/other-writable")
	}
	return nil
}

func (d *Deliverer) deliverSocket(ctx context.Context, opID, plaintext string, dest *types.Destination) (map[string]interface{}, error) {
	if err := checkEndpoint(dest.Endpoint, dest); err != nil {
		// Path validation happens before any connection: nothing sent,
		// outcome is a clean failure (not uncertain).
		if err.Error() == "recipient unavailable" {
			return nil, err
		}
		return nil, err
	}
	dialer := net.Dialer{Timeout: dialTO}
	conn, err := dialer.DialContext(ctx, "unix", dest.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("recipient unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTO))

	// Authenticate the peer BEFORE sending the payload. A substituted
	// process at the configured path receives nothing (C05).
	uid, gid, err := peerIdentity(conn)
	if err != nil {
		return nil, fmt.Errorf("recipient authentication failed")
	}
	if uid != *dest.ExpectedUID {
		return nil, errors.New("recipient identity mismatch")
	}
	if dest.ExpectedGID != nil && gid != *dest.ExpectedGID {
		return nil, errors.New("recipient group mismatch")
	}

	payload := []byte(plaintext)
	digest := payloadDigest(payload)
	env := envelope{Version: envelopeVersion, OpID: opID, Digest: digest, Payload: plaintext}
	frame, err := json.Marshal(env)
	if err != nil {
		return nil, errors.New("envelope build failed")
	}
	if len(frame) > maxPayload+1024 {
		return nil, errors.New("payload too large")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if err := writeFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("delivery failed")
	}
	if err := writeFull(conn, frame); err != nil {
		// Bytes may have reached the recipient; outcome unknown.
		return nil, ErrUncertain
	}
	// Ack: length-prefixed JSON, bounded.
	var ackLen [4]byte
	if _, err := io.ReadFull(conn, ackLen[:]); err != nil {
		return nil, ErrUncertain
	}
	n := binary.BigEndian.Uint32(ackLen[:])
	if n == 0 || n > 4096 {
		return nil, ErrUncertain
	}
	ackBuf := make([]byte, n)
	if _, err := io.ReadFull(conn, ackBuf); err != nil {
		return nil, ErrUncertain
	}
	var a ack
	dec := json.NewDecoder(bytes.NewReader(ackBuf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, ErrUncertain
	}
	// The ack must bind the exact operation and payload digest. A forged,
	// stale or byte-count-only ack cannot mark the transfer completed.
	if !a.Accepted || a.OpID != opID || a.Digest != digest || a.Bytes != len(payload) {
		return nil, ErrUncertain
	}
	// The returned receipt is the PUBLIC receipt (G01): fixed scalar
	// shape with no secret-derived fingerprint. The payload digest stays
	// inside the trusted protocol (ack binding above) and the
	// broker-private dispatch record — it is never published to the
	// agent, so a low-entropy secret gains no offline guessing oracle.
	return map[string]interface{}{
		"destination_id": dest.ID,
		"delivered":      true,
		"bytes":          a.Bytes,
	}, nil
}
