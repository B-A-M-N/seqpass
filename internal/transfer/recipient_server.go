package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// RecipientServerConfig configures the trusted recipient endpoint. The
// zero value is deliberately unusable: a production recipient must state
// where its socket lives, who may connect, and which consumer commits the
// secret.
type RecipientServerConfig struct {
	// SocketPath is the Unix socket the recipient listens on.
	SocketPath string
	// SocketMode is the socket's permission bits. Zero defaults to 0600.
	SocketMode os.FileMode
	// SocketUID/SocketGID, when > 0, set the socket's owner/group (requires
	// privilege). A separate broker UID can only connect when the socket's
	// group grants it, so multi-UID deployments set SocketGID to a shared
	// group rather than relying on the default owner-only 0600.
	SocketUID int
	SocketGID int
	// TrustedCallerUIDs is the allowlist of broker UIDs permitted to
	// connect. Empty means "only this process's effective UID" — the
	// single-user default. A peer that is not listed receives nothing.
	TrustedCallerUIDs []uint32
	// MaxConnections bounds concurrent in-flight connections. Zero means 8.
	MaxConnections int
	// ConnDeadline bounds one request/response exchange. Zero means 15s.
	ConnDeadline time.Duration
	// MaxFrameBytes bounds an inbound frame. Zero means 256 KiB.
	MaxFrameBytes int
	// Consumer commits each delivery. Required.
	Consumer SecretConsumer
}

// RecipientServer serves the recipient wire contract on a Unix socket. It
// authenticates the connecting peer, validates every wire field, requires
// payload/digest agreement, and only then asks the consumer to commit.
type RecipientServer struct {
	cfg      RecipientServerConfig
	listener net.Listener
	closed   chan struct{}
	sem      chan struct{}
	ownUID   uint32
}

// NewRecipientServer creates and binds the recipient socket.
func NewRecipientServer(cfg RecipientServerConfig) (*RecipientServer, error) {
	if cfg.SocketPath == "" {
		return nil, fmt.Errorf("recipient socket path required")
	}
	if cfg.Consumer == nil {
		return nil, fmt.Errorf("recipient consumer required")
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0600
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 8
	}
	if cfg.ConnDeadline <= 0 {
		cfg.ConnDeadline = 15 * time.Second
	}
	if cfg.MaxFrameBytes <= 0 {
		cfg.MaxFrameBytes = 256 * 1024
	}
	dir := filepath.Dir(cfg.SocketPath)
	dfi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("recipient socket directory: %w", err)
	}
	if dfi.Mode()&os.ModeSymlink != 0 || !dfi.IsDir() {
		return nil, fmt.Errorf("recipient socket directory is unsafe")
	}
	if fi, err := os.Lstat(cfg.SocketPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to replace symlink at socket path")
		}
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("refusing to delete non-socket at socket path")
		}
		if err := os.Remove(cfg.SocketPath); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, err
	}
	if cfg.SocketUID > 0 || cfg.SocketGID > 0 {
		if err := os.Lchown(cfg.SocketPath, cfg.SocketUID, cfg.SocketGID); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("recipient socket ownership: %w (setting socket owner/group requires privilege)", err)
		}
	}
	if err := os.Chmod(cfg.SocketPath, cfg.SocketMode); err != nil {
		_ = l.Close()
		return nil, err
	}
	return &RecipientServer{
		cfg:      cfg,
		listener: l,
		closed:   make(chan struct{}),
		sem:      make(chan struct{}, cfg.MaxConnections),
		ownUID:   uint32(os.Geteuid()),
	}, nil
}

// SocketPath returns the bound socket path.
func (r *RecipientServer) SocketPath() string { return r.cfg.SocketPath }

// Serve accepts connections until Close is called.
func (r *RecipientServer) Serve() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
				continue
			}
		}
		select {
		case r.sem <- struct{}{}:
		case <-r.closed:
			_ = conn.Close()
			return
		default:
			// Bounded: refuse rather than queue unboundedly. The broker
			// treats a refused connection as an unavailable recipient and
			// never retries it blindly.
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-r.sem }()
			r.handleConn(conn)
		}()
	}
}

// Close stops accepting new connections.
func (r *RecipientServer) Close() error {
	select {
	case <-r.closed:
		return nil
	default:
		close(r.closed)
	}
	return r.listener.Close()
}

// authorizeCaller verifies the peer's OS identity BEFORE reading any frame.
func (r *RecipientServer) authorizeCaller(conn net.Conn) error {
	uid, _, err := peerIdentity(conn)
	if err != nil {
		return fmt.Errorf("caller authentication failed")
	}
	if len(r.cfg.TrustedCallerUIDs) == 0 {
		if uid != r.ownUID {
			return fmt.Errorf("caller UID %d is not the recipient identity", uid)
		}
		return nil
	}
	for _, allowed := range r.cfg.TrustedCallerUIDs {
		if uid == allowed {
			return nil
		}
	}
	return fmt.Errorf("caller UID %d is not a trusted broker identity", uid)
}

func (r *RecipientServer) handleConn(conn net.Conn) {
	defer conn.Close()
	if err := r.authorizeCaller(conn); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(r.cfg.ConnDeadline))
	frame, err := readFrame(conn, r.cfg.MaxFrameBytes)
	if err != nil {
		return
	}
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(frame, &head); err != nil {
		return
	}
	switch head.Kind {
	case "", "delivery":
		r.handleDelivery(conn, frame)
	case "lookup":
		r.handleLookup(conn, frame)
	default:
		return
	}
}

func (r *RecipientServer) handleDelivery(conn net.Conn, frame []byte) {
	var env struct {
		Version uint32 `json:"v"`
		OpID    string `json:"op_id"`
		Digest  string `json:"digest"`
		Payload string `json:"payload"`
	}
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return
	}
	if env.Version != envelopeVersion {
		r.writeError(conn, env.OpID, env.Digest, "unsupported envelope version")
		return
	}
	payload := []byte(env.Payload)
	if err := ValidateDelivery(Delivery{OperationID: env.OpID, Payload: payload}, env.Digest); err != nil {
		r.writeError(conn, env.OpID, env.Digest, "delivery rejected")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.ConnDeadline)
	defer cancel()
	acceptance, err := r.cfg.Consumer.Accept(ctx, Delivery{
		OperationID: env.OpID,
		Payload:     payload,
	})
	if err != nil {
		r.writeError(conn, env.OpID, env.Digest, "commit failed")
		return
	}
	if acceptance.Digest != env.Digest {
		r.writeError(conn, env.OpID, env.Digest, "consumer committed a different payload")
		return
	}
	r.writeAck(conn, env.OpID, env.Digest, len(payload))
}

func (r *RecipientServer) handleLookup(conn net.Conn, frame []byte) {
	var req LookupRequest
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return
	}
	if req.Version != envelopeVersion {
		r.writeLookupError(conn, req.OpID, req.Digest, "unsupported version")
		return
	}
	if !ValidOperationID(req.OpID) {
		r.writeLookupError(conn, req.OpID, req.Digest, "invalid operation id")
		return
	}
	if req.Digest != "" && !ValidDigest(req.Digest) {
		r.writeLookupError(conn, req.OpID, req.Digest, "invalid digest")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.ConnDeadline)
	defer cancel()
	state, err := r.cfg.Consumer.Lookup(ctx, req.OpID)
	if err != nil {
		r.writeLookupError(conn, req.OpID, req.Digest, "lookup failed")
		return
	}
	if state == "" {
		state = StateUnknown
	}
	digest := req.Digest
	if digest == "" {
		if dr, ok := r.cfg.Consumer.(DigestReporter); ok {
			if stored, err := dr.StoredDigest(ctx, req.OpID); err == nil {
				digest = stored
			}
		}
	}
	resp := LookupResponse{OpID: req.OpID, Digest: digest, Status: string(state)}
	out, _ := json.Marshal(resp)
	_ = writeFrame(conn, out)
}

func readFrame(conn net.Conn, max int) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || int(n) > max {
		return nil, fmt.Errorf("frame out of bounds")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(conn net.Conn, frame []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if err := writeFull(conn, lenBuf[:]); err != nil {
		return err
	}
	return writeFull(conn, frame)
}

func (r *RecipientServer) writeAck(conn net.Conn, opID, digest string, bytes int) {
	a := ack{Accepted: true, OpID: opID, Digest: digest, Bytes: bytes}
	frame, _ := json.Marshal(a)
	_ = writeFrame(conn, frame)
}

func (r *RecipientServer) writeError(conn net.Conn, opID, digest, msg string) {
	a := ack{Accepted: false, OpID: opID, Digest: digest, Error: msg}
	frame, _ := json.Marshal(a)
	_ = writeFrame(conn, frame)
}

func (r *RecipientServer) writeLookupError(conn net.Conn, opID, digest, msg string) {
	resp := LookupResponse{OpID: opID, Digest: digest, Status: RecipientRejected, Error: msg}
	frame, _ := json.Marshal(resp)
	_ = writeFrame(conn, frame)
}

// ErrUnavailable matches the deliverer's recipient-unavailable diagnostic.
var ErrUnavailable = errors.New("recipient unavailable")
