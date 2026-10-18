package transfer

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// RecipientServer serves the recipient wire contract on a Unix socket.
// It persists every payload durably before acknowledging and answers
// lookup queries from the same durable store.
type RecipientServer struct {
	listener net.Listener
	store    *RecipientStore
	closed   chan struct{}
}

// NewRecipientServer creates and binds a Unix socket at socketPath, backed
// by the provided durable store. The socket is created with 0600 perms.
func NewRecipientServer(socketPath string, store *RecipientStore) (*RecipientServer, error) {
	if socketPath == "" || store == nil {
		return nil, fmt.Errorf("socket path and store required")
	}
	if fi, err := os.Lstat(socketPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to replace symlink at socket path")
		}
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("refusing to delete non-socket at socket path")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return &RecipientServer{listener: l, store: store, closed: make(chan struct{})}, nil
}

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
		go r.handleConn(conn)
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

func (r *RecipientServer) handleConn(conn net.Conn) {
	defer conn.Close()
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 4096 {
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	var req map[string]interface{}
	if err := json.Unmarshal(buf, &req); err != nil {
		return
	}
	switch req["kind"] {
	case "delivery":
		r.handleDelivery(conn, req)
	case "lookup":
		r.handleLookup(conn, req)
	}
}

func (r *RecipientServer) handleDelivery(conn net.Conn, req map[string]interface{}) {
	opID, _ := req["op_id"].(string)
	digest, _ := req["digest"].(string)
	payload, _ := req["payload"].(string)
	if opID == "" || digest == "" {
		r.writeError(conn, opID, digest, "missing op_id or digest")
		return
	}
	// Decode payload from base64.
	// The wire protocol transmits base64-encoded payload.
	payloadBytes, err := json.Marshal([]byte(payload))
	if err != nil {
		r.writeError(conn, opID, digest, "invalid payload")
		return
	}
	var decoded []byte
	if err := json.Unmarshal(payloadBytes, &decoded); err != nil {
		r.writeError(conn, opID, digest, "invalid payload encoding")
		return
	}
	duplicate, err := r.store.Accept(opID, digest, decoded)
	if err != nil {
		r.writeError(conn, opID, digest, err.Error())
		return
	}
	// Persisted before ack. The (op_id, digest) pair is the idempotency key.
	r.writeAck(conn, opID, digest, len(decoded))
	_ = duplicate
}

func (r *RecipientServer) handleLookup(conn net.Conn, req map[string]interface{}) {
	opID, _ := req["op_id"].(string)
	digest, _ := req["digest"].(string)
	if opID == "" {
		r.writeLookupError(conn, opID, digest, "missing op_id")
		return
	}
	state, err := r.store.Status(opID, digest)
	if err != nil {
		r.writeLookupError(conn, opID, digest, err.Error())
		return
	}
	if state == "" {
		state = RecipientUnknown
	}
	resp := LookupResponse{OpID: opID, Digest: digest, Status: state}
	frame, _ := json.Marshal(resp)
	r.writeFrame(conn, frame)
}

func (r *RecipientServer) writeFrame(conn net.Conn, frame []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	_ = writeFull(conn, lenBuf[:])
	_ = writeFull(conn, frame)
}

func (r *RecipientServer) writeAck(conn net.Conn, opID, digest string, bytes int) {
	a := ack{Accepted: true, OpID: opID, Digest: digest, Bytes: bytes}
	frame, _ := json.Marshal(a)
	r.writeFrame(conn, frame)
}

func (r *RecipientServer) writeError(conn net.Conn, opID, digest, msg string) {
	a := ack{Accepted: false, OpID: opID, Digest: digest, Error: msg}
	frame, _ := json.Marshal(a)
	r.writeFrame(conn, frame)
}

func (r *RecipientServer) writeLookupError(conn net.Conn, opID, digest, msg string) {
	resp := LookupResponse{OpID: opID, Digest: digest, Status: RecipientRejected, Error: msg}
	frame, _ := json.Marshal(resp)
	r.writeFrame(conn, frame)
}

// ErrUnavailable matches the deliverer's recipient-unavailable diagnostic.
var ErrUnavailable = errors.New("recipient unavailable")

// ensureTime is used to satisfy the time import in future protocol additions.
var _ = time.Now
