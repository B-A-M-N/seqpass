package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// Recipient delivery states (CV-10). Accepted data and applied data are
// different outcomes: a storage-purpose receiver's terminal state is
// durably_accepted, while only a receiver claiming application-level
// completion may report applied. SeqPass owns retry authorization; the
// recipient owns idempotent acceptance and application state.
const (
	RecipientUnknown         = "unknown"
	RecipientReceived        = "received"
	RecipientDurablyAccepted = "durably_accepted"
	RecipientApplied         = "applied"
	RecipientRejected        = "rejected"
)

func validRecipientStatus(s string) bool {
	switch s {
	case RecipientUnknown, RecipientReceived, RecipientDurablyAccepted,
		RecipientApplied, RecipientRejected:
		return true
	}
	return false
}

// LookupRequest asks the recipient what happened to one operation. An
// empty Digest matches any digest stored under OpID (the reconciling
// operator may not know the digest of an uncertain transfer); a non-empty
// Digest pins the exact payload. The recipient must echo both fields.
type LookupRequest struct {
	Version uint32 `json:"v"`
	Kind    string `json:"kind"`
	OpID    string `json:"op_id"`
	Digest  string `json:"digest"`
}

// LookupResponse is the recipient's answer. OpID/Digest echo the request
// (Digest carries the stored digest when the request left it empty);
// Status is one of the closed Recipient* states.
type LookupResponse struct {
	OpID   string `json:"op_id"`
	Digest string `json:"digest"`
	Status string `json:"status"`
	Bytes  int    `json:"bytes,omitempty"`
	Error  string `json:"error,omitempty"`
}

// LookupResult is the broker-side answer with the peer identity it came
// from, so verification binds recipient identity + operation ID + digest.
type LookupResult struct {
	Status string
	Digest string
	Bytes  int
}

// Lookup asks the recipient for the delivery state of opID without moving
// any payload. It reuses the delivery trust path (endpoint validation +
// peer authentication BEFORE any exchange) and binds the response to the
// requested operation: a stale, forged, or foreign-op answer is rejected.
// Only the recipient's own acceptance/application state is reported —
// Lookup never claims an independent external postcondition.
//
// An empty digest is a DIAGNOSTIC wildcard: it may report whatever the
// recipient holds under the op ID, but it must never settle an uncertain
// transfer (G02). Authoritative reconciliation uses LookupExact with the
// payload digest from the trusted dispatch record.
func (d *Deliverer) Lookup(ctx context.Context, dest *types.Destination, opID, digest string) (LookupResult, error) {
	if dest == nil {
		return LookupResult{}, errors.New("unknown destination")
	}
	if opID == "" {
		return LookupResult{}, errors.New("missing operation id")
	}
	if dest.Type != "recipient-socket" {
		return LookupResult{}, errors.New("lookup needs a recipient-socket destination")
	}
	if err := checkEndpoint(dest.Endpoint, dest); err != nil {
		return LookupResult{}, err
	}
	dialer := net.Dialer{Timeout: dialTO}
	conn, err := dialer.DialContext(ctx, "unix", dest.Endpoint)
	if err != nil {
		return LookupResult{}, errors.New("recipient unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTO))
	uid, gid, err := peerIdentity(conn)
	if err != nil {
		return LookupResult{}, errors.New("recipient authentication failed")
	}
	if uid != *dest.ExpectedUID {
		return LookupResult{}, errors.New("recipient identity mismatch")
	}
	if dest.ExpectedGID != nil && gid != *dest.ExpectedGID {
		return LookupResult{}, errors.New("recipient group mismatch")
	}
	frame, err := json.Marshal(LookupRequest{Version: envelopeVersion, OpID: opID, Digest: digest, Kind: "lookup"})
	if err != nil {
		return LookupResult{}, errors.New("lookup build failed")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if err := writeFull(conn, lenBuf[:]); err != nil {
		return LookupResult{}, errors.New("lookup failed")
	}
	if err := writeFull(conn, frame); err != nil {
		return LookupResult{}, errors.New("lookup failed")
	}
	var respLen [4]byte
	if _, err := io.ReadFull(conn, respLen[:]); err != nil {
		return LookupResult{}, errors.New("lookup failed")
	}
	n := binary.BigEndian.Uint32(respLen[:])
	if n == 0 || n > 4096 {
		return LookupResult{}, errors.New("lookup failed")
	}
	respBuf := make([]byte, n)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return LookupResult{}, errors.New("lookup failed")
	}
	var lr LookupResponse
	dec := json.NewDecoder(bytes.NewReader(respBuf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lr); err != nil {
		return LookupResult{}, errors.New("lookup failed")
	}
	// Bind the answer to the question: op echo must match, a pinned
	// digest must echo back, and the status must be closed vocabulary.
	if lr.OpID != opID {
		return LookupResult{}, errors.New("lookup answer binds another operation")
	}
	if digest != "" && lr.Digest != digest {
		return LookupResult{}, errors.New("lookup answer binds another payload")
	}
	if !validRecipientStatus(lr.Status) {
		return LookupResult{}, errors.New("lookup answer outside closed status vocabulary")
	}
	return LookupResult{Status: lr.Status, Digest: lr.Digest, Bytes: lr.Bytes}, nil
}

// LookupExact is the authoritative reconciliation query (G02): the digest
// is required and must echo exactly. A recipient holding a different
// payload under the same op ID cannot settle this delivery.
func (d *Deliverer) LookupExact(ctx context.Context, dest *types.Destination, opID, digest string) (LookupResult, error) {
	if digest == "" {
		return LookupResult{}, errors.New("authoritative reconciliation requires the exact payload digest")
	}
	return d.Lookup(ctx, dest, opID, digest)
}
