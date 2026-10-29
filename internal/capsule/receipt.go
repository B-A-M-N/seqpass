package capsule

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const ReceiptVersion = 1

// Receipt is a recipient-authenticated, secret-free proof of the result for
// one exact encrypted capsule. Its signing key is distinct from both HPKE
// decryption and issuer signing keys.
type Receipt struct {
	Version             int       `json:"version"`
	Kind                string    `json:"kind"`
	ReceiptKeyID        string    `json:"receipt_key_id"`
	OperationID         string    `json:"operation_id"`
	HandoffID           string    `json:"handoff_id"`
	DestinationID       string    `json:"destination_id"`
	DestinationRevision int       `json:"destination_revision"`
	CapsuleDigest       string    `json:"capsule_digest"`
	CapsuleBytes        int       `json:"capsule_bytes"`
	State               string    `json:"state"`
	IssuedAt            time.Time `json:"issued_at"`
	Signature           []byte    `json:"signature"`
}

type unsignedReceipt struct {
	Version             int       `json:"version"`
	Kind                string    `json:"kind"`
	ReceiptKeyID        string    `json:"receipt_key_id"`
	OperationID         string    `json:"operation_id"`
	HandoffID           string    `json:"handoff_id"`
	DestinationID       string    `json:"destination_id"`
	DestinationRevision int       `json:"destination_revision"`
	CapsuleDigest       string    `json:"capsule_digest"`
	CapsuleBytes        int       `json:"capsule_bytes"`
	State               string    `json:"state"`
	IssuedAt            time.Time `json:"issued_at"`
}

func (r Receipt) unsigned() unsignedReceipt {
	return unsignedReceipt{r.Version, r.Kind, r.ReceiptKeyID, r.OperationID, r.HandoffID,
		r.DestinationID, r.DestinationRevision, r.CapsuleDigest, r.CapsuleBytes,
		r.State, r.IssuedAt}
}

func (r Receipt) validate() error {
	if r.Version != ReceiptVersion || r.Kind != "seqpass.handoff-receipt" ||
		!validID(r.ReceiptKeyID) || !validID(r.OperationID) || !validID(r.HandoffID) ||
		!validID(r.DestinationID) || r.DestinationRevision <= 0 ||
		len(r.CapsuleDigest) != 64 || strings.ToLower(r.CapsuleDigest) != r.CapsuleDigest {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(r.CapsuleDigest); err != nil || r.CapsuleBytes <= 0 || r.CapsuleBytes > MaxSize {
		return ErrInvalid
	}
	switch r.State {
	case "applied", "rejected", "uncertain":
	default:
		return ErrInvalid
	}
	if r.IssuedAt.IsZero() || r.IssuedAt.After(time.Now().Add(time.Minute)) || len(r.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

// SignReceipt signs a canonical secret-free result with a recipient-owned
// Ed25519 key. The signature binds the operation, destination revision,
// handoff ID, encrypted capsule digest, byte count and outcome.
func SignReceipt(r Receipt, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	r.Version = ReceiptVersion
	r.Kind = "seqpass.handoff-receipt"
	r.Signature = nil
	if err := r.validateUnsigned(); err != nil {
		return nil, err
	}
	signed, err := json.Marshal(r.unsigned())
	if err != nil {
		return nil, ErrInvalid
	}
	r.Signature = ed25519.Sign(private, signed)
	b, err := json.Marshal(r)
	if err != nil || len(b) > 16*1024 {
		return nil, ErrInvalid
	}
	return b, nil
}

func (r Receipt) validateUnsigned() error {
	r.Signature = make([]byte, ed25519.SignatureSize)
	return r.validate()
}

// VerifyReceipt strictly parses and authenticates a recipient receipt.
func VerifyReceipt(b []byte, keyID string, public ed25519.PublicKey) (Receipt, error) {
	r, err := ParseReceipt(b)
	if err != nil || len(public) != ed25519.PublicKeySize || !validID(keyID) || r.ReceiptKeyID != keyID {
		return Receipt{}, ErrInvalid
	}
	signed, err := json.Marshal(r.unsigned())
	if err != nil || !ed25519.Verify(public, signed, r.Signature) {
		return Receipt{}, fmt.Errorf("%w: invalid recipient signature", ErrInvalid)
	}
	return r, nil
}

// ParseReceipt validates the bounded, strict wire shape before the caller
// looks up the pinned public key needed for signature verification.
func ParseReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if len(b) == 0 || len(b) > 16*1024 {
		return r, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || dec.Decode(new(any)) != io.EOF {
		return Receipt{}, ErrInvalid
	}
	if r.validate() != nil {
		return Receipt{}, ErrInvalid
	}
	return r, nil
}
