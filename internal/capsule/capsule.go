// Package capsule implements the signed, recipient-encrypted SeqPass handoff
// envelope. It keeps keyset persistence and recipient identity provisioning
// outside the agent-facing capsule format.
package capsule

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const (
	Version   = 1
	Algorithm = "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305"
	MaxSize   = 1024 * 1024
)

var ErrInvalid = errors.New("invalid handoff capsule")

// Payload is encrypted in full. Credential is raw secret material and must
// never be marshaled or logged outside the authenticated ciphertext.
type Payload struct {
	HandoffID           string    `json:"handoff_id"`
	OperationID         string    `json:"operation_id"`
	DestinationID       string    `json:"destination_id"`
	DestinationRevision int       `json:"destination_revision"`
	TargetID            string    `json:"target_id"`
	App                 string    `json:"app"`
	Provider            string    `json:"provider,omitempty"`
	Account             string    `json:"account"`
	Slot                string    `json:"slot"`
	UpdateMethod        string    `json:"update_method"`
	Activation          string    `json:"activation,omitempty"`
	SourceRef           string    `json:"source_ref"`
	SourceRevision      int       `json:"source_revision"`
	IssuedAt            time.Time `json:"issued_at"`
	NotBefore           time.Time `json:"not_before"`
	ExpiresAt           time.Time `json:"expires_at"`
	Credential          []byte    `json:"credential"`
}

// Envelope is opaque to the agent. Enc is the RFC 9180 KEM encapsulated key;
// Ciphertext is the HPKE ciphertext. Signature is an independent issuer
// signature over every header field plus both encrypted fields.
type Envelope struct {
	Version             int       `json:"version"`
	Kind                string    `json:"kind"`
	Algorithm           string    `json:"algorithm"`
	RecipientKeyID      string    `json:"recipient_key_id"`
	SigningKeyID        string    `json:"signing_key_id"`
	HandoffID           string    `json:"handoff_id"`
	OperationID         string    `json:"operation_id"`
	DestinationID       string    `json:"destination_id"`
	DestinationRevision int       `json:"destination_revision"`
	IssuedAt            time.Time `json:"issued_at"`
	NotBefore           time.Time `json:"not_before"`
	ExpiresAt           time.Time `json:"expires_at"`
	Enc                 []byte    `json:"enc"`
	Ciphertext          []byte    `json:"ciphertext"`
	Signature           []byte    `json:"issuer_signature"`
}

// Expect pins the envelope to the locally registered recipient identity and
// expected operation. Empty optional values are not wildcards for identifiers.
type Expect struct {
	RecipientKeyID      string
	SigningKeyID        string
	HandoffID           string
	OperationID         string
	DestinationID       string
	DestinationRevision int
	TargetID            string
	App                 string
	Provider            string
	Account             string
	Slot                string
	UpdateMethod        string
	Activation          string
	SourceRef           string
	SourceRevision      int
	Now                 time.Time
}

type header struct {
	Version             int       `json:"version"`
	Kind                string    `json:"kind"`
	Algorithm           string    `json:"algorithm"`
	RecipientKeyID      string    `json:"recipient_key_id"`
	SigningKeyID        string    `json:"signing_key_id"`
	HandoffID           string    `json:"handoff_id"`
	OperationID         string    `json:"operation_id"`
	DestinationID       string    `json:"destination_id"`
	DestinationRevision int       `json:"destination_revision"`
	IssuedAt            time.Time `json:"issued_at"`
	NotBefore           time.Time `json:"not_before"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type signedEnvelope struct {
	Header     header `json:"header"`
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

func (e Envelope) header() header {
	return header{e.Version, e.Kind, e.Algorithm, e.RecipientKeyID, e.SigningKeyID, e.HandoffID, e.OperationID, e.DestinationID, e.DestinationRevision, e.IssuedAt, e.NotBefore, e.ExpiresAt}
}

func (e Envelope) signingBytes() ([]byte, error) {
	return json.Marshal(signedEnvelope{Header: e.header(), Enc: e.Enc, Ciphertext: e.Ciphertext})
}

// Seal encrypts payload to recipient and signs the complete envelope. The
// recipient key handle must use Tink's raw RFC 9180 X25519/HKDF-SHA256/
// ChaCha20-Poly1305 template. key IDs are operator-pinned metadata.
func Seal(payload Payload, recipientKeyID, signingKeyID string, recipientPublic *keyset.Handle, issuerPrivate ed25519.PrivateKey) (Envelope, error) {
	if recipientPublic == nil || len(issuerPrivate) != ed25519.PrivateKeySize || !validID(recipientKeyID) || !validID(signingKeyID) {
		return Envelope{}, ErrInvalid
	}
	if err := validatePayload(payload); err != nil {
		return Envelope{}, err
	}
	e := Envelope{
		Version: Version, Kind: "seqpass.sealed-handoff", Algorithm: Algorithm, RecipientKeyID: recipientKeyID, SigningKeyID: signingKeyID,
		HandoffID: payload.HandoffID, OperationID: payload.OperationID, DestinationID: payload.DestinationID,
		DestinationRevision: payload.DestinationRevision, IssuedAt: payload.IssuedAt, NotBefore: payload.NotBefore, ExpiresAt: payload.ExpiresAt,
	}
	ctxInfo, err := json.Marshal(e.header())
	if err != nil {
		return Envelope{}, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	defer zero(plaintext)
	primitive, err := hybrid.NewHybridEncrypt(recipientPublic)
	if err != nil {
		return Envelope{}, fmt.Errorf("initialize HPKE recipient key: %w", err)
	}
	combined, err := primitive.Encrypt(plaintext, ctxInfo)
	if err != nil {
		return Envelope{}, fmt.Errorf("HPKE seal failed: %w", err)
	}
	// RFC 9180 DHKEM(X25519) encodings are exactly 32 bytes.
	if len(combined) <= 32 {
		return Envelope{}, ErrInvalid
	}
	e.Enc = append([]byte(nil), combined[:32]...)
	e.Ciphertext = append([]byte(nil), combined[32:]...)
	zero(combined)
	signed, err := e.signingBytes()
	if err != nil {
		return Envelope{}, err
	}
	e.Signature = ed25519.Sign(issuerPrivate, signed)
	return e, nil
}

// Open verifies the issuer and all pinned metadata before HPKE decryption,
// then checks the authenticated plaintext repeats the exact signed target.
func Open(e Envelope, expect Expect, issuerPublic ed25519.PublicKey, recipientPrivate *keyset.Handle) (Payload, error) {
	if recipientPrivate == nil || len(issuerPublic) != ed25519.PublicKeySize || !validID(expect.RecipientKeyID) || !validID(expect.SigningKeyID) {
		return Payload{}, ErrInvalid
	}
	if e.Version != Version || e.Kind != "seqpass.sealed-handoff" || e.Algorithm != Algorithm || e.RecipientKeyID != expect.RecipientKeyID || e.SigningKeyID != expect.SigningKeyID ||
		e.HandoffID != expect.HandoffID || e.OperationID != expect.OperationID || e.DestinationID != expect.DestinationID || e.DestinationRevision != expect.DestinationRevision ||
		len(e.Enc) != 32 || len(e.Ciphertext) == 0 || len(e.Signature) != ed25519.SignatureSize || len(e.Enc)+len(e.Ciphertext) > MaxSize {
		return Payload{}, ErrInvalid
	}
	now := expect.Now
	if now.IsZero() {
		now = time.Now()
	}
	if e.IssuedAt.After(now.Add(time.Minute)) || e.NotBefore.After(now) || !e.ExpiresAt.After(now) || !e.ExpiresAt.After(e.IssuedAt) || e.ExpiresAt.Sub(e.IssuedAt) > 15*time.Minute {
		return Payload{}, ErrInvalid
	}
	signed, err := e.signingBytes()
	if err != nil || !ed25519.Verify(issuerPublic, signed, e.Signature) {
		return Payload{}, ErrInvalid
	}
	ctxInfo, err := json.Marshal(e.header())
	if err != nil {
		return Payload{}, ErrInvalid
	}
	combined := make([]byte, 0, len(e.Enc)+len(e.Ciphertext))
	combined = append(combined, e.Enc...)
	combined = append(combined, e.Ciphertext...)
	defer zero(combined)
	primitive, err := hybrid.NewHybridDecrypt(recipientPrivate)
	if err != nil {
		return Payload{}, ErrInvalid
	}
	plaintext, err := primitive.Decrypt(combined, ctxInfo)
	if err != nil {
		return Payload{}, ErrInvalid
	}
	defer zero(plaintext)
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, ErrInvalid
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Payload{}, ErrInvalid
	}
	if validatePayload(p) != nil || p.HandoffID != e.HandoffID || p.OperationID != e.OperationID || p.DestinationID != e.DestinationID ||
		p.DestinationRevision != e.DestinationRevision || p.App != expect.App || p.Provider != expect.Provider || p.Account != expect.Account || p.Slot != expect.Slot || p.UpdateMethod != expect.UpdateMethod || p.Activation != expect.Activation ||
		p.TargetID != expect.TargetID || p.SourceRef != expect.SourceRef || p.SourceRevision != expect.SourceRevision || !p.IssuedAt.Equal(e.IssuedAt) || !p.NotBefore.Equal(e.NotBefore) || !p.ExpiresAt.Equal(e.ExpiresAt) {
		zero(p.Credential)
		return Payload{}, ErrInvalid
	}
	// The JSON decoder allocated this credential slice independently of the
	// plaintext buffer above; the recipient owns and must zero it.
	return p, nil
}

func validatePayload(p Payload) error {
	if !validID(p.HandoffID) || !validID(p.OperationID) || !validID(p.DestinationID) || !validID(p.TargetID) || !validID(p.App) || (p.Provider != "" && !validID(p.Provider)) || !validID(p.Account) || !validID(p.Slot) || !validID(p.UpdateMethod) || (p.Activation != "" && !validID(p.Activation)) ||
		p.DestinationRevision <= 0 || p.SourceRevision < 0 || p.SourceRef == "" || len(p.SourceRef) > 256 || len(p.Credential) == 0 || len(p.Credential) > 512*1024 ||
		p.IssuedAt.IsZero() || p.NotBefore.Before(p.IssuedAt) || !p.ExpiresAt.After(p.NotBefore) || p.ExpiresAt.Sub(p.IssuedAt) > 15*time.Minute {
		return ErrInvalid
	}
	return nil
}

func validID(s string) bool {
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r) || r == '_') {
			return false
		}
	}
	return true
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Marshal produces the bounded agent-carriable representation.
func Marshal(e Envelope) ([]byte, error) {
	if e.Version != Version || e.Kind != "seqpass.sealed-handoff" || e.Algorithm != Algorithm || len(e.Signature) != ed25519.SignatureSize || len(e.Enc) != 32 || len(e.Ciphertext) == 0 {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxSize {
		return nil, ErrInvalid
	}
	return b, nil
}

// Parse decodes one bounded envelope and rejects unknown fields and trailing data.
func Parse(b []byte) (Envelope, error) {
	if len(b) == 0 || len(b) > MaxSize {
		return Envelope{}, ErrInvalid
	}
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, ErrInvalid
	}
	if dec.Decode(new(any)) != io.EOF {
		return Envelope{}, ErrInvalid
	}
	if _, err := Marshal(e); err != nil {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}
