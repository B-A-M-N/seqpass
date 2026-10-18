// Package transfer: the reference recipient store.
//
// SP-18 originally shipped a single "RecipientStore" that persisted delivery
// metadata and acknowledged it. That store is retained ONLY as a test
// fixture and a metadata journal: it does not commit a secret to any
// credential destination, so it must never be advertised or wired as a
// production credential consumer. The production contract lives in
// consumer.go (SecretConsumer + ApplicationConsumer); this file keeps the
// fixture's on-disk shape and its readback so reconciliation tests and the
// recipient wire tests continue to exercise the plaintext-free journal.
package transfer

import (
	"fmt"
	"sync"
)

// RecipientState* are the fixture's state labels. They are string values
// equal to the typed DeliveryState constants so the wire layer, the fixture
// and the production consumer all speak one vocabulary.
const (
	RecipientStateReceived        = string(StateReceived)
	RecipientStateDurablyAccepted = string(StateDurablyAccepted)
)

// RecipientRecord is the plaintext-free record held by the fixture store.
type RecipientRecord struct {
	OpID    string `json:"op_id"`
	Digest  string `json:"digest"`
	State   string `json:"state"`
	Payload []byte `json:"-"` // never serialized through lookup/readback
}

// RecipientStore is a metadata-only reference recipient. It is a test
// fixture: it verifies that a supplied payload agrees with its claimed
// digest and journals durably_accepted, but it does NOT commit the secret
// anywhere. Use ApplicationConsumer for a real credential destination.
type RecipientStore struct {
	journal *OperationJournal
	mu      sync.Mutex
}

// NewRecipientStore creates a fixture store rooted at dir.
func NewRecipientStore(dir string) (*RecipientStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("recipient store directory required")
	}
	j, err := NewOperationJournal(dir)
	if err != nil {
		return nil, err
	}
	return &RecipientStore{journal: j}, nil
}

// Accept journals a delivery after verifying that the payload agrees with
// the claimed digest. It returns duplicate=true when (op_id, digest) was
// already recorded (idempotent re-ack).
func (r *RecipientStore) Accept(opID, digest string, payload []byte) (bool, error) {
	if len(payload) == 0 {
		return false, invalid("empty payload")
	}
	if err := ValidateDelivery(Delivery{OperationID: opID, Payload: payload}, digest); err != nil {
		return false, err
	}
	existing, ok, err := r.journal.Load(opID)
	if err != nil {
		return false, err
	}
	if ok {
		if existing.Digest != digest {
			return false, ErrOperationConflict
		}
		return true, nil
	}
	if err := r.journal.Upsert(JournalEntry{
		OperationID: opID,
		Digest:      digest,
		State:       StateDurablyAccepted,
	}); err != nil {
		return false, err
	}
	return false, nil
}

// Status reports the recorded state for opID (empty when unknown). A
// non-empty digest must match the stored digest; an empty digest is a
// diagnostic wildcard.
func (r *RecipientStore) Status(opID, digest string) (string, error) {
	entry, ok, err := r.journal.Load(opID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	if digest != "" && entry.Digest != digest {
		return "", nil
	}
	return string(entry.State), nil
}

// ListAll returns every journaled record (bounded by caller).
func (r *RecipientStore) ListAll() ([]*RecipientRecord, error) {
	entries, err := r.journal.List()
	if err != nil {
		return nil, err
	}
	out := make([]*RecipientRecord, 0, len(entries))
	for _, e := range entries {
		out = append(out, &RecipientRecord{OpID: e.OperationID, Digest: e.Digest, State: string(e.State)})
	}
	return out, nil
}
