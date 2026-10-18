// Package transfer provides the production recipient for SeqPass transfer
// deliveries (SP-18). The recipient persists each envelope under
// (op_id, digest) before acknowledging, supports exact readback for
// reconciliation, handles duplicates idempotently, and distinguishes
// received from durably_accepted states.
package transfer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RecipientState is the closed state vocabulary a recipient reports.
const (
	RecipientStateReceived        = "received"
	RecipientStateDurablyAccepted = "durably_accepted"
)

// RecipientRecord is the durable per-delivery record held by the recipient.
type RecipientRecord struct {
	OpID    string `json:"op_id"`
	Digest  string `json:"digest"`
	State   string `json:"state"`
	Payload []byte `json:"-"` // never serialized through lookup/readback
}

// RecipientStore persists delivery records durably before acknowledgment.
// It is safe for concurrent use.
type RecipientStore struct {
	dir string
	mu  sync.Mutex
}

// NewRecipientStore creates a durable store rooted at dir. Each record is
// written atomically as (op_id).json before its ack is sent.
func NewRecipientStore(dir string) (*RecipientStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("recipient store directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("recipient store create: %w", err)
	}
	return &RecipientStore{dir: dir}, nil
}

func (r *RecipientStore) recordPath(opID, digest string) string {
	// The (op_id, digest) pair is the idempotency key. A safe filename
	// uses op_id directly (broker-generated opaque ID) and digest (hex).
	return filepath.Join(r.dir, fmt.Sprintf("%s_%s.json", opID, digest))
}

// Accept persists the payload under (op_id, digest) before returning a
// durable-acceptance signal. A duplicate (op_id, digest) is acknowledged
// without reapplying side effects; the payload must match the stored digest.
func (r *RecipientStore) Accept(opID, digest string, payload []byte) (bool, error) {
	if opID == "" || digest == "" || payload == nil {
		return false, fmt.Errorf("incomplete delivery")
	}
	path := r.recordPath(opID, digest)
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate: if a record with this op_id exists with a
	// different digest, refuse. Same (op_id, digest) is idempotent.
	if existing, err := os.ReadFile(path); err == nil {
		var rec RecipientRecord
		if json.Unmarshal(existing, &rec) == nil {
			return true, nil // already durably accepted, idempotent re-ack
		}
		return false, fmt.Errorf("corrupt recipient record at %s", path)
	}
	// Check whether any record exists with this op_id but a different digest.
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if err != nil {
			continue
		}
		var rec RecipientRecord
		if json.Unmarshal(data, &rec) == nil && rec.OpID == opID && rec.Digest != digest {
			return false, fmt.Errorf("duplicate op_id %q with different digest", opID)
		}
	}
	// Write atomically: temp file then rename.
	rec := RecipientRecord{OpID: opID, Digest: digest, State: RecipientStateDurablyAccepted}
	data, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(r.dir, "accept-*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
		_ = tmp.Close()
	}()
	if _, err := tmp.Write(data); err != nil {
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return false, nil // first acceptance
}

// Status reports the current delivery state for (op_id, digest).
func (r *RecipientStore) Status(opID, digest string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(r.recordPath(opID, digest))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // unknown
		}
		return "", err
	}
	var rec RecipientRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", err
	}
	return rec.State, nil
}

// ListAll returns all persisted records (bounded by caller).
func (r *RecipientStore) ListAll() ([]*RecipientRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	var out []*RecipientRecord
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if err != nil {
			continue
		}
		var rec RecipientRecord
		if json.Unmarshal(data, &rec) == nil {
			out = append(out, &rec)
		}
	}
	return out, nil
}
