// Package transfer: the recipient-side consumer contract (SP-18/P0).
//
// The original reference recipient acknowledged a delivery after storing
// only (op_id, digest) metadata. That is not credential consumption: the
// bytes reached a process, but nothing durable or verifiable happened to
// them. This file replaces the ambiguous "acceptance store" with an
// explicit SecretConsumer contract plus a plaintext-free operation
// journal. A consumer may only report a terminal success state after it
// has either securely committed the secret to the configured destination
// or executed the permitted credentialed action and verified the effect.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// DeliveryState is the closed, typed vocabulary a consumer reports for one
// operation. It intentionally mirrors the wire Recipient* constants in
// lookup.go: the wire layer stays a string protocol, but broker-side logic
// switches on this type so an unknown string cannot be mistaken for a
// terminal state.
type DeliveryState string

const (
	// StateUnknown means the consumer holds no record for the operation.
	StateUnknown DeliveryState = "unknown"
	// StateReceived means bytes arrived but are not yet durably committed.
	// It is a transient state, never a successful terminal outcome.
	StateReceived DeliveryState = "received"
	// StateDurablyAccepted means the secret is committed to its configured
	// destination (or the permitted action was performed) but the consumer
	// could not independently verify the intended effect.
	StateDurablyAccepted DeliveryState = "durably_accepted"
	// StateApplied means the consumer independently verified the intended
	// effect of the credentialed operation. Only a consumer that can
	// actually verify application may report this state.
	StateApplied DeliveryState = "applied"
	// StateRejected means the operation was refused and no effect occurred.
	StateRejected DeliveryState = "rejected"
)

// validDeliveryState reports whether s is in the closed vocabulary.
func validDeliveryState(s DeliveryState) bool {
	switch s {
	case StateUnknown, StateReceived, StateDurablyAccepted, StateApplied, StateRejected:
		return true
	}
	return false
}

// Delivery is one broker->consumer credential delivery. Payload is the
// plaintext, held only for the duration of Accept: a consumer must never
// persist it under its own name unless the configured destination IS a
// secret store.
type Delivery struct {
	OperationID string
	DataKind    string
	Payload     []byte
}

// Acceptance is the consumer's answer for one Accept call. State is the
// post-call state; Duplicate reports that this operation was already
// committed and no side effect was repeated.
type Acceptance struct {
	OperationID string
	DataKind    string
	Digest      string
	State       DeliveryState
	Duplicate   bool
}

// SecretConsumer is the recipient-side contract the broker's transfer path
// depends on. Implementations must be idempotent under (OperationID,
// digest): a repeated delivery of the same bytes must not repeat the
// credentialed side effect.
type SecretConsumer interface {
	// Accept commits the delivery to its destination (or executes the
	// permitted action) and returns the resulting state. It must return an
	// error, and no terminal success state, when it cannot commit.
	Accept(ctx context.Context, delivery Delivery) (Acceptance, error)
	// Lookup reports the current state for an operation without moving any
	// payload. Reconciliation uses this after an ambiguous acknowledgment.
	Lookup(ctx context.Context, operationID string) (DeliveryState, error)
}

// Committed is the outcome a CredentialCommitter reports for one commit.
type Committed struct {
	// Applied is true when the committed action's intended effect is
	// verified (not merely attempted).
	Applied bool
	// Digest is the digest of the bytes actually committed, echoed so the
	// consumer can confirm it committed exactly what it was handed.
	Digest string
}

// CredentialCommitter is the destination-specific half of a consumer: it
// knows how to securely commit a secret to a real credential destination or
// perform one permitted credentialed action. It contains no broker state.
type CredentialCommitter interface {
	// Commit commits the delivery. It must be idempotent for a repeated
	// (OperationID, digest) pair. A nil error with applied == false means
	// the secret was durably stored but application was not verified.
	Commit(ctx context.Context, delivery Delivery) (Committed, error)
}

var (
	// opIDPattern is the accepted operation-id shape. It deliberately
	// excludes path separators and "." so an untrusted wire string can
	// never be used directly as a filesystem component.
	opIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	// digestPattern is a lowercase hex sha256.
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidOperationID reports whether id is a safe opaque operation id.
func ValidOperationID(id string) bool { return opIDPattern.MatchString(id) }

// ValidDigest reports whether d is a lowercase hex sha256 digest.
func ValidDigest(d string) bool { return digestPattern.MatchString(d) }

// PayloadDigest is the canonical digest of a payload. It is the same
// function the broker uses to bind the wire envelope, so a consumer can
// verify payload/digest agreement independently of the sender.
func PayloadDigest(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// ValidationError marks a delivery rejected before any side effect.
type ValidationError struct{ Reason string }

func (e *ValidationError) Error() string { return "delivery rejected: " + e.Reason }

func invalid(reason string) error { return &ValidationError{Reason: reason} }

// ErrOperationConflict is returned when a repeated operation id carries a
// different digest than the one already committed.
var ErrOperationConflict = errors.New("operation id already committed with a different payload")

// ValidateDelivery enforces the delivery preconditions a consumer must not
// skip: safe operation id, present payload, and payload/digest agreement.
func ValidateDelivery(d Delivery, claimedDigest string) error {
	if !ValidOperationID(d.OperationID) {
		return invalid("operation id is not an accepted opaque identifier")
	}
	if len(d.Payload) == 0 {
		return invalid("empty payload")
	}
	actual := PayloadDigest(d.Payload)
	switch {
	case claimedDigest == "":
		return invalid("missing digest")
	case !ValidDigest(claimedDigest):
		return invalid("digest is not a lowercase hex sha256")
	case claimedDigest != actual:
		return invalid("payload does not match the claimed digest")
	}
	return nil
}

// DigestReporter is an optional refinement of SecretConsumer: a consumer
// that can answer a wildcard lookup with the digest it actually holds, so
// the recipient socket never has to echo an empty digest back to a
// reconciling broker.
type DigestReporter interface {
	StoredDigest(ctx context.Context, operationID string) (string, error)
}

// JournalEntry is the durable, plaintext-free record of one committed
// operation. It never contains the secret or a low-entropy derivative of
// it: Digest is the sha256 the broker already puts on the trusted wire.
type JournalEntry struct {
	OperationID string        `json:"operation_id"`
	DataKind    string        `json:"data_kind,omitempty"`
	Digest      string        `json:"digest"`
	State       DeliveryState `json:"state"`
	Applied     bool          `json:"applied"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// OperationJournal is a durable, plaintext-free record store keyed by a
// validated operation id. Record filenames are derived from the validated
// id, never from an untrusted wire string.
type OperationJournal struct {
	dir string
	mu  sync.Mutex
}

// NewOperationJournal creates a journal rooted at dir (0700).
func NewOperationJournal(dir string) (*OperationJournal, error) {
	if dir == "" {
		return nil, fmt.Errorf("operation journal directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("operation journal create: %w", err)
	}
	return &OperationJournal{dir: dir}, nil
}

func (j *OperationJournal) path(operationID string) (string, error) {
	if !ValidOperationID(operationID) {
		return "", invalid("operation id is not an accepted opaque identifier")
	}
	return filepath.Join(j.dir, operationID+".json"), nil
}

// Load returns the entry for operationID. ok is false when no record exists.
func (j *OperationJournal) Load(operationID string) (JournalEntry, bool, error) {
	path, err := j.path(operationID)
	if err != nil {
		return JournalEntry{}, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return JournalEntry{}, false, nil
		}
		return JournalEntry{}, false, err
	}
	var e JournalEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return JournalEntry{}, false, fmt.Errorf("corrupt operation journal record: %w", err)
	}
	if !validDeliveryState(e.State) {
		return JournalEntry{}, false, fmt.Errorf("corrupt operation journal state %q", e.State)
	}
	return e, true, nil
}

// Upsert writes the entry durably (temp file, fsync, atomic rename).
func (j *OperationJournal) Upsert(entry JournalEntry) error {
	if !ValidOperationID(entry.OperationID) {
		return invalid("operation id is not an accepted opaque identifier")
	}
	if !ValidDigest(entry.Digest) {
		return invalid("digest is not a lowercase hex sha256")
	}
	if !validDeliveryState(entry.State) {
		return invalid("state is outside the closed vocabulary")
	}
	entry.UpdatedAt = time.Now().UTC()
	path, err := j.path(entry.OperationID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tmp, err := os.CreateTemp(j.dir, ".journal-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
		_ = tmp.Close()
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// List returns every journaled entry (bounded by the caller).
func (j *OperationJournal) List() ([]JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	var out []JournalEntry
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(j.dir, e.Name()))
		if err != nil {
			continue
		}
		var entry JournalEntry
		if json.Unmarshal(data, &entry) == nil && validDeliveryState(entry.State) {
			out = append(out, entry)
		}
	}
	return out, nil
}

// ApplicationConsumer is the production SecretConsumer: it journals every
// operation and commits the secret through a destination-specific
// CredentialCommitter. It reports StateApplied only when the committer
// verifies the intended effect; otherwise it reports StateDurablyAccepted.
type ApplicationConsumer struct {
	journal    *OperationJournal
	committer  CredentialCommitter
	commitHint time.Duration
}

// NewApplicationConsumer builds a consumer over journal and committer.
func NewApplicationConsumer(journal *OperationJournal, committer CredentialCommitter) (*ApplicationConsumer, error) {
	if journal == nil {
		return nil, fmt.Errorf("operation journal required")
	}
	if committer == nil {
		return nil, fmt.Errorf("credential committer required")
	}
	return &ApplicationConsumer{journal: journal, committer: committer}, nil
}

// Accept journals and commits one delivery. A repeated (OperationID, digest)
// is acknowledged idempotently without repeating the side effect; a repeated
// operation id with a different digest is refused.
func (c *ApplicationConsumer) Accept(ctx context.Context, d Delivery) (Acceptance, error) {
	digest := PayloadDigest(d.Payload)
	if err := ValidateDelivery(d, digest); err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	existing, ok, err := c.journal.Load(d.OperationID)
	if err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	if ok {
		if existing.Digest != digest {
			return Acceptance{
				OperationID: d.OperationID,
				DataKind:    existing.DataKind,
				Digest:      existing.Digest,
				State:       existing.State,
			}, ErrOperationConflict
		}
		// Idempotent replay: report the state already reached, no re-commit.
		return Acceptance{
			OperationID: d.OperationID,
			DataKind:    existing.DataKind,
			Digest:      existing.Digest,
			State:       existing.State,
			Duplicate:   true,
		}, nil
	}
	// Record receipt before the (possibly slow, possibly external) commit so
	// a crash mid-commit is visible for reconciliation rather than silent.
	if err := c.journal.Upsert(JournalEntry{
		OperationID: d.OperationID,
		DataKind:    d.DataKind,
		Digest:      digest,
		State:       StateReceived,
	}); err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	committed, err := c.committer.Commit(ctx, d)
	if err != nil {
		// Do not claim success: leave the record in StateReceived so an
		// operator can see the operation is neither applied nor cleanly
		// rejected.
		return Acceptance{
			OperationID: d.OperationID,
			DataKind:    d.DataKind,
			Digest:      digest,
			State:       StateReceived,
		}, err
	}
	if committed.Digest != "" && committed.Digest != digest {
		return Acceptance{
			OperationID: d.OperationID,
			DataKind:    d.DataKind,
			Digest:      digest,
			State:       StateReceived,
		}, invalid("committer reported a different payload digest")
	}
	state := StateDurablyAccepted
	if committed.Applied {
		state = StateApplied
	}
	if err := c.journal.Upsert(JournalEntry{
		OperationID: d.OperationID,
		DataKind:    d.DataKind,
		Digest:      digest,
		State:       state,
		Applied:     committed.Applied,
	}); err != nil {
		return Acceptance{
			OperationID: d.OperationID,
			DataKind:    d.DataKind,
			Digest:      digest,
			State:       StateReceived,
		}, err
	}
	return Acceptance{
		OperationID: d.OperationID,
		DataKind:    d.DataKind,
		Digest:      digest,
		State:       state,
	}, nil
}

// Lookup reports the journaled state for an operation.
func (c *ApplicationConsumer) Lookup(ctx context.Context, operationID string) (DeliveryState, error) {
	entry, ok, err := c.journal.Load(operationID)
	if err != nil {
		return StateUnknown, err
	}
	if !ok {
		return StateUnknown, nil
	}
	return entry.State, nil
}

// StoredDigest reports the digest committed for an operation ("" when none).
func (c *ApplicationConsumer) StoredDigest(ctx context.Context, operationID string) (string, error) {
	entry, ok, err := c.journal.Load(operationID)
	if err != nil || !ok {
		return "", err
	}
	return entry.Digest, nil
}

// ReferenceRecipient is a metadata-only SecretConsumer used only as a test
// fixture. It journals durably_accepted without committing the secret to any
// destination, so it MUST NOT be wired as a production credential consumer:
// use ApplicationConsumer with a real CredentialCommitter instead.
type ReferenceRecipient struct {
	journal *OperationJournal
}

// NewReferenceRecipient builds the fixture over a journal.
func NewReferenceRecipient(journal *OperationJournal) (*ReferenceRecipient, error) {
	if journal == nil {
		return nil, fmt.Errorf("operation journal required")
	}
	return &ReferenceRecipient{journal: journal}, nil
}

// Accept records durably_accepted without applying the payload (fixture only).
func (r *ReferenceRecipient) Accept(ctx context.Context, d Delivery) (Acceptance, error) {
	digest := PayloadDigest(d.Payload)
	if err := ValidateDelivery(d, digest); err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	existing, ok, err := r.journal.Load(d.OperationID)
	if err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	if ok {
		if existing.Digest != digest {
			return Acceptance{
				OperationID: d.OperationID,
				DataKind:    existing.DataKind,
				Digest:      existing.Digest,
				State:       existing.State,
			}, ErrOperationConflict
		}
		return Acceptance{
			OperationID: d.OperationID,
			DataKind:    existing.DataKind,
			Digest:      existing.Digest,
			State:       existing.State,
			Duplicate:   true,
		}, nil
	}
	if err := r.journal.Upsert(JournalEntry{
		OperationID: d.OperationID,
		DataKind:    d.DataKind,
		Digest:      digest,
		State:       StateDurablyAccepted,
	}); err != nil {
		return Acceptance{OperationID: d.OperationID, State: StateRejected}, err
	}
	return Acceptance{
		OperationID: d.OperationID,
		DataKind:    d.DataKind,
		Digest:      digest,
		State:       StateDurablyAccepted,
	}, nil
}

// Lookup reports the journaled state for an operation (fixture).
func (r *ReferenceRecipient) Lookup(ctx context.Context, operationID string) (DeliveryState, error) {
	entry, ok, err := r.journal.Load(operationID)
	if err != nil {
		return StateUnknown, err
	}
	if !ok {
		return StateUnknown, nil
	}
	return entry.State, nil
}

// StoredDigest reports the digest recorded for an operation (fixture).
func (r *ReferenceRecipient) StoredDigest(ctx context.Context, operationID string) (string, error) {
	entry, ok, err := r.journal.Load(operationID)
	if err != nil || !ok {
		return "", err
	}
	return entry.Digest, nil
}

// CallbackCommitter adapts a function into a CredentialCommitter. It exists
// for embedding and tests; production deployments wire a destination-specific
// committer (file, git, scoped HTTP) from secureops.
type CallbackCommitter struct {
	Fn func(ctx context.Context, d Delivery) (Committed, error)
}

// Commit calls Fn.
func (c *CallbackCommitter) Commit(ctx context.Context, d Delivery) (Committed, error) {
	if c.Fn == nil {
		return Committed{}, errors.New("committer not configured")
	}
	return c.Fn(ctx, d)
}

// FileCommitter durably commits a secret to an owner-only file and verifies
// the intended effect by reading the file back and comparing digests. It is
// the reference "securely store it" consumer used by the privileged
// qualification harness: the destination directory must be 0700 and the file
// is written 0600 with fsync before rename.
type FileCommitter struct {
	dir string
}

// NewFileCommitter creates the destination directory (0700).
func NewFileCommitter(dir string) (*FileCommitter, error) {
	if dir == "" {
		return nil, fmt.Errorf("file committer directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FileCommitter{dir: dir}, nil
}

// Commit writes the payload to <dir>/<operation-id>.secret and verifies the
// digest by reading it back.
func (f *FileCommitter) Commit(ctx context.Context, d Delivery) (Committed, error) {
	digest := PayloadDigest(d.Payload)
	if err := ValidateDelivery(d, digest); err != nil {
		return Committed{}, err
	}
	path := filepath.Join(f.dir, d.OperationID+".secret")
	tmp, err := os.CreateTemp(f.dir, ".commit-*.tmp")
	if err != nil {
		return Committed{}, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
		_ = tmp.Close()
	}()
	if err := tmp.Chmod(0600); err != nil {
		return Committed{}, err
	}
	if _, err := tmp.Write(d.Payload); err != nil {
		return Committed{}, err
	}
	if err := tmp.Sync(); err != nil {
		return Committed{}, err
	}
	if err := tmp.Close(); err != nil {
		return Committed{}, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return Committed{}, err
	}
	// Independently verify the intended effect: the destination now holds
	// exactly the digest that was committed.
	readback, err := os.ReadFile(path)
	if err != nil {
		return Committed{}, fmt.Errorf("verify readback: %w", err)
	}
	if got := PayloadDigest(readback); got != digest {
		return Committed{Digest: got}, fmt.Errorf("readback digest mismatch")
	}
	return Committed{Applied: true, Digest: digest}, nil
}
