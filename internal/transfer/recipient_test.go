package transfer

import (
	"testing"
)

func TestRecipientAcceptPersistsDurably(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRecipientStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Accept("op-1", "digest-1", []byte("payload"))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if first {
		t.Fatal("first accept should return false (not duplicate)")
	}
	// Verify durable persistence.
	state, err := store.Status("op-1", "digest-1")
	if err != nil {
		t.Fatal(err)
	}
	if state != RecipientStateDurablyAccepted {
		t.Fatalf("state = %q, want %q", state, RecipientStateDurablyAccepted)
	}
	// Duplicate with the same digest is idempotent.
	dup, err := store.Accept("op-1", "digest-1", []byte("payload"))
	if err != nil {
		t.Fatalf("duplicate accept: %v", err)
	}
	if !dup {
		t.Fatal("duplicate should return true (already accepted)")
	}
}

func TestRecipientDuplicateDigestMismatchFails(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRecipientStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept("op-2", "digest-a", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	// Same op_id, different digest is refused.
	if _, err := store.Accept("op-2", "digest-b", []byte("other")); err == nil {
		t.Fatal("duplicate op_id with different digest accepted")
	}
}

func TestRecipientUnknownStatus(t *testing.T) {
	store, err := NewRecipientStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Status("op-unknown", "digest")
	if err != nil {
		t.Fatal(err)
	}
	if state != "" {
		t.Fatalf("unknown status = %q, want empty", state)
	}
}
