package transfer

import "testing"

func TestRecipientAcceptPersistsDurably(t *testing.T) {
	store, err := NewRecipientStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	digest := PayloadDigest(payload)
	first, err := store.Accept("op1", digest, payload)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if first {
		t.Fatal("first accept should return false (not duplicate)")
	}
	// Verify durable persistence.
	state, err := store.Status("op1", digest)
	if err != nil {
		t.Fatal(err)
	}
	if state != RecipientStateDurablyAccepted {
		t.Fatalf("state = %q, want %q", state, RecipientStateDurablyAccepted)
	}
	// Duplicate with the same digest is idempotent.
	dup, err := store.Accept("op1", digest, payload)
	if err != nil {
		t.Fatalf("duplicate accept: %v", err)
	}
	if !dup {
		t.Fatal("duplicate should return true (already accepted)")
	}
}

func TestRecipientDuplicateDigestMismatchFails(t *testing.T) {
	store, err := NewRecipientStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := []byte("payload")
	if _, err := store.Accept("op2", PayloadDigest(a), a); err != nil {
		t.Fatal(err)
	}
	// Same op_id, different digest is refused.
	b := []byte("other")
	if _, err := store.Accept("op2", PayloadDigest(b), b); err == nil {
		t.Fatal("duplicate op_id with different digest accepted")
	}
}

// A payload that does not agree with its claimed digest must be refused, so
// the fixture cannot record acceptance for bytes it never received.
func TestRecipientRejectsDigestMismatch(t *testing.T) {
	store, err := NewRecipientStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept("op3", PayloadDigest([]byte("expected")), []byte("tampered")); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func TestRecipientUnknownStatus(t *testing.T) {
	store, err := NewRecipientStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Status("opunknown", PayloadDigest([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if state != "" {
		t.Fatalf("unknown status = %q, want empty", state)
	}
}
