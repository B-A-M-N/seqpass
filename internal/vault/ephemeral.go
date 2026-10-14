package vault

import (
	"sync"
	"time"
)

// MaxEphemeralBytes bounds one staged payload (QR-01). SeqPass relays
// short-lived secrets, not files; the spool lives in broker memory.
const MaxEphemeralBytes = 64 * 1024

// EphemeralStore is the production short-lived payload spool (QR-01).
// Unlike MemoryVault (a test fixture with bare Get semantics), every
// byte here is held under an explicit lifetime and an authorized-holder
// set:
//
//   - payloads expire by deadline and never survive broker restart;
//   - plaintext leaves the store ONLY through GetFor under a live
//     reservation for the exact operation, as a fresh copy;
//   - revocation/expiry fails new reservations and reads immediately;
//     backing bytes are zeroed as soon as no in-flight holder needs
//     them (or at once when nothing is in flight);
//   - clearing is best-effort memory hygiene, not a physical-erasure
//     guarantee: Go copies, swap and OS snapshots are out of scope and
//     must not be claimed otherwise.
//
// The zero value is unusable; construct with NewEphemeralStore.
type EphemeralStore struct {
	mu      sync.Mutex
	payload map[string]*ephemeralEntry
}

type ephemeralEntry struct {
	buf     []byte
	expires time.Time
	revoked bool
	expired bool // deadline passed while holders outstanding
	retain  bool // keep reusable-grant payload until revoke or expiry
	holders map[string]bool
}

// NewEphemeralStore returns an empty production spool.
func NewEphemeralStore() *EphemeralStore {
	return &EphemeralStore{payload: make(map[string]*ephemeralEntry)}
}

// Store stages a payload with a bounded lifetime. Re-storing a live key
// is refused: rotation happens through a new relay, never by silently
// swapping bytes under outstanding reservations.
func (e *EphemeralStore) Store(key string, secret []byte, ttl time.Duration) error {
	return e.store(key, secret, ttl, false)
}

// StoreRetained stages a reusable grant payload. Releasing its last
// operation holder does not clear it; it remains available to separately
// reserved operations until explicit revocation or its original deadline.
func (e *EphemeralStore) StoreRetained(key string, secret []byte, ttl time.Duration) error {
	return e.store(key, secret, ttl, true)
}

func (e *EphemeralStore) store(key string, secret []byte, ttl time.Duration, retain bool) error {
	if key == "" || len(secret) == 0 || len(secret) > MaxEphemeralBytes {
		return ErrNotSupported
	}
	if ttl <= 0 {
		return ErrNotSupported
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ent, ok := e.payload[key]; ok && !ent.gone() {
		return ErrNotSupported
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	e.payload[key] = &ephemeralEntry{
		buf:     cp,
		expires: time.Now().Add(ttl),
		retain:  retain,
		holders: make(map[string]bool),
	}
	return nil
}

// Reserve registers opID as an authorized holder of key. It fails when
// the payload is missing, revoked, or past its deadline — never queues.
// Single-use exclusivity is enforced by relay metadata (remaining uses),
// not here: the store only guarantees that unreserved operations and
// foreign operations cannot read.
func (e *EphemeralStore) Reserve(key, opID string, now time.Time) error {
	if key == "" || opID == "" {
		return ErrNotFound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok || ent.revoked || ent.gone() {
		return ErrNotFound
	}
	if !now.Before(ent.expires) {
		// P0-05: zero backing bytes when marking expired here too.
		ent.expired = true
		clearBytes(ent.buf)
		ent.buf = nil
		return ErrNotFound
	}
	ent.holders[opID] = true
	return nil
}

// HasReservation reports whether opID currently holds key (for admission
// revalidation without touching plaintext).
func (e *EphemeralStore) HasReservation(key, opID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok || ent.revoked || ent.expired || ent.gone() {
		return false
	}
	if !time.Now().Before(ent.expires) {
		return false
	}
	return ent.holders[opID]
}

// GetFor copies the payload out for a holding operation only. The
// caller owns the returned slice and must clear it after use.
func (e *EphemeralStore) GetFor(key, opID string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok || ent.revoked || ent.expired || ent.gone() {
		return nil, ErrNotFound
	}
	if !time.Now().Before(ent.expires) {
		// P0-05: zero backing bytes when marking expired here too.
		ent.expired = true
		clearBytes(ent.buf)
		ent.buf = nil
		return nil, ErrNotFound
	}
	if !ent.holders[opID] {
		return nil, ErrNotFound
	}
	out := make([]byte, len(ent.buf))
	copy(out, ent.buf)
	return out, nil
}

// Release drops one holder. When the entry is dead (revoked/expired/
// deleted-pending) and no holders remain, its bytes are zeroed at once.
func (e *EphemeralStore) Release(key, opID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok {
		return
	}
	delete(ent.holders, opID)
	e.maybeClear(key, ent)
}

// Delete removes a payload immediately, zeroing its bytes unless holders
// are still outstanding — then it is tombstoned (reads fail) and zeroed
// on the last release. Returns true when bytes were present.
func (e *EphemeralStore) Delete(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok {
		return false
	}
	// P0-05: zero backing bytes immediately on delete. Holders already
	// own their copies from GetFor; the store buffer is never needed
	// again and must not retain plaintext for the last-release path.
	ent.revoked = true
	clearBytes(ent.buf)
	ent.buf = nil
	e.maybeClear(key, ent)
	return true
}

// Revoke is Delete with intent documented: outstanding in-flight holders
// keep their already-resolved copies (they cannot be retracted), but no
// new reservation or read can begin.
func (e *EphemeralStore) Revoke(key string) bool { return e.Delete(key) }

// Sweep expires overdue payloads. Entries with holders are marked (reads
// fail from now on) and zeroed when the last holder releases; idle ones
// are zeroed immediately. Previously marked expired/revoked entries with
// no remaining holders are reaped here too (F02): a failed read that
// first observed expiry must not leave backing bytes allocated forever.
// Returns the number of entries reaped or marked.
func (e *EphemeralStore) Sweep(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for k, ent := range e.payload {
		if ent.gone() {
			delete(e.payload, k)
			n++
			continue
		}
		if ent.expired || ent.revoked {
			// Previously marked dead: zero now when no holder needs it.
			before := len(e.payload)
			e.maybeClear(k, ent)
			if len(e.payload) < before {
				n++
			}
			continue
		}
		if !now.Before(ent.expires) {
			// P0-05: zero backing bytes immediately when marking expired.
			ent.expired = true
			clearBytes(ent.buf)
			ent.buf = nil
			e.maybeClear(k, ent)
			n++
		}
	}
	return n
}

// Holders reports the number of outstanding operation holders for key
// (test instrumentation, F02): both holder count and backing-buffer
// zeroization must be asserted, not just Live().
func (e *EphemeralStore) Holders(key string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	if !ok {
		return 0
	}
	return len(ent.holders)
}

// HasBacking reports whether the backing buffer is still allocated for
// key (test instrumentation, F02).
func (e *EphemeralStore) HasBacking(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	return ok && ent.buf != nil
}

// DropAll zeroizes and forgets every payload. This is the broker-restart
// path: in-memory relays are intentionally unavailable after restart,
// and metadata must say so (relay sweep marks them unavailable).
func (e *EphemeralStore) DropAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, ent := range e.payload {
		clearBytes(ent.buf)
		delete(e.payload, k)
	}
}

// Live reports whether readable bytes exist for key (no plaintext).
func (e *EphemeralStore) Live(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.payload[key]
	return ok && !ent.revoked && !ent.expired && !ent.gone() && time.Now().Before(ent.expires)
}

func (ent *ephemeralEntry) gone() bool { return ent.buf == nil }

// maybeClear zeroizes and removes ent when nothing outstanding needs it.
// Caller holds e.mu.
func (e *EphemeralStore) maybeClear(key string, ent *ephemeralEntry) {
	if len(ent.holders) > 0 && !ent.revoked && !ent.expired {
		return
	}
	if len(ent.holders) > 0 && (ent.revoked || ent.expired) {
		// Dead entry with in-flight holders: backing bytes were already
		// zeroed by Delete/Reserve/GetFor/Sweep. Keep the map entry so
		// the last Release removes it.
		return
	}
	if ent.retain && !ent.revoked && !ent.expired {
		return
	}
	clearBytes(ent.buf)
	ent.buf = nil
	delete(e.payload, key)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
