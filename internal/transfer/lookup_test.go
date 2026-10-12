package transfer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// lookupFixture serves one scripted LookupResponse per connection.
func lookupFixture(t *testing.T, respond func(req map[string]interface{}) interface{}) string {
	t.Helper()
	sock := filepath.Join(sockDir(t), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var lb [4]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(lb[:])
				if n == 0 || n > 2<<20 {
					return
				}
				buf := make([]byte, n)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				var req map[string]interface{}
				if err := json.Unmarshal(buf, &req); err != nil {
					return
				}
				raw, _ := json.Marshal(respond(req))
				binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
				_, _ = c.Write(lb[:])
				_, _ = c.Write(raw)
			}(c)
		}
	}()
	return sock
}

// CV-10: the lookup answer binds the requested operation and payload.
func TestLookupBindsOperation(t *testing.T) {
	d := NewDeliverer()
	sock := lookupFixture(t, func(req map[string]interface{}) interface{} {
		return map[string]interface{}{
			"op_id": req["op_id"], "digest": "abc", "status": RecipientDurablyAccepted, "bytes": 3,
		}
	})
	res, err := d.Lookup(context.Background(), destOf(t, "recipient-socket", sock), "op-1", "")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if res.Status != RecipientDurablyAccepted || res.Digest != "abc" {
		t.Fatalf("bad result: %+v", res)
	}
}

// A pinned digest that echoes differently is another payload: rejected.
func TestLookupDigestMismatch(t *testing.T) {
	d := NewDeliverer()
	sock := lookupFixture(t, func(req map[string]interface{}) interface{} {
		return map[string]interface{}{
			"op_id": req["op_id"], "digest": "other", "status": RecipientDurablyAccepted,
		}
	})
	if _, err := d.Lookup(context.Background(), destOf(t, "recipient-socket", sock), "op-1", "abc"); err == nil {
		t.Fatal("lookup accepted an answer binding another payload")
	}
}

// An answer for a foreign operation is rejected.
func TestLookupForeignOpRejected(t *testing.T) {
	d := NewDeliverer()
	sock := lookupFixture(t, func(req map[string]interface{}) interface{} {
		return map[string]interface{}{
			"op_id": "someone-else", "digest": "abc", "status": RecipientApplied,
		}
	})
	if _, err := d.Lookup(context.Background(), destOf(t, "recipient-socket", sock), "op-1", ""); err == nil {
		t.Fatal("lookup accepted a foreign-operation answer")
	}
}

// Status vocabulary is closed: unknown states are transport failures,
// never silently accepted.
func TestLookupClosedVocabulary(t *testing.T) {
	d := NewDeliverer()
	sock := lookupFixture(t, func(req map[string]interface{}) interface{} {
		return map[string]interface{}{
			"op_id": req["op_id"], "digest": "abc", "status": "definitely-applied-trust-me",
		}
	})
	if _, err := d.Lookup(context.Background(), destOf(t, "recipient-socket", sock), "op-1", ""); err == nil {
		t.Fatal("lookup accepted an out-of-vocabulary status")
	}
}

// Rejected and unknown are honest terminal answers that pass through.
func TestLookupHonestTerminals(t *testing.T) {
	d := NewDeliverer()
	for _, st := range []string{RecipientRejected, RecipientUnknown, RecipientApplied} {
		sock := lookupFixture(t, func(req map[string]interface{}) interface{} {
			return map[string]interface{}{
				"op_id": req["op_id"], "digest": "abc", "status": st,
			}
		})
		res, err := d.Lookup(context.Background(), destOf(t, "recipient-socket", sock), "op-1", "")
		if err != nil || res.Status != st {
			t.Fatalf("status %s: %+v %v", st, res, err)
		}
	}
}
