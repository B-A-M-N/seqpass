package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// defaultCallTimeout bounds a call without a caller deadline. The broker's
// handler timeout is 30s; the client margin above it keeps a canceled or
// stalled harness request from waiting forever (SC-11).
const defaultCallTimeout = 60 * time.Second

type Client struct {
	mu   sync.Mutex
	conn net.Conn
	enc  *json.Encoder
	sc   *bufio.Scanner
	w    *bufio.Writer
	seq  int64
}

func Dial(socket string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("broker unavailable: %w", err)
	}
	w := bufio.NewWriter(conn)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &Client{
		conn: conn,
		enc:  json.NewEncoder(w),
		sc:   sc,
		w:    w,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// Call performs one IPC round-trip. No secret material may appear in params.
// Plaintext is returned only by handoff.redeem on the authenticated recipient
// socket; callers must keep that response inside the recipient process.
func (c *Client) Call(method string, params map[string]interface{}) (interface{}, error) {
	return c.CallCtx(context.Background(), method, params)
}

// CallCtx performs one IPC round-trip honoring ctx cancellation: the
// caller's deadline (or a default bound) becomes the connection deadline,
// so a canceled harness request stops waiting promptly instead of blocking
// in a read (SC-11). Cancellation stops the wait, not the operation: once
// the broker crosses dispatch, the outcome must be reconciled via status,
// never inferred from the canceled wait.
func (c *Client) CallCtx(ctx context.Context, method string, params map[string]interface{}) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > defaultCallTimeout {
		deadline = time.Now().Add(defaultCallTimeout)
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer c.conn.SetDeadline(time.Time{})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("c%d", atomic.AddInt64(&c.seq, 1))
	if err := c.enc.Encode(Request{ID: id, Method: method, Params: params}); err != nil {
		return nil, err
	}
	if err := c.w.Flush(); err != nil {
		return nil, err
	}
	for c.sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var resp Response
		if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
			return nil, fmt.Errorf("protocol mismatch")
		}
		if resp.ID != id {
			continue
		}
		if !resp.OK {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return resp.Data, nil
	}
	if err := c.sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("broker closed connection")
}
