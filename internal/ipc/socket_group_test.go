package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SC-04: the agent socket must carry the configured agent group — plain
// Unix bind does not inherit the directory's group, so the broker assigns
// it explicitly and verifies the result. Without this, a deployment can
// satisfy the UID allowlist yet fail at filesystem permission checks (or
// tempt operators into weakening UID isolation to "make it work").
func TestAgentSocketGroupAssigned(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent", "broker.sock")
	egid := uint32(os.Getegid())
	srv := NewServer(nil, sock, "", nil, nil)
	srv.AgentGID = &egid
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat agent socket: %v", err)
	}
	if got := sysGID(st); got != egid {
		t.Fatalf("agent socket GID = %d, want %d (SC-04)", got, egid)
	}
	if perm := st.Mode().Perm(); perm != 0660 {
		t.Fatalf("agent socket mode = %o, want 0660", perm)
	}
	dst, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("stat agent socket dir: %v", err)
	}
	if got := sysGID(dst); got != egid {
		t.Fatalf("agent socket dir GID = %d, want %d (group traverse)", got, egid)
	}
}

// SC-11: a canceled caller stops waiting promptly instead of blocking in a
// read. The black-hole peer never replies; the caller's deadline (not the
// peer) terminates the wait.
func TestCallCtxHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "blackhole.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Never reply; hold the connection open.
			go func() { <-time.After(30 * time.Second); c.Close() }()
		}
	}()
	cli, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := cli.CallCtx(ctx, MethodHealth, nil); err == nil {
		t.Fatal("black-hole call succeeded")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("canceled call blocked %v (SC-11)", elapsed)
	}
	// Pre-canceled context fails without any I/O wait.
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := cli.CallCtx(canceled, MethodHealth, nil); err == nil {
		t.Fatal("pre-canceled call succeeded")
	}
}

// SC-04: agent and admin sockets must be distinct paths; sharing one path
// would collapse the owner-only admin boundary into the group-accessible
// agent socket.
func TestIdenticalSocketPathsRejected(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	srv := NewServer(nil, sock, sock, nil, nil)
	if err := srv.Start(); err == nil {
		srv.Close()
		t.Fatal("identical agent/admin socket paths accepted (SC-04)")
	}
}
