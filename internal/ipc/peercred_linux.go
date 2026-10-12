package ipc

import (
	"fmt"
	"net"
	"syscall"
)

// Peer describes the OS identity of a connecting process.
type Peer struct {
	UID uint32
	GID uint32
	PID int
}

// peerCred extracts SO_PEERCRED from a Unix connection (Linux).
func peerCred(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var credErr error
	err = raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		peer = Peer{UID: ucred.Uid, GID: ucred.Gid, PID: int(ucred.Pid)}
	})
	if err != nil {
		return Peer{}, err
	}
	if credErr != nil {
		return Peer{}, credErr
	}
	return peer, nil
}
