//go:build linux

package transfer

import (
	"fmt"
	"net"
	"syscall"
)

// peerIdentity returns the OS credentials of the process on the other end of
// a Unix connection. Checked BEFORE any payload byte is sent (C05).
func peerIdentity(conn net.Conn) (uid, gid uint32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var ucred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		ucred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return ucred.Uid, ucred.Gid, nil
}
