//go:build linux

package apptarget

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func verifyFIGatewayPeer(connection net.Conn, expectedUID *uint32) error {
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("gateway connection is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	var peerUID uint32
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		credential, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		peerUID = credential.Uid
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	wantUID := uint32(os.Geteuid())
	if expectedUID != nil {
		wantUID = *expectedUID
	}
	if peerUID != wantUID {
		return fmt.Errorf("gateway peer uid mismatch")
	}
	return nil
}
