//go:build !linux

package ipc

import (
	"fmt"
	"net"
)

// Peer describes the OS identity of a connecting process.
type Peer struct {
	UID uint32
	GID uint32
	PID int
}

func peerCred(conn net.Conn) (Peer, error) {
	return Peer{}, fmt.Errorf("peer credentials require linux")
}
