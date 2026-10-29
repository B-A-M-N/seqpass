//go:build !linux

package apptarget

import (
	"fmt"
	"net"
)

func verifyFIGatewayPeer(net.Conn, *uint32) error {
	return fmt.Errorf("FI Gateway credential handoff requires Linux peer credentials")
}
