//go:build !linux

package transfer

import (
	"fmt"
	"net"
)

// Non-Linux builds cannot authenticate the recipient peer, so delivery is
// refused: an unauthenticated recipient socket would disclose credentials.
func peerIdentity(conn net.Conn) (uint32, uint32, error) {
	return 0, 0, fmt.Errorf("recipient authentication requires Linux")
}
