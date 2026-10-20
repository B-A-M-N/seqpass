//go:build !linux

package aegiskeys

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// socketPair is unsupported on non-Linux hosts: the credential-resolution
// helper is a Linux deployment mechanism (peer verification reads
// /proc/<pid>/exe). Non-Linux builds keep the in-process resolve path.
func socketPair() (server net.Conn, child *os.File, err error) {
	return nil, nil, errors.New("resolve helper requires Linux")
}

// helperCommand is unused on non-Linux hosts.
func helperCommand(ctx context.Context, helperPath, aegisSocket string, child *os.File) *exec.Cmd {
	return nil
}
