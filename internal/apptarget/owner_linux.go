//go:build linux

package apptarget

import (
	"fmt"
	"os"
	"syscall"
)

func validateDirectory(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("application config parent is not controlled by the recipient")
	}
	if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("application config parent is writable by an untrusted identity")
	}
	return nil
}

func validateFileOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("application credential file is not recipient-owned")
	}
	return nil
}
