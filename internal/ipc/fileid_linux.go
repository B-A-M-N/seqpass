//go:build linux

package ipc

import (
	"os"
	"syscall"
)

// fileID identifies a filesystem object by device + inode so cleanup removes
// only the exact socket this process bound (C09), never a substituted path.
type fileID struct {
	dev uint64
	ino uint64
	ok  bool
}

func statID(fi os.FileInfo) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino, ok: true}
}
