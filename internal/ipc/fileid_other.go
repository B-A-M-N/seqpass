//go:build !linux

package ipc

import "os"

type fileID struct {
	dev uint64
	ino uint64
	ok  bool
}

func statID(fi os.FileInfo) fileID { return fileID{} }
