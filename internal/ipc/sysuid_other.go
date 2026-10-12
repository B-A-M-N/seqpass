//go:build !linux

package ipc

import "os"

func sysUID(fi os.FileInfo) int {
	return -1
}

func sysGID(fi os.FileInfo) uint32 {
	return 0
}
