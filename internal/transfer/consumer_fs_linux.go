//go:build linux

package transfer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openSecureCommitDir(path string) (dirFD int, canonical string, dev, ino uint64, err error) {
	canonical, err = filepath.Abs(path)
	if err != nil {
		return -1, "", 0, 0, err
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", 0, 0, err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(canonical), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkErr := unix.Mkdirat(fd, part, 0700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, "", 0, 0, fmt.Errorf("create credential destination component %s: %w", part, mkErr)
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, "", 0, 0, fmt.Errorf("open credential destination component %s without following symlinks: %w", part, openErr)
		}
		_ = unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, "", 0, 0, fmt.Errorf("inspect credential destination: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return -1, "", 0, 0, fmt.Errorf("credential destination is not a directory")
	}
	if st.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return -1, "", 0, 0, fmt.Errorf("credential destination must be owned by the recipient UID")
	}
	if st.Mode&0077 != 0 {
		_ = unix.Close(fd)
		return -1, "", 0, 0, fmt.Errorf("credential destination must not grant group or other access")
	}
	return fd, canonical, uint64(st.Dev), st.Ino, nil
}

func closeCommitDir(fd int) { _ = unix.Close(fd) }

func writeCommitFileAt(dirFD int, name string, payload []byte) (bool, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	tmpName := ".commit-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(dirFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return false, fmt.Errorf("create private commit file: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = unix.Unlinkat(dirFD, tmpName, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), tmpName)
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("write credential commit: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("sync credential commit: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close credential commit: %w", err)
	}
	if err := unix.Renameat2(dirFD, tmpName, dirFD, name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, fmt.Errorf("commit credential without replacement: %w", err)
	}
	committed = true
	if err := unix.Fsync(dirFD); err != nil {
		return true, fmt.Errorf("sync credential destination directory: %w", err)
	}
	return true, nil
}

func readCommitFileAt(dirFD int, name string, expectedSize int) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close() //nolint:errcheck
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return nil, fmt.Errorf("existing credential destination is not a private regular file owned by the recipient")
	}
	if st.Size != int64(expectedSize) {
		return nil, fmt.Errorf("existing credential destination has unexpected size")
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(expectedSize)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) != expectedSize {
		return nil, fmt.Errorf("credential destination changed during verification")
	}
	return payload, nil
}
