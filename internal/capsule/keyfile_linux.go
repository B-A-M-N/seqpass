//go:build linux

package capsule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func validateKeyParent(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("key directory must be absolute")
	}
	clean := filepath.Clean(dir)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	cur := string(filepath.Separator)
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("key directory contains a symlink or non-directory")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return fmt.Errorf("key directory is not controlled by the service identity")
		}
		if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return fmt.Errorf("key directory is writable by an untrusted identity")
		}
	}
	return nil
}

func validatePrivateKeyFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("key path must be absolute")
	}
	if err := validateKeyParent(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key must be a regular owner-only file owned by the service identity")
	}
	return nil
}

func openPrivateKeyFile(path string) (*os.File, error) {
	if err := validatePrivateKeyFile(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
