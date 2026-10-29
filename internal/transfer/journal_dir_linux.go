//go:build linux

package transfer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ensureOperationJournalDir creates the leaf directory without following
// symlinks and verifies that only the recipient UID can access it. Ancestors
// may be root-owned or recipient-owned, but may not be writable by other UIDs
// unless they are root-owned sticky directories such as /tmp.
func ensureOperationJournalDir(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == unix.ENOENT && i == len(parts)-1 {
			if mkErr := unix.Mkdirat(fd, part, 0700); mkErr != nil && mkErr != unix.EEXIST {
				return mkErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			return fmt.Errorf("open %q without following symlinks: %w", part, openErr)
		}
		var st unix.Stat_t
		if statErr := unix.Fstat(next, &st); statErr != nil {
			_ = unix.Close(next)
			return statErr
		}
		last := i == len(parts)-1
		if last {
			if st.Uid != uint32(os.Geteuid()) {
				_ = unix.Close(next)
				return fmt.Errorf("journal directory must be recipient-owned")
			}
			if st.Mode&0077 != 0 {
				if err := unix.Fchmod(next, 0700); err != nil {
					_ = unix.Close(next)
					return fmt.Errorf("restrict journal directory permissions: %w", err)
				}
			}
		} else if (st.Uid != 0 && st.Uid != uint32(os.Geteuid()) && st.Mode&unix.S_ISVTX == 0) || st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			_ = unix.Close(next)
			return fmt.Errorf("journal ancestor %q is writable by an untrusted UID (uid=%d mode=%#o euid=%d)", part, st.Uid, st.Mode, os.Geteuid())
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil
}
