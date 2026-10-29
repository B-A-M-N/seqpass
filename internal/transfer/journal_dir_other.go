//go:build !linux

package transfer

import (
	"fmt"
	"os"
)

func ensureOperationJournalDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("journal directory must be a private directory")
	}
	return nil
}
