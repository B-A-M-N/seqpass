package apptarget

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validatePath(path string, missingLeafOK bool) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("application config path must be absolute")
	}
	clean := filepath.Clean(path)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	cur := string(filepath.Separator)
	for i, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if missingLeafOK {
				continue
			}
			return fmt.Errorf("application config path component is missing")
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("application config path contains a symlink")
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return fmt.Errorf("application config parent is not a directory")
			}
			if err := validateDirectory(info); err != nil {
				return fmt.Errorf("%s: %w", cur, err)
			}
		}
	}
	if info, err := os.Lstat(clean); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("application credential file must be regular and owner-only")
		}
		if err := validateFileOwner(info); err != nil {
			return err
		}
	} else if !missingLeafOK || !os.IsNotExist(err) {
		return err
	}
	return nil
}

func atomicPrivateWrite(path string, data []byte) error {
	if err := validatePath(path, true); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := validatePath(filepath.Join(dir, ".seqpass-path-check"), true); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".seqpass-credential-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
