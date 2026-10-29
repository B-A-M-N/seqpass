//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// validateResolveHelper resolves the operator-configured helper to its
// canonical path and verifies its content identity and filesystem trust
// before the broker accepts work. AegisKeys independently checks the live
// helper's path and hash against its executable grant on every resolve.
func validateResolveHelper(path, expectedSHA256 string, euid uint32) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("helper path is required")
	}
	if len(expectedSHA256) != sha256.Size*2 {
		return "", fmt.Errorf("helper SHA-256 pin must be 64 hexadecimal characters")
	}
	want, err := hex.DecodeString(expectedSHA256)
	if err != nil {
		return "", fmt.Errorf("invalid helper SHA-256 pin: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve helper path: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", fmt.Errorf("make helper path absolute: %w", err)
	}
	fi, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect helper: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("helper must be a regular executable file")
	}
	if fi.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("helper must not be group- or world-writable")
	}
	if err := validateTrustedPathOwners(canonical, euid); err != nil {
		return "", err
	}
	f, err := os.Open(canonical)
	if err != nil {
		return "", fmt.Errorf("open helper: %w", err)
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", fmt.Errorf("hash helper: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close helper after hashing: %w", closeErr)
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), hex.EncodeToString(want)) {
		return "", fmt.Errorf("helper SHA-256 does not match configured pin")
	}
	return canonical, nil
}

func validateTrustedPathOwners(path string, euid uint32) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		fi, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("inspect helper directory %s: %w", dir, err)
		}
		if fi.Mode().Perm()&0022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("helper directory %s must not be group- or world-writable", dir)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != euid) {
			return fmt.Errorf("helper directory %s must be owned by root or the broker UID", dir)
		}
		if dir == string(filepath.Separator) {
			break
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect helper owner: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != euid) {
		return fmt.Errorf("helper must be owned by root or the broker UID")
	}
	return nil
}
