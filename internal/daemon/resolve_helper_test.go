//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolatedProductionRequiresResolveHelper(t *testing.T) {
	_, err := New(Config{
		DBPath:        filepath.Join(t.TempDir(), "broker.db"),
		SocketPath:    filepath.Join(t.TempDir(), "broker.sock"),
		VaultType:     "aegiskeys",
		AssuranceMode: AssuranceIsolated,
	})
	if err == nil || !strings.Contains(err.Error(), "requires --aegiskeys-resolve-helper") {
		t.Fatalf("isolated production without helper = %v, want actionable helper requirement", err)
	}
}

func TestValidateResolveHelperRejectsInvalidIdentityAndPermissions(t *testing.T) {
	dir, err := os.MkdirTemp("", ".resolve-helper-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "helper")
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("trusted helper fixture")
	if err := os.WriteFile(path, content, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	pin := hex.EncodeToString(sum[:])

	got, err := validateResolveHelper(path, pin, uint32(os.Geteuid()))
	if err != nil || got != path {
		t.Fatalf("valid helper = %q, %v", got, err)
	}
	if _, err := validateResolveHelper(filepath.Join(dir, "missing"), pin, uint32(os.Geteuid())); err == nil {
		t.Fatal("missing helper accepted")
	}
	if _, err := validateResolveHelper(path, "not-a-sha256", uint32(os.Geteuid())); err == nil {
		t.Fatal("malformed identity pin accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateResolveHelper(path, pin, uint32(os.Geteuid())); err == nil {
		t.Fatal("non-executable helper accepted")
	}
	if err := os.WriteFile(path, []byte("replacement helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := validateResolveHelper(path, pin, uint32(os.Geteuid())); err == nil {
		t.Fatal("replaced helper accepted with stale identity pin")
	}
}
