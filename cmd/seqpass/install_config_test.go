package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/config"
)

// The init-side install-config writer is the twin of the adapter writer and
// must honor the same security properties: identical content is a no-op, a
// differing file is never overwritten without --force, and the file is
// world-readable on purpose (every installation UID must resolve its
// endpoints) but carries no credential-bearing field.
func TestWriteInstallConfigSecurityProperties(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")

	d := config.Defaults()
	d.VaultType = config.VaultAegisKeys
	data, err := config.RenderConfig(d)
	if err != nil {
		t.Fatal(err)
	}

	// First write succeeds.
	if err := writeInstallConfigPath(target, data, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(data) {
		t.Fatalf("rendered config drifts from the written file:\n%s\nvs\n%s", first, data)
	}

	// Idempotent rewrite is a no-op.
	if err := writeInstallConfigPath(target, data, false); err != nil {
		t.Fatalf("idempotent rewrite refused: %v", err)
	}
	second, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(data) {
		t.Fatal("idempotent rewrite changed the file")
	}

	// A differing file is refused without --force, and stays untouched.
	d2 := d
	d2.DBPath = filepath.Join(dir, "other.db")
	data2, err := config.RenderConfig(d2)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeInstallConfigPath(target, data2, false); err == nil {
		t.Fatal("writeInstallConfig overwrote a differing config without --force")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatal("refused rewrite still modified the file")
	}

	// --force replaces it.
	if err := writeInstallConfigPath(target, data2, true); err != nil {
		t.Fatalf("--force refused to overwrite: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data2) {
		t.Fatal("--force did not write the new config")
	}

	// World-readable by design, but never writable by others, and never
	// carrying a credential-bearing word.
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Fatalf("install config mode = %v, want 0644 (all installation UIDs must read endpoints)", fi.Mode().Perm())
	}
	lower := strings.ToLower(string(got))
	for _, forbidden := range []string{"password", "secret_value", "api_key", "\"token\"", "credential"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("install config carries a credential-bearing field %q:\n%s", forbidden, got)
		}
	}
}
