package transfer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileCommitterRejectsUnsafeDirectories(t *testing.T) {
	root := t.TempDir()
	insecure := filepath.Join(root, "insecure")
	if err := os.Mkdir(insecure, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCommitter(insecure); err == nil || !strings.Contains(err.Error(), "group or other access") {
		t.Fatalf("permissive destination directory = %v, want refusal", err)
	}

	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCommitter(alias); err == nil {
		t.Fatal("symlink destination accepted")
	}

	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(parent, "child")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCommitter(filepath.Join(parent, "child", "nested")); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestFileCommitterNoOverwriteAndIdempotentRetry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	committer, err := NewFileCommitter(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first := Delivery{OperationID: "op-file-1", DataKind: "api_key", Payload: []byte("synthetic-key-one")}
	got, err := committer.Commit(ctx, first)
	if err != nil || !got.Applied {
		t.Fatalf("first commit = %+v, %v", got, err)
	}
	got, err = committer.Commit(ctx, first)
	if err != nil || !got.Applied || got.Digest != PayloadDigest(first.Payload) {
		t.Fatalf("identical retry = %+v, %v", got, err)
	}
	conflict := Delivery{OperationID: first.OperationID, DataKind: "api_key", Payload: []byte("different-key-two")}
	if _, err := committer.Commit(ctx, conflict); err == nil {
		t.Fatal("different payload replaced an existing operation file")
	}
	stored, err := os.ReadFile(filepath.Join(dir, first.OperationID+".secret"))
	if err != nil || string(stored) != string(first.Payload) {
		t.Fatalf("stored bytes changed after conflict: %q, %v", stored, err)
	}
}

func TestFileCommitterDetectsDestinationReplacement(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "credentials")
	committer, err := NewFileCommitter(dir)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "original")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := Delivery{OperationID: "op-replaced", DataKind: "api_key", Payload: []byte("synthetic-key")}
	if _, err := committer.Commit(context.Background(), d); err == nil || !strings.Contains(err.Error(), "changed after initialization") {
		t.Fatalf("replaced destination = %v, want identity refusal", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement directory received credential files: %v", entries)
	}
}
