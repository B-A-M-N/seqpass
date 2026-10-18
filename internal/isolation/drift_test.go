package isolation

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// An unchanged boundary reports no drift.
func TestFingerprintNoDrift(t *testing.T) {
	dir := mkPublicTempDir(t)
	sock := filepath.Join(dir, "s.sock")
	listenUnix(t, sock)
	fp := CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock})
	if drift := fp.Drift(CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock})); len(drift) != 0 {
		t.Fatalf("stable boundary reported drift: %v", drift)
	}
}

// A permission change on a protected socket is drift.
func TestFingerprintDetectsPermissionDrift(t *testing.T) {
	dir := mkPublicTempDir(t)
	sock := filepath.Join(dir, "s.sock")
	listenUnix(t, sock)
	before := CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock})
	if err := os.Chmod(sock, 0640); err != nil {
		t.Fatal(err)
	}
	drift := before.Drift(CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock}))
	if len(drift) == 0 {
		t.Fatal("permission change not detected")
	}
}

// A vanished protected socket is drift, never a silent downgrade.
func TestFingerprintDetectsMissingSocket(t *testing.T) {
	dir := mkPublicTempDir(t)
	sock := filepath.Join(dir, "s.sock")
	listenUnix(t, sock)
	before := CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock})
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	drift := before.Drift(CaptureFingerprint(uint32(os.Geteuid()), uint32(os.Getegid()), []string{sock}))
	if len(drift) == 0 {
		t.Fatal("missing protected socket not detected")
	}
}

// A changed effective identity is drift.
func TestFingerprintDetectsIdentityDrift(t *testing.T) {
	dir := mkPublicTempDir(t)
	before := CaptureFingerprint(1000, 1000, []string{filepath.Join(dir, "absent")})
	drift := before.Drift(CaptureFingerprint(1001, 1000, []string{filepath.Join(dir, "absent")}))
	if len(drift) == 0 {
		t.Fatal("effective uid change not detected")
	}
}
