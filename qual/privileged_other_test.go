//go:build !linux

package qual

import "testing"

func runPrivilegedBoundary(t *testing.T, h *harness) (bool, string) {
	t.Helper()
	return false, "the process-boundary runner is implemented only for Linux"
}
