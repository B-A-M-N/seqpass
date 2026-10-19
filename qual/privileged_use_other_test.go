//go:build !linux

package qual

import "testing"

func runPrivilegedSyntheticUse(t *testing.T, h *harness) (bool, string) {
	t.Helper()
	return false, "the synthetic credential tier is implemented only for Linux"
}
