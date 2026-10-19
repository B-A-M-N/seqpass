//go:build !linux

package secureops

// applyGitLimits is a no-op on non-Linux platforms; SeqPass does not
// claim resource-limit protection it does not enforce. The git profile's
// other guarantees (fixed environment, descriptor-only credential,
// projected output, hard timeout in a killed process group) are
// platform-independent.
func applyGitLimits(pid int) {}
