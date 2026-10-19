//go:build !linux

package main

import "fmt"

// disableCoreDumps is a no-op off Linux; the deployment must ensure
// ulimit -c 0 itself (documented in the broker startup warning path).
func disableCoreDumps() error {
	return fmt.Errorf("not supported on this platform")
}
