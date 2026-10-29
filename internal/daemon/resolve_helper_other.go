//go:build !linux

package daemon

import "fmt"

func validateResolveHelper(path, expectedSHA256 string, euid uint32) (string, error) {
	return "", fmt.Errorf("isolated AegisKeys resolve helpers require Linux filesystem identity checks")
}
