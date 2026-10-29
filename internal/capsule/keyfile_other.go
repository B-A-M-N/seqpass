//go:build !linux

package capsule

import (
	"fmt"
	"os"
)

func validateKeyParent(string) error {
	return fmt.Errorf("recipient key files require Linux ownership checks")
}
func validatePrivateKeyFile(string) error {
	return fmt.Errorf("recipient key files require Linux ownership checks")
}
func openPrivateKeyFile(string) (*os.File, error) {
	return nil, fmt.Errorf("recipient key files require Linux no-follow opens")
}
