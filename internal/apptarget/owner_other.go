//go:build !linux

package apptarget

import (
	"fmt"
	"os"
)

func validateDirectory(os.FileInfo) error {
	return fmt.Errorf("application credential updates require Linux owner checks")
}
func validateFileOwner(os.FileInfo) error {
	return fmt.Errorf("application credential updates require Linux owner checks")
}
