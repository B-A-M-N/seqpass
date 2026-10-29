//go:build !linux

package apptarget

import "fmt"

func lockConfig(string) (func(), error) {
	return nil, fmt.Errorf("application credential updates require Linux file locking")
}
