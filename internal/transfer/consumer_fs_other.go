//go:build !linux

package transfer

import "fmt"

func openSecureCommitDir(string) (int, string, uint64, uint64, error) {
	return -1, "", 0, 0, fmt.Errorf("file credential consumer requires Linux descriptor-relative filesystem support")
}
func closeCommitDir(int) {}
func writeCommitFileAt(int, string, []byte) (bool, error) {
	return false, fmt.Errorf("unsupported platform")
}
func readCommitFileAt(int, string, int) ([]byte, error) {
	return nil, fmt.Errorf("unsupported platform")
}
