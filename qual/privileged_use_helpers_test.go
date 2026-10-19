//go:build linux

package qual

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// newSyntheticValue returns a random synthetic credential-like value. The
// value exists only in harness memory (and the root-owned mock vault
// file); retained evidence carries digests only.
func newSyntheticValue(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer clear(raw)
	return prefix + hex.EncodeToString(raw), nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func splitLines(text string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func countJSONLines(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return len(splitLines(string(raw))), nil
}

// containsAnyValue reports whether the haystack carries the needle
// literally or base64-encoded (the same dual-form scan the relay tier
// uses).
func containsAnyValue(haystack []byte, needles ...string) bool {
	for _, needle := range needles {
		if containsValue(haystack, []byte(needle)) {
			return true
		}
	}
	return false
}

// writeSyntheticVaultFile stages the credential in the root-owned mock
// vault file the AegisKeys mock loads, mirroring the protected backing file
// of a live deployment.
func writeSyntheticVaultFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(value)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// readSyntheticVaultFile returns the vault value (trusted harness only).
func readSyntheticVaultFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// dataField pulls one field out of a persisted receipt: the receipt JSON
// is the closed result DTO itself (result.Data marshaled), so fields sit
// at the top level.
func dataField(receipt map[string]interface{}, key string) interface{} {
	if receipt == nil {
		return nil
	}
	return receipt[key]
}

func itoa(v uint32) string {
	return fmt.Sprintf("%d", v)
}

func b64(v string) string {
	return base64.StdEncoding.EncodeToString([]byte(v))
}
