package vault

import "errors"

var (
	ErrNotFound     = errors.New("secret not found")
	ErrNotSupported = errors.New("operation not supported")
)

// Vault is a trusted-executor-only credential source.
// It must never be linked into agent-facing response paths and must never
// be exposed over MCP or agent IPC. Production uses AegisKeys via
// internal/aegiskeys; the in-process Vault exists only for the broker's
// ephemeral/test path.
type Vault interface {
	// Store stages a secret. Production provisioning happens in AegisKeys;
	// this is retained for tests and the ephemeral transfer spool.
	Store(key string, secret []byte) error
	// Get resolves plaintext. Trusted executor only.
	Get(key string) ([]byte, error)
	Delete(key string) error
	Name() string
}
