package vault

import "sync"

// MemoryVault is a test fixture only. It loses credentials on broker restart
// and must not be used as durable production storage. Production uses
// AegisKeys as the authoritative credential store.
type MemoryVault struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func NewMemoryVault() *MemoryVault {
	return &MemoryVault{
		secrets: make(map[string][]byte),
	}
}

func (m *MemoryVault) Store(key string, secret []byte) error {
	if key == "" || len(secret) == 0 {
		return ErrNotSupported
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	m.secrets[key] = cp
	return nil
}

func (m *MemoryVault) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.secrets[key]
	if !ok {
		return nil, ErrNotFound
	}
	res := make([]byte, len(s))
	copy(res, s)
	return res, nil
}

func (m *MemoryVault) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, key)
	return nil
}

func (m *MemoryVault) Name() string {
	return "memory-test-fixture"
}
