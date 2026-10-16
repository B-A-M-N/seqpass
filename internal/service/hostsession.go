package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/types"
)

// Host session bounds (HI-02): long enough for a real workflow, short
// enough to stop stale native adapters from presenting old requests.
const (
	minHostSessionTTL = time.Minute
	maxHostSessionTTL = 8 * time.Hour
)

func clampHostSessionTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return time.Hour
	}
	if ttl < minHostSessionTTL {
		return minHostSessionTTL
	}
	if ttl > maxHostSessionTTL {
		return maxHostSessionTTL
	}
	return ttl
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session token randomness unavailable: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validHostKind(kind harness.HostSessionKind) bool {
	switch kind {
	case harness.HostKindGeneric, harness.HostKindHermes,
		harness.HostKindCodex, harness.HostKindClaude,
		harness.HostKindOpenCode, harness.HostKindPi,
		harness.HostKindJCode, harness.HostKindQwen,
		harness.HostKindAgy:
		return true
	default:
		return false
	}
}

// RegisterHostSession authenticates a native-host adapter through the
// broker's protected IPC domain. The caller supplies only harness type,
// thread correlation, and the human authenticated on that connection.
// The broker assigns both principals, mints the token, and stores only
// its hash.
func (s *Service) RegisterHostSession(hostPrincipal, humanPrincipal string, reg harness.HostRegistration) (*types.HostSession, *harness.HostSessionToken, error) {
	if hostPrincipal == "" || humanPrincipal == "" {
		return nil, nil, fmt.Errorf("missing host or human principal")
	}
	if !validHostKind(reg.HostKind) {
		return nil, nil, fmt.Errorf("unknown host kind")
	}
	threadID := strings.TrimSpace(reg.ThreadID)
	if len(threadID) > 256 {
		return nil, nil, fmt.Errorf("thread ID too long")
	}
	for _, r := range threadID {
		if r < 32 || r == 127 {
			return nil, nil, fmt.Errorf("thread ID contains control characters")
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, nil, fmt.Errorf("session ID randomness unavailable: %w", err)
	}
	token, err := randomToken()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	expiresAt := now.Add(clampHostSessionTTL(reg.TTLOfSession))
	h := &types.HostSession{
		ID:             "host-" + hex.EncodeToString(idBytes),
		HostKind:       string(reg.HostKind),
		AgentPrincipal: hostPrincipal,
		HumanPrincipal: humanPrincipal,
		ThreadID:       threadID,
		ExpiresAt:      expiresAt,
	}
	if err := s.db.CreateHostSession(h); err != nil {
		return nil, nil, err
	}
	tokenHash := hashSessionToken(token)
	if err := s.db.CreateHostSessionToken(h.ID, tokenHash, expiresAt); err != nil {
		return nil, nil, err
	}
	s.audit(h.ID, "host_session_registered", hostPrincipal, humanPrincipal, string(reg.HostKind))
	caps := harness.NegotiatedCapabilities(reg.Credentials)
	return h, &harness.HostSessionToken{
		SessionID:   h.ID,
		Token:       token,
		ExpiresAt:   expiresAt,
		Credentials: caps,
	}, nil
}

// HostSessionAuth validates a broker-held session token using constant
// time comparison and returns the associated broker session.
func (s *Service) HostSessionAuth(sessionID, token string) (*types.HostSession, error) {
	if sessionID == "" || token == "" {
		return nil, fmt.Errorf("missing host session or token")
	}
	stored, expiresAt, err := s.db.HostSessionTokenFor(sessionID)
	if err != nil {
		return nil, fmt.Errorf("host session token invalid")
	}
	now := time.Now()
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hashSessionToken(token))) != 1 ||
		!now.Before(expiresAt) {
		return nil, fmt.Errorf("host session token invalid")
	}
	h, err := s.db.GetHostSession(sessionID)
	if err != nil || h == nil || !now.Before(h.ExpiresAt) {
		return nil, fmt.Errorf("host session invalid or expired")
	}
	return h, nil
}

// BindRelayHost attaches an already authenticated relay to an already
// authenticated host session. Both records must belong to the same
// broker-authenticated agent principal; a forged thread ID adds no
// authorization.
func (s *Service) BindRelayHost(agent, relayID string, session *types.HostSession) error {
	if session == nil {
		return fmt.Errorf("missing host session")
	}
	return s.db.BindRelayToHostSession(relayID, session.ID, agent)
}

var _ = metadata.DestDigest
