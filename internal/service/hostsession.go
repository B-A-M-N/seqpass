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
	now := time.Now()
	// S1: the human's authenticated intake principal never implicitly
	// authorizes the host's agent identity. A broker-provisioned binding
	// must resolve the exact agent principal, and a self-binding is refused.
	if hostPrincipal == humanPrincipal {
		return nil, nil, fmt.Errorf("host principal binding must use distinct identities")
	}
	binding, err := s.db.ResolveHostPrincipalBinding(humanPrincipal, string(reg.HostKind), now)
	if err != nil {
		return nil, nil, err
	}
	if binding == nil || binding.AgentPrincipal != hostPrincipal {
		s.audit("", "host_registration_denied", humanPrincipal, hostPrincipal, "unbound-agent")
		return nil, nil, fmt.Errorf("host is not authorized for this agent principal")
	}
	// S3/S7: qualify this exact registration against the broker's accepted
	// snapshot. Unqualified hosts fall back; they never inherit another
	// host's native assurance.
	decision, qualErr := s.SelectNativeModeForRegistration(reg.HostKind, reg.HostVersion, reg.AdapterVersion, reg.Topology, reg.SecurityConfig)
	if qualErr != nil {
		s.audit("", "host_registration_downgraded", hostPrincipal, humanPrincipal, "qualification-mismatch")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, nil, fmt.Errorf("session ID randomness unavailable: %w", err)
	}
	token, err := randomToken()
	if err != nil {
		return nil, nil, err
	}
	// SP-10: the session TTL must never outlive the underlying binding.
	sessionTTL := clampHostSessionTTL(reg.TTLOfSession)
	if time.Until(binding.ExpiresAt) < sessionTTL {
		sessionTTL = time.Until(binding.ExpiresAt)
	}
	expiresAt := now.Add(sessionTTL)
	h := &types.HostSession{
		ID:              "host-" + hex.EncodeToString(idBytes),
		HostKind:        string(reg.HostKind),
		AgentPrincipal:  hostPrincipal,
		HumanPrincipal:  humanPrincipal,
		ThreadID:        threadID,
		ExpiresAt:       expiresAt,
		InputMode:       string(decision.Mode),
		Assurance:       decision.Assurance,
		AssuranceReason: decision.Reason,
	}
	// SP-11: session and token are created in one transaction. A partial
	// write leaves neither record operational.
	tokenHash := hashSessionToken(token)
	if err := s.db.CreateHostSessionWithToken(h, tokenHash, expiresAt); err != nil {
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
	// SP-10: revalidate the underlying host principal binding on every
	// authentication. A revoked or expired binding must immediately lose
	// operational authority — not just prevent new registrations.
	binding, bindErr := s.db.ResolveHostPrincipalBinding(h.HumanPrincipal, h.HostKind, now)
	if bindErr != nil || binding == nil || binding.AgentPrincipal != h.AgentPrincipal {
		return nil, fmt.Errorf("host binding revoked or expired")
	}
	return h, nil
}

// SelectNativeModeForRegistration evaluates this exact registration against
// the broker-held qualification snapshot. It is per-session evidence, never
// shared Service state.
//
// For a verified isolated deployment the broker requires every
// agent-observable boundary property to be proven before inline native
// capture is offered (objective 4.3). The strict selector can only decline
// the stronger surface; it never widens what is offered and never upgrades
// assurance.
func (s *Service) SelectNativeModeForRegistration(hostKind harness.HostSessionKind, hostVersion, adapterVersion, topology string, securityConfig map[string]string) (harness.NativeModeDecision, error) {
	if s.cfg.RequireVerifiedHostIsolation {
		return harness.SelectNativeModeRequiringIsolation(s.hostQualification, hostKind, hostVersion, adapterVersion, topology, securityConfig, time.Now())
	}
	return harness.SelectNativeMode(s.hostQualification, hostKind, hostVersion, adapterVersion, topology, securityConfig, time.Now())
}

// BindRelayHost attaches an already authenticated relay to an already
// authenticated host session. Both records must belong to the same
// broker-authenticated agent principal; a forged thread ID adds no
// authorization.
func (s *Service) BindRelayHost(agent, relayID string, session *types.HostSession) error {
	if session == nil {
		return fmt.Errorf("missing host session")
	}
	return s.db.CreateRelayHostSession(relayID, session.ID, agent, time.Now())
}

// ListPendingRelaysForHostSession returns relays explicitly bound to the
// exact authenticated host session; there is no shared-principal fallback.
func (s *Service) ListPendingRelaysForHostSession(session *types.HostSession, limit int) ([]*types.RelayRecord, error) {
	if session == nil {
		return nil, fmt.Errorf("missing host session")
	}
	return s.db.ListPendingRelaysForHostSession(session.ID, limit)
}

var _ = metadata.DestDigest
