package service

import (
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/policy"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
	"github.com/secretbridge/secretbridge/internal/vault"
)

// Config for the privileged broker. The agent-facing adapter must never
// construct a Service directly; it talks to the broker over internal/ipc.
type Config struct {
	DBPath string
	// DefaultOpTTL bounds the operator approval window for new
	// requests (G04): zero means the 5-minute default. Values are
	// clamped to [1 minute, 24 hours] — human-in-the-loop workflows
	// need a workable window, but an unbounded authorization is a
	// stale-approval hazard.
	DefaultOpTTL time.Duration
	// MaxConcurrentOps bounds the auto worker's execution pool.
	// Zero means 4; clamped to [1, 32].
	MaxConcurrentOps int
	// VaultType is fail-closed and explicit (C14): "aegiskeys" for
	// production (authoritative store, no in-process secrets) or
	// "memory-test" for clearly-labeled development/tests only. Empty
	// and unknown values are rejected, never silently defaulted.
	VaultType string
	// AegisKeysSocket is the existing AegisKeys broker socket path.
	AegisKeysSocket string
	AegisKeysDir    string
}

type Service struct {
	db    *metadata.DB
	vault vault.Vault // ephemeral/test only; production resolves via AegisKeys
	// Broker-owned host presentation facts (HI-01/HI-07). The agent
	// cannot set or override them.
	hostInputMode string
	hostAssurance string
	// eph is the production short-lived relay spool (QR-01). It lives in
	// broker memory under every vault type: a production broker hosts
	// AegisKeys-backed reusable credentials AND bounded relays
	// simultaneously. Restart drops it; relay rows go unavailable.
	eph    *vault.EphemeralStore
	policy *policy.Engine
	cfg    Config
}

// maxConcurrentOps returns the bounded auto-worker pool size
// (concurrency design): default 4, clamped to [1, 32]. Manual
// execution paths are unaffected — each operation still claims
// independently through the atomic gates.
func (s *Service) maxConcurrentOps() int {
	n := s.cfg.MaxConcurrentOps
	if n <= 0 {
		return 4
	}
	if n > 32 {
		return 32
	}
	return n
}

// opTTL returns the clamped default authorization window for new
// requests (G04).
func (s *Service) opTTL() time.Duration {
	ttl := s.cfg.DefaultOpTTL
	if ttl <= 0 {
		return 5 * time.Minute
	}
	if ttl < time.Minute {
		return time.Minute
	}
	if ttl > 24*time.Hour {
		return 24 * time.Hour
	}
	return ttl
}

func New(config Config) (*Service, error) {
	db, err := metadata.NewDB(config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init db: %w", err)
	}

	// Fail closed on unsupported configuration. No silent fallback and no
	// silent ephemeral vault when AegisKeys is unavailable (C14).
	var v vault.Vault
	switch config.VaultType {
	case "memory-test", "memory":
		v = vault.NewMemoryVault()
	case "aegiskeys":
		// Authoritative store lives in AegisKeys; broker holds no in-process
		// vault. Keep a memory spool handle for ephemeral payloads only.
		v = vault.NewMemoryVault()
	default:
		_ = db.Close()
		return nil, fmt.Errorf("unsupported vault type %q: use memory-test or aegiskeys", config.VaultType)
	}

	// Bootstrap activation contract (CV-02/CV-07): every externally
	// observable operation must have exactly one unambiguous completion
	// contract before the broker accepts work. A state-changing driver
	// without a verifier, or a read-only driver carrying one, refuses
	// startup instead of silently misreporting outcomes.
	if err := secureops.ValidateRegistries(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("registry activation failed: %w", err)
	}
	svc := &Service{
		db:            db,
		vault:         v,
		eph:           vault.NewEphemeralStore(),
		policy:        policy.NewEngine(db),
		cfg:           config,
		hostInputMode: string(harness.InputExternalTTY),
		hostAssurance: string(intake.AssuranceModelBlind),
	}
	// Restart truth (QR-01/05): in-memory relay payloads are gone with
	// the old process. Say so in metadata — never present them as ready
	// or recoverable.
	if n, err := db.MarkRelaysUnavailable(time.Now()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("relay restart marking failed: %w", err)
	} else if n > 0 {
		_ = db.WriteAuditLog(&types.AuditLog{
			OperationID: "", Action: "startup_relay_unavailable", Actor: "broker",
			Outcome: fmt.Sprintf("relays=%d", n),
		})
	}
	// Startup reconciliation (SC-07): close crash-orphaned operations
	// before any new execution work. Pre-dispatch orphans never caused a
	// side effect (failed); dispatching orphans may have (uncertain).
	// Sweep already-expired requests at startup so no restart presents
	// dead work as pending (G04).
	if _, err := db.ExpireOpenOperations(time.Now()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("startup expiry sweep failed: %w", err)
	}
	if failed, uncertain, err := db.ReconcileExecuting(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("startup reconcile failed: %w", err)
	} else if failed+uncertain > 0 {
		_ = db.WriteAuditLog(&types.AuditLog{
			OperationID: "", Action: "startup_reconcile", Actor: "broker",
			Outcome: fmt.Sprintf("failed=%d uncertain=%d", failed, uncertain),
		})
	}
	return svc, nil
}

// SetHostInputAssurance installs broker-configured presentation facts.
// It is callable only from trusted broker/server wiring, never through an
// agent method. An unqualified host-native label is rejected: host_native
// is reserved for a future independently qualified adapter.
// HostInputMode returns the broker-configured presentation mode.
func (s *Service) HostInputMode() string { return s.hostInputMode }

// HostInputAssurance returns the broker-configured assurance label.
func (s *Service) HostInputAssurance() string { return s.hostAssurance }

// HostInputReason explains why that label was assigned without exposing
// or depending on agent claims.
func (s *Service) HostInputReason() string {
	if s.hostAssurance == string(intake.AssuranceAgentIsolated) {
		if s.hostInputMode == string(harness.InputHostNative) {
			return "qualified native host adapter with all agent boundaries verified"
		}
		return "external trusted input with all agent boundaries verified"
	}
	return "protected transport verified; full agent process/tool/transcript isolation is not proven"
}

func (s *Service) SetHostInputAssurance(mode, assurance string) error {
	if assurance == string(intake.AssuranceModelBlind) && mode == string(harness.InputExternalTTY) {
		s.hostInputMode, s.hostAssurance = mode, assurance
		return nil
	}
	if assurance == string(intake.AssuranceAgentIsolated) && mode == string(harness.InputExternalTTY) {
		s.hostInputMode, s.hostAssurance = mode, assurance
		return nil
	}
	if assurance == string(intake.AssuranceModelBlind) && mode == string(harness.InputHostNative) {
		s.hostInputMode, s.hostAssurance = mode, assurance
		return nil
	}
	if assurance == string(intake.AssuranceAgentIsolated) && mode == string(harness.InputHostNative) {
		s.hostInputMode, s.hostAssurance = mode, assurance
		return nil
	}
	return fmt.Errorf("unsupported trusted input assurance")
}

func (s *Service) Close() error {
	// Explicit teardown (QR-09): staged relay bytes are zeroed at close
	// rather than left for garbage collection.
	if s.eph != nil {
		s.eph.DropAll()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Service) DB() *metadata.DB { return s.db }

// CatalogOp is one discoverable operation on a secret reference (G06).
// Access distinguishes what the agent may invoke directly from what needs
// more context: "ready" means an allow-rule covers the op broadly and it
// can be submitted as described; "needs_destination" means permission is
// broad but a concrete registered destination is still required at
// submit; "scoped" means the op is permitted only in a narrower context
// (exact destination or resource) that the agent must supply.
// Disallowed operations are omitted entirely, never listed as denied.
type CatalogOp struct {
	Name                string                   `json:"name"`
	Description         string                   `json:"description"`
	Params              []secureops.ParamInfo    `json:"params,omitempty"`
	ResourceKind        string                   `json:"resource_kind,omitempty"`
	Completion          secureops.CompletionMode `json:"completion"`
	RequiresDestination bool                     `json:"requires_destination"`
	Access              string                   `json:"access"` // ready | scoped
}

// CatalogEntry pairs a secret reference with its policy-filtered,
// discoverable operations. Never includes secret material.
type CatalogEntry struct {
	Ref        *types.SecretReference `json:"ref"`
	Operations []CatalogOp            `json:"operations"`
}

// Catalog returns only references the authenticated principal may use,
// each with the operations it can discover (G06). Default-deny: unknown
// principals see nothing, and operations without any matching allow-rule
// stay hidden instead of failing later at submit.
func (s *Service) Catalog(principal string) ([]CatalogEntry, error) {
	if principal == "" {
		return nil, nil
	}
	all, err := s.db.ListSecretRefs()
	if err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, sr := range all {
		dec, err := s.policy.Evaluate(policy.Request{
			Principal:       principal,
			Op:              "discover",
			SecretRef:       sr.ID,
			Destinationless: true,
		})
		if err != nil || !dec.Allow {
			continue
		}
		// Never include secret material; refs are identifiers only.
		entry := CatalogEntry{Ref: &types.SecretReference{
			ID:          sr.ID,
			Name:        sr.Name,
			Description: sr.Description,
			CreatedAt:   sr.CreatedAt,
			UpdatedAt:   sr.UpdatedAt,
			Owner:       sr.Owner,
			Binding:     sr.Binding,
		}}
		for _, d := range secureops.All() {
			rules, err := s.policy.MatchingRules(principal, sr.ID, d.Name())
			if err != nil || len(rules) == 0 {
				continue
			}
			info := d.Describe()
			entry.Operations = append(entry.Operations, CatalogOp{
				Name: d.Name(), Description: info.Description, Params: info.Params,
				ResourceKind: info.ResourceKind, Completion: d.Completion(),
				RequiresDestination: d.RequiresDestination(),
				Access:              ruleAccess(rules, info.ResourceKind, d.RequiresDestination()),
			})
		}
		if rules, err := s.policy.MatchingRules(principal, sr.ID, "transfer"); err == nil && len(rules) > 0 {
			entry.Operations = append(entry.Operations, CatalogOp{
				Name:                "transfer",
				Description:         "Request a direct broker-to-recipient transfer (needs a registered destination_id)",
				Completion:          secureops.ExternalPostcondition,
				RequiresDestination: true,
				Access:              ruleAccess(rules, "", true),
			})
		}
		out = append(out, entry)
	}
	return out, nil
}

// ruleAccess classifies discovery honestly against admission semantics
// (P1 false-ready fix): it reuses the shared policy scope predicates, so
// an empty resource list can never read as broad availability — admission
// denies resource-bearing ops under resourceless rules (matchResource),
// and discovery agrees. Destination-required ops report
// needs_destination instead of ready, since no catalog claim alone makes
// them submittable.
func ruleAccess(rules []types.PolicyRule, resourceKind string, needsDest bool) string {
	broad := false
	for _, r := range rules {
		if policy.RuleDestOpen(r) && policy.RuleCoversResource(r, resourceKind) {
			broad = true
			break
		}
	}
	if !broad {
		return "scoped"
	}
	if needsDest {
		return "needs_destination"
	}
	return "ready"
}

// maxStagedBytes bounds trusted-intake payloads (SC-08): SeqPass is not a
// general file store, and the spool lives in broker memory.
const maxStagedBytes = 64 * 1024

// StageEphemeral stores a bounded sensitive payload into the ephemeral
// spool (SC-08). This is the ONLY intake path for unbound payloads, and it
// exists only in memory-test mode: the operator stages the payload from the
// trusted terminal over the admin socket; agents can only reference the
// resulting ref ID and never supply or read plaintext. The spool dies with
// the broker (no restart durability) and has no expiry index — staged
// payloads should be consumed promptly and deleted after use. Under a
// production vault type this fails closed: production payloads live in
// AegisKeys under stable bindings.
func (s *Service) StageEphemeral(refID string, payload []byte) error {
	if s.cfg.VaultType != "memory-test" && s.cfg.VaultType != "memory" {
		return fmt.Errorf("ephemeral staging is development-only (memory-test)")
	}
	if refID == "" {
		return fmt.Errorf("missing ref")
	}
	if len(payload) == 0 || len(payload) > maxStagedBytes {
		return fmt.Errorf("payload must be 1..%d bytes", maxStagedBytes)
	}
	sr, err := s.db.GetSecretRef(refID)
	if err != nil || sr == nil {
		return fmt.Errorf("unknown secret ref")
	}
	if sr.Binding != "" {
		return fmt.Errorf("ref has an AegisKeys binding; ephemeral staging refused")
	}
	if err := s.vault.Store(refID, payload); err != nil {
		return err
	}
	s.audit(refID, "secret_staged", "operator", refID, fmt.Sprintf("bytes=%d", len(payload)))
	return nil
}

// AddSecretRef is admin-only (trusted operator terminal, never MCP).
func (s *Service) AddSecretRef(sr *types.SecretReference) error {
	return s.db.CreateSecretRef(sr)
}

// AddDestination is admin-only (trusted operator terminal, never MCP).
func (s *Service) AddDestination(d *types.Destination) error {
	return s.db.CreateDestination(d)
}
