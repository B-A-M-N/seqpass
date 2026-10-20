package types

import (
	"errors"
	"time"
)

// SecretReference is an identifier for a secret; agents never receive the actual secret.
// SecretRef IDs map to AegisKeys bindings in production (see SecretSource).
type SecretReference struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Owner       string    `json:"owner"`
	// Binding is the authoritative AegisKeys binding, if sourced from AegisKeys.
	Binding string `json:"binding,omitempty"`
	// P0-3 trusted-intake provisioning state (all durable references; no
	// credential bytes ever live in this database):
	// ProvisionRequestID is the durable idempotency anchor shared with the
	// provider — retries and reconciliation key on it; RecordID/BindingID
	// are the provider's stable identities (the binding ID protects a
	// later rebind of the binding NAME from silently redirecting an
	// approved operation); ReconcileStatus is the lifecycle marker
	// ('' = plain ref, or one of the ProvisionReconcile* values).
	ProvisionRequestID string `json:"provision_request_id,omitempty"`
	RecordID           string `json:"record_id,omitempty"`
	BindingID          string `json:"binding_id,omitempty"`
	ReconcileStatus    string `json:"reconcile_status,omitempty"`
	// UseOnce marks a use-once intake reference: consumed (failed closed)
	// after its first successful execution.
	UseOnce bool `json:"use_once,omitempty"`
	// RequestCommitment (P0-D) is the KEYED commitment (HMAC-SHA256 under
	// a broker-local secret in broker_state) over the FULL canonical
	// request identity: principal, mode, service, kind, label, binding,
	// canonical operation allowlist, expiry, description, env hint,
	// resolver grant — and the credential VALUE itself. It lets any later
	// retry under the same request ID prove the request is byte-identical
	// WITHOUT persisting plaintext or an unkeyed (dictionary-attackable)
	// hash of the secret. Empty on plain (non-provisioned) references.
	RequestCommitment string `json:"request_commitment,omitempty"`
}

// ProvisionUseIntent is the durable continuation record for a
// save_and_use intake: the intended operation (destination, parameters,
// principal, request identity) REVIEWED AT SAVE TIME, persisted before any
// approval exists. It carries NO authorization: the recorded workflow only
// becomes an ordinary pending use REQUEST through the continuation, which
// still needs the operator's independent approval before execution.
// Intent states: pending (recorded, grant not yet usable) → submitted (a
// durable use request exists; op_id set) → completed/failed (the op's
// terminal state) / blocked (reference conflicted or revoked pre-dispatch).
type ProvisionUseIntent struct {
	ID                 string            `json:"id"`
	ProvisionRequestID string            `json:"provision_request_id"`
	RefID              string            `json:"ref_id"`
	Principal          string            `json:"principal"`
	Operation          string            `json:"operation"`
	Target             string            `json:"target,omitempty"`
	Params             map[string]string `json:"params,omitempty"`
	OpID               string            `json:"op_id,omitempty"`
	State              string            `json:"state"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// ProvisionUseIntent* are the durable intent lifecycle states.
const (
	ProvisionUseIntentPending   = "pending"
	ProvisionUseIntentSubmitted = "submitted"
	ProvisionUseIntentCompleted = "completed"
	ProvisionUseIntentFailed    = "failed"
	ProvisionUseIntentBlocked   = "blocked"
)

// ProvisionReconcile* are the durable reconcile statuses of a provisioned
// secret reference ('uncertain' = the provider may have committed; retry
// the SAME provision request ID to reconcile, per the exactly-once
// contract).
const (
	ProvisionReconcilePending   = "pending"   // write-ahead record before the provider call
	ProvisionReconcileUncertain = "uncertain" // exchange lost mid-commit; reconcile by request ID
	ProvisionReconcileConflict  = "conflict"  // durable identity exists with different content
	ProvisionReconcileCommitted = "committed" // provider committed; authorization pending
	ProvisionReconcileReady     = "ready"     // provider reports the credential resolvable
	// ProvisionReconcileGrantPresent (P1-A): the resolve grant EXISTS at
	// the provider, but no unlocked/policy-valid/executable-pin-valid
	// readiness verdict has been reported. Distinct from ready — surfaces
	// must not present grant_present as executable readiness.
	ProvisionReconcileGrantPresent = "grant_present"
	ProvisionReconcileConsumed     = "consumed" // use-once reference executed
	ProvisionReconcileFailed       = "failed"   // provider refused (access_denied/invalid)
	// ProvisionReconcileIdentityConflict: a committed reference's stable
	// provider identity (record/binding ID) DIVERGED at the provider —
	// rebind, rotation, corrupted metadata, or an altered replay. The
	// ORIGINAL pins are preserved (never overwritten with the provider's
	// new identity); every subsequent use fails closed until an explicit
	// operator-authorized reconciliation resolves the divergence.
	ProvisionReconcileIdentityConflict = "identity_conflict"
	// ProvisionReconcileTransient (P0-C): a GENUINELY TRANSIENT use-once
	// intake. The credential lives ONLY in the broker's in-memory
	// ephemeral spool under its bounded lifetime — NO durable AegisKeys
	// credential exists, and the payload is unrecoverable after expiry
	// or restart (the reference row is metadata only). Distinct from the
	// persisted single-use contract (use_once), where AegisKeys
	// deliberately retains the encrypted credential and SeqPass limits
	// its use to one authorized execution.
	ProvisionReconcileTransient = "transient"
)

// SourceKind distinguishes credential sources.
type SourceKind string

const (
	SourceAegisKeys SourceKind = "aegiskeys"
	SourceEphemeral SourceKind = "ephemeral"
)

// SecretSource describes where a secret comes from without carrying plaintext.
type SecretSource struct {
	Kind    SourceKind `json:"kind"`
	Binding string     `json:"binding,omitempty"`
	Ref     string     `json:"ref,omitempty"`
	// Stable identity pins (P0-3 rebind protection): attached by
	// resolveSource from the SecretReference's provisioned identity. The
	// provider denies generically when a pin no longer matches, so a
	// rebind of the binding NAME cannot silently redirect an approved
	// operation. Empty pins = pre-P0-3 refs (unpinned resolves).
	BindingID string `json:"binding_id,omitempty"`
	RecordID  string `json:"record_id,omitempty"`
	// UseOnce marks a use-once provisioned reference: the execution path
	// consumes it exactly-once at dispatch (guarded UPDATE, concurrent
	// second dispatch fails closed).
	UseOnce bool `json:"use_once,omitempty"`
}

// Destination represents a registered trusted recipient.
// Agents select registered destination IDs, never arbitrary URLs/paths.
type Destination struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"` // file, http-pinned, ssh-pinned, etc.
	Endpoint         string    `json:"endpoint"`
	AuthMethod       string    `json:"auth_method"`
	AllowedOps       []string  `json:"allowed_ops"`
	RequiresApproval bool      `json:"requires_approval"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	ApprovedBy       string    `json:"approved_by,omitempty"`
	// Revision invalidates approvals bound to an older destination config.
	Revision int `json:"revision"`
	// ExpectedUID/GID pin the recipient process identity (C05). Nil means
	// unconfigured, and delivery fails closed: the operator must name the
	// exact recipient UID (and optionally GID) at registration.
	ExpectedUID *uint32 `json:"expected_uid,omitempty"`
	ExpectedGID *uint32 `json:"expected_gid,omitempty"`
	// SourceRepo pins the content source for the git.push profile: an
	// absolute, operator-registered repository path. The agent cannot
	// name or alter it — pushed content is a registration fact, like the
	// remote. Empty for fetch-only destinations.
	SourceRepo string `json:"source_repo,omitempty"`
}

// Operation lifecycle states.
const (
	StatusRequested       = "requested"
	StatusPendingApproval = "pending_approval"
	StatusAuthorized      = "authorized"
	StatusClaimed         = "claimed"
	StatusExecuting       = "executing"
	// StatusDispatching marks the atomic dispatch barrier (SC-03): the
	// commit of this transition is the defined point authorizing external
	// I/O. Revocation committed before it prevents dispatch; revocation
	// after it meets an in-flight operation that cannot be undone.
	StatusDispatching = "dispatching"
	StatusCompleted   = "completed"
	StatusFailed      = "failed"
	StatusUncertain   = "uncertain"
	StatusRejected    = "rejected"
	StatusExpired     = "expired"
	StatusCancelled   = "cancelled"
)

// AuditLog records metadata only (no plaintext payloads).
type AuditLog struct {
	ID          string    `json:"id"`
	OperationID string    `json:"operation_id"`
	Action      string    `json:"action"`
	Actor       string    `json:"actor"`
	Target      string    `json:"target"`
	Outcome     string    `json:"outcome"`
	Metadata    string    `json:"metadata"` // JSON metadata, no secrets
	CreatedAt   time.Time `json:"created_at"`
}

// Policy defines authorization rules. Default-deny: no matching allow = denial.
type Policy struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Rules     []PolicyRule `json:"rules"`
	Priority  int          `json:"priority"`
	Enabled   bool         `json:"enabled"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	// Revision invalidates approvals bound to an older policy.
	Revision int `json:"revision"`
}

// ResourceDescriptor binds credential permission to the exact resource
// (C10): authorizing an operation for one resource must not open every
// resource the credential can read.
type ResourceDescriptor struct {
	Kind       string `json:"kind"`
	Identifier string `json:"identifier"`
}

// PolicyRule defines a single allow rule. Conditions are not supported and
// cause creation to fail: silently ignored restrictions are a grant-expansion
// hazard (C06). Principal, SecretRefs and Ops must be explicit (use "*"
// for wildcard); empty values are rejected at creation.
//
// NoApproval opts explicitly into preauthorized execution (SC-05): matching
// operations become authorized at submit without human approval and are
// consumed by the trusted worker through the normal claim path. Absent
// means human approval is required. A destination with RequiresApproval
// set always forces human approval (escalation only, never de-escalation).
//
// Approval-mode precedence (P2-9, conservative combination): an operation
// preauthorizes only when EVERY applicable rule sets NoApproval. Any
// applicable rule without it forces human approval, regardless of rule
// order or policy priority — a broad preauthorization grant can never
// silently bypass a narrower mandatory-review rule.
//
// Resources entries are "kind:identifier" (e.g. "github.repository:o/r"),
// "kind/*", or "*"; bare identifiers are rejected so one kind's scope can
// never silently match another kind (SC-10).
type PolicyRule struct {
	Principal  string            `json:"principal"`
	SecretRefs []string          `json:"secret_refs"`
	Ops        []string          `json:"ops"`
	DestIDs    []string          `json:"dest_ids"`
	Resources  []string          `json:"resources,omitempty"`
	NoApproval bool              `json:"no_approval,omitempty"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

func errPolicy(msg string) error {
	return errors.New(msg)
}

// ValidateRule rejects policies that would be silently overbroad (C06):
// nonempty conditions (unenforced), or empty principal/secret/op lists
// (implicit wildcards). Callers must write explicit "*" wildcards.
// Lives in types to avoid a policy<->metadata import cycle.
func ValidateRule(r PolicyRule) error {
	if len(r.Conditions) > 0 {
		return errPolicy("policy conditions are not supported")
	}
	if r.Principal == "" {
		return errPolicy("policy principal must be explicit")
	}
	if len(r.SecretRefs) == 0 {
		return errPolicy("policy secret_refs must be explicit")
	}
	if len(r.Ops) == 0 {
		return errPolicy("policy ops must be explicit")
	}
	for _, res := range r.Resources {
		if res == "*" {
			continue
		}
		kind, id, ok := splitResource(res)
		if !ok || kind == "" || id == "" {
			return errPolicy("policy resource must be \"*\", \"kind/*\", or \"kind:identifier\"")
		}
		_ = id
	}
	return nil
}

func splitResource(res string) (kind, id string, ok bool) {
	for i := 0; i < len(res); i++ {
		if res[i] == ':' {
			return res[:i], res[i+1:], true
		}
	}
	return "", "", false
}

// ParseResource splits a "kind:identifier" entry for the policy engine.
func ParseResource(res string) (kind, id string, ok bool) {
	return splitResource(res)
}

// TransferRequest for blind sensitive-data transfer.
type TransferRequest struct {
	ID            string       `json:"id"`
	SecretRef     string       `json:"secret_ref"`
	Source        SecretSource `json:"source"`
	DestinationID string       `json:"destination_id"`
	PayloadRef    string       `json:"payload_ref"`
	ExpiresAt     time.Time    `json:"expires_at"`
	Status        string       `json:"status"`
	RequestedBy   string       `json:"requested_by"`
	ApprovedBy    string       `json:"approved_by,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
	CompletedAt   *time.Time   `json:"completed_at,omitempty"`
	// Revision + bindings for atomic claim and approval invalidation.
	Revision     int    `json:"revision"`
	AuthEpoch    int64  `json:"auth_epoch"`
	DestDigest   string `json:"dest_digest"`
	DestRevision int    `json:"dest_revision"`
	OpHash       string `json:"op_hash"`
}

// Relay lifecycle states (QR-03/SP-TUI-03). Awaiting_user is the only
// state that can accept a payload; ready/authorized gate dispatch;
// delivered/uncertain/rejected/expired/cancelled/unavailable are terminal
// for new work (uncertain still reconciles against the original
// recipient, never a second delivery).
const (
	RelayAwaitingUser = "awaiting_user"
	RelayReady        = "ready"
	RelayAuthorized   = "authorized"
	RelayReserved     = "reserved"
	RelayDispatching  = "dispatching"
	RelayDelivered    = "delivered"
	RelayUncertain    = "uncertain"
	RelayRejected     = "rejected"
	RelayExpired      = "expired"
	RelayCancelled    = "cancelled"
	RelayUnavailable  = "unavailable"
)

// Relay consumption policies (QR-05): per-reference behavior, not one
// global mode. SingleDispatch (the default) lets exactly one operation
// reserve and dispatch; BoundedUses allows N independently authorized
// operations (e.g. a shared key for several apps); ReusableUntilExpiry
// permits concurrent authorized use until deadline or revocation.
const (
	RelaySingleDispatch = "single_dispatch"
	RelayBoundedUses    = "bounded_uses"
	RelayReusable       = "reusable_until_expiry"
)

// RelayRecord is the broker-side authorization envelope for one
// short-lived handoff (QR-04). It binds the exact agent, recipient
// (+ its configuration revision at approval), purpose, deadline and
// consumption budget. The relay ID is an unpredictable locator —
// possession alone authorizes nothing; every transition revalidates
// the envelope against the caller's authenticated identity.
// No plaintext lives here or in any relay table row (QR-01).
type RelayRecord struct {
	ID             string    `json:"id"`
	AgentPrincipal string    `json:"agent_principal"`
	IntakeOwner    string    `json:"intake_owner,omitempty"`
	DestinationID  string    `json:"destination_id"`
	DestRevision   int       `json:"dest_revision"`
	DestDigest     string    `json:"dest_digest"`
	DataKind       string    `json:"data_kind"`
	Purpose        string    `json:"purpose,omitempty"`
	State          string    `json:"state"`
	Consumption    string    `json:"consumption"`
	MaxDeliveries  uint32    `json:"max_deliveries"`
	UsedDeliveries uint32    `json:"used_deliveries"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revision       uint64    `json:"revision"`
	OpID           string    `json:"op_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// HostSession is the broker-issued binding for a native host integration
// (HI-02). It identifies the harness instance/workflow and the two
// principals authenticated by the broker. It carries no credential or
// agent-asserted security claim.
type HostSession struct {
	ID              string    `json:"id"`
	HostKind        string    `json:"host_kind"`
	AgentPrincipal  string    `json:"agent_principal"`
	HumanPrincipal  string    `json:"human_principal"`
	ThreadID        string    `json:"thread_id,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	Revision        uint64    `json:"revision"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	InputMode       string    `json:"input_mode"`
	Assurance       string    `json:"input_assurance"`
	AssuranceReason string    `json:"input_reason"`
}

// HostPrincipalBinding is the broker-authorized association between a
// trusted human intake identity and an approved agent identity. Neither
// side can create it by supplying an identity claim; it is explicitly
// provisioned by the broker operator and version-guarded.
type HostPrincipalBinding struct {
	HumanPrincipal string    `json:"human_principal"`
	AgentPrincipal string    `json:"agent_principal"`
	HostKind       string    `json:"host_kind"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revision       uint64    `json:"revision"`
}

// RelayHostSession is the exact association between one relay and one
// broker-issued native host session. It is created when a trusted host
// claims the relay and never inferred from a shared principal.
type RelayHostSession struct {
	RelayID        string    `json:"relay_id"`
	SessionID      string    `json:"session_id"`
	AgentPrincipal string    `json:"agent_principal"`
	HumanPrincipal string    `json:"human_principal"`
	HostKind       string    `json:"host_kind"`
	CreatedAt      time.Time `json:"created_at"`
}

// UseRequest for credential-backed operation.
type UseRequest struct {
	ID           string            `json:"id"`
	SecretRef    string            `json:"secret_ref"`
	Source       SecretSource      `json:"source"`
	Operation    string            `json:"operation"`
	Target       string            `json:"target"`
	Params       map[string]string `json:"params"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Status       string            `json:"status"`
	RequestedBy  string            `json:"requested_by"`
	ApprovedBy   string            `json:"approved_by,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CompletedAt  *time.Time        `json:"completed_at,omitempty"`
	Revision     int               `json:"revision"`
	AuthEpoch    int64             `json:"auth_epoch"`
	DestDigest   string            `json:"dest_digest"`
	DestRevision int               `json:"dest_revision"`
	OpHash       string            `json:"op_hash"`
}
