package ipc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

// Methods exposed over the broker Unix sockets.
const (
	MethodCatalog         = "catalog"
	MethodUseSubmit       = "use.submit"
	MethodTransferSubmit  = "transfer.submit"
	MethodStatus          = "status"
	MethodOpsMine         = "ops.mine"
	MethodOpsPending      = "ops.pending" // admin only (all principals)
	MethodOpsReady        = "ops.ready"   // admin only: authorized, awaiting execution (G03)
	MethodApproveUse      = "admin.approve_use"
	MethodRejectUse       = "admin.reject_use"
	MethodApproveTransfer = "admin.approve_transfer"
	MethodRejectTransfer  = "admin.reject_transfer"
	MethodSecretAdd       = "admin.secret_add"
	MethodSecretStage     = "admin.secret_stage" // bounded trusted intake, dev-mode only (SC-08)
	MethodDestAdd         = "admin.dest_add"
	MethodPolicyAdd       = "admin.policy_add"
	MethodPolicySet       = "admin.policy_set"
	MethodDestUpdate      = "admin.dest_update"
	MethodExecuteUse      = "admin.execute_use"
	MethodExecuteTransfer = "admin.execute_transfer"
	MethodOpShow          = "admin.op_show"        // reviewed-envelope display for approval (SC-02)
	MethodVerifyOutcome   = "admin.verify_outcome" // independent postcondition check (SC-14)
	MethodRecipientStatus = "recipient.status"
	MethodHandoffIssue    = "handoff.issue"
	MethodHandoffRetrieve = "handoff.retrieve"
	MethodHandoffRedeem   = "handoff.redeem"
	MethodHandoffComplete = "handoff.complete"    // recipient acceptance/application readback (CV-10)
	MethodHandoffReceipt  = "handoff.receipt"     // relay recipient-signed offline capsule receipt
	MethodAttestPublic    = "admin.attest_public" // P0-1: executor attest public key (admin only)
	// P0-3: trusted-intake credential persistence. Values cross ONLY the
	// intake/admin sockets (trusted plaintext domains); the agent
	// allowlist never admits these.
	MethodIntakeCredentialSave  = "intake.credential_save"
	MethodIntakeProvisionStatus = "intake.provision_status"
	MethodHealth                = "health"
	// Relay handshake (QR-03): agent requests, user fulfills.
	MethodRelayRequest = "relay.request"
	MethodRelayStatus  = "relay.status"
	MethodRelayCancel  = "relay.cancel"
	// Intake domain (QR-02/SP-TUI-04): trusted human-side surface only.
	// Plaintext enters the broker exclusively through intake.fulfill.
	MethodIntakeInspect = "intake.inspect"
	MethodIntakeFulfill = "intake.fulfill"
	MethodIntakeReject  = "intake.reject"
	MethodIntakeCancel  = "intake.cancel"
	MethodIntakeRequest = "intake.request"
	// Native host adapter surfaces (HI-02/HI-03). Registration and token
	// validation require the protected intake trust boundary. Agent-facing
	// request events are deliberately not here: notifications are scoped
	// to the already authenticated native host, not to model control.
	MethodHostBindingCreate = "admin.host_binding_create"
	MethodHostRegister      = "host.register"
	MethodHostEvent         = "host.event"
	MethodHostPending       = "host.pending"
	MethodHostReview        = "host.review"
	MethodHostNotice        = "host.notice"
	MethodHostStatus        = "host.status"
	MethodHostCancelPrompt  = "host.cancel_prompt"
)

// Role is the explicit IPC security domain (SP-TUI-04). It replaces the
// old isAdmin boolean at every dispatch decision: each socket admits
// exactly one role, and each role admits exactly its method set.
type Role int

const (
	RoleAgent Role = iota
	RoleIntake
	RoleAdmin
	RoleHost
	RoleRecipient
)

// AgentAllowlist is the untrusted harness-facing surface. No plaintext intake
// or retrieval, no admin actions — and no intake methods: an agent can
// request a handoff and poll its own status, but can never supply,
// approve, or read back the sensitive value (QR-02).
// HostAllowlist is the native-host adapter surface. It can observe
// presentation metadata and review a pending request, but can never
// fulfill, reject, or otherwise authorize delivery. This is a separate
// role from intake: HI-04's data plane remains intake-only.
var HostAllowlist = map[string]bool{
	MethodHostEvent:        true,
	MethodHostPending:      true,
	MethodHostNotice:       true,
	MethodHostStatus:       true,
	MethodHostReview:       true,
	MethodHostCancelPrompt: true,
	MethodHealth:           true,
}

var AgentAllowlist = map[string]bool{
	MethodCatalog:         true,
	MethodUseSubmit:       true,
	MethodTransferSubmit:  true,
	MethodStatus:          true,
	MethodOpsMine:         true,
	MethodRecipientStatus: true,
	MethodHandoffIssue:    true,
	MethodHandoffRetrieve: true,
	MethodHandoffReceipt:  true,
	MethodRelayRequest:    true,
	MethodRelayStatus:     true,
	MethodRelayCancel:     true,
	MethodHealth:          true,
}

// RecipientAllowlist is the narrowly scoped application handoff channel.
var RecipientAllowlist = map[string]bool{
	MethodHandoffRedeem:   true,
	MethodHandoffComplete: true,
	MethodHealth:          true,
}

// IntakeAllowlist is the trusted human-side surface (QR-02/SP-TUI-04):
// review pending requests, supply payloads, authorize or reject. Only
// intake.fulfill carries plaintext, and only inbound.
// IntakeAllowlist is the trusted human-side surface (QR-02/SP-TUI-04):
// review pending requests, supply payloads, authorize or reject. Only
// intake.fulfill carries plaintext, and only inbound. It also owns
// native-host registration because that adapter must authenticate over a
// protected trust boundary; a host token never gains fulfillment rights.
var IntakeAllowlist = map[string]bool{
	MethodHostRegister:  true,
	MethodIntakeInspect: true,
	MethodIntakeFulfill: true,
	MethodIntakeReject:  true,
	MethodIntakeCancel:  true,
	MethodIntakeRequest: true,
	MethodHealth:        true,
	// P0-3: trusted intake selects credential persistence. The VALUE
	// arrives here (intake socket = the trusted plaintext crossing, same
	// as intake.fulfill) and travels only onward through the trusted
	// helper crossing. NEVER on the agent surface.
	MethodIntakeCredentialSave:  true,
	MethodIntakeProvisionStatus: true,
}

// AdminAllowlist = agent surface + intake surface + trusted operator
// actions. Operators are trusted humans: they may fulfill from the
// admin terminal as well as the intake socket.
var AdminAllowlist = map[string]bool{
	MethodHostBindingCreate: true,
	MethodHostRegister:      true,
	MethodCatalog:           true,
	MethodUseSubmit:         true,
	MethodTransferSubmit:    true,
	MethodStatus:            true,
	MethodOpsMine:           true,
	MethodRelayRequest:      true,
	MethodRelayStatus:       true,
	MethodRelayCancel:       true,
	MethodIntakeInspect:     true,
	MethodIntakeFulfill:     true,
	MethodIntakeReject:      true,
	MethodIntakeCancel:      true,
	MethodIntakeRequest:     true,
	MethodOpsPending:        true,
	MethodOpsReady:          true,
	MethodApproveUse:        true,
	MethodRejectUse:         true,
	MethodApproveTransfer:   true,
	MethodRejectTransfer:    true,
	MethodSecretAdd:         true,
	MethodSecretStage:       true,
	MethodDestAdd:           true,
	MethodPolicyAdd:         true,
	MethodPolicySet:         true,
	MethodDestUpdate:        true,
	MethodExecuteUse:        true,
	MethodExecuteTransfer:   true,
	MethodOpShow:            true,
	MethodVerifyOutcome:     true,
	MethodRecipientStatus:   true,
	MethodHandoffIssue:      true,
	MethodHandoffRetrieve:   true,
	MethodHealth:            true,
	// P0-1: the operator retrieves the broker's attest public key to pin
	// it in the AegisKeys grant (attest_key). Admin-only by construction:
	// the key is for grant authoring, not an agent surface.
	MethodAttestPublic: true,
	// P0-3: trusted-intake persistence methods (operators may also drive
	// them from the admin terminal).
	MethodIntakeCredentialSave:  true,
	MethodIntakeProvisionStatus: true,
}

type Request struct {
	ID     string                 `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type Response struct {
	ID    string      `json:"id"`
	OK    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

// uintParam extracts an optional non-negative integer param (JSON numbers
// decode as float64). ok is false when the key is absent.
func uintParam(p map[string]interface{}, k string) (uint32, bool) {
	if p == nil {
		return 0, false
	}
	v, ok := p[k]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		if n < 0 || n != float64(uint32(n)) {
			return 0, false
		}
		return uint32(n), true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	default:
		return 0, false
	}
}

// expectRevision extracts the operator-reviewed revision for approval CAS
// (SC-02). Absent means "no reviewed revision supplied" (-1); the service
// then CAS-checks the current revision, which still races safely.
func expectRevision(p map[string]interface{}) int {
	if p == nil {
		return -1
	}
	v, ok := p["expect_revision"]
	if !ok || v == nil {
		return -1
	}
	switch n := v.(type) {
	case float64:
		if n < 0 || n != float64(int(n)) {
			return -1
		}
		return int(n)
	case int:
		if n < 0 {
			return -1
		}
		return n
	default:
		return -1
	}
}

func strParam(p map[string]interface{}, k string) string {
	if p == nil {
		return ""
	}
	v, _ := p[k].(string)
	return v
}

// ttlParam extracts an optional time-to-live in seconds (relay deadlines
// are per-request, independent of the operation approval window). Absent
// or invalid means zero — the service applies its default.
func ttlParam(p map[string]interface{}) time.Duration {
	if p == nil {
		return 0
	}
	switch n := p["ttl_seconds"].(type) {
	case float64:
		if n <= 0 || n > 86400 {
			return 0
		}
		return time.Duration(n * float64(time.Second))
	case int:
		if n <= 0 || n > 86400 {
			return 0
		}
		return time.Duration(n) * time.Second
	default:
		return 0
	}
}

func uintParamOr(p map[string]interface{}, k string) uint32 {
	n, _ := uintParam(p, k)
	return n
}

// b64Param decodes a bounded base64 payload (intake fulfillment). The
// plaintext enters the broker ONLY here (QR-02); the decoded bytes are
// handed to the ephemeral store, never logged or reflected.
func b64Param(p map[string]interface{}, k string) ([]byte, error) {
	s := strParam(p, k)
	if s == "" {
		return nil, fmt.Errorf("missing payload")
	}
	if len(s) > 4*(64*1024)/3+8 {
		return nil, fmt.Errorf("payload too large")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, fmt.Errorf("payload must be 1..65536 bytes")
	}
	return raw, nil
}

// newRequestID generates a fresh durable provisioning request ID (P0-3).
// crypto/rand: the request ID is the reconciliation anchor — an
// unpredictable ID prevents a local attacker from pre-creating a matching
// provider entry (grant pinning still enforces identity server-side).
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fail closed: no ID, no provisioning.
		return ""
	}
	return hex.EncodeToString(b)
}

// provisionReportData maps the separate-outcome report onto the IPC
// response. Credential values are never included: metadata only.
func provisionReportData(report *service.ProvisionReport, ref *types.SecretReference, requestID string) map[string]interface{} {
	out := map[string]interface{}{
		"request_id":      requestID,
		"saved":           report.Saved,
		"provider_status": report.ProviderStatus,
	}
	if ref != nil {
		out["ref_id"] = ref.ID
		out["binding"] = ref.Binding
		out["reconcile_status"] = ref.ReconcileStatus
		if ref.RecordID != "" {
			out["record_id"] = ref.RecordID
		}
		if ref.BindingID != "" {
			out["binding_id"] = ref.BindingID
		}
		out["use_once"] = ref.UseOnce
	}
	if report.ReEnrollmentRequired {
		out["authorization"] = "pending: approve the staged resolver grant in AegisKeys before resolves succeed"
		// P1-B: the staged-grant workflow information and the explicit
		// approval step — metadata only, never secrets.
		surfaceStagedGrant(out, report, requestID)
	}
	if report.IdentityConflict {
		out["identity_conflict"] = true
		out["conflict_next_step"] = report.ConflictNextStep
	}
	if report.IntentState != "" {
		out["use_intent_state"] = report.IntentState
	}
	if report.CachedStatus {
		// P1-A cached-status honesty: this provider_status is the LAST
		// OBSERVED state from the durable row, not a fresh provider
		// verdict — poll --status to re-verify; dispatch revalidates
		// regardless.
		out["cached_status"] = true
		out["provider_status_note"] = "last observed provider state (not freshly verified); poll credential-save --status for a live verdict"
	}
	if !report.StagedUntil.IsZero() {
		// P0-C transient staging: metadata only, never the credential.
		out["transient"] = true
		out["staged_until"] = report.StagedUntil.UTC().Format(time.RFC3339)
	}
	if report.UseResult != nil {
		use := map[string]interface{}{"executed": report.UseResult.Executed}
		if report.UseResult.OpID != "" {
			use["op_id"] = report.UseResult.OpID
		}
		if report.UseResult.Err != "" {
			use["detail"] = report.UseResult.Err
		}
		// Separate durable outcome: the use result stands next to the
		// save result, never merged into it.
		out["use_outcome"] = use
	}
	return out
}

// surfaceStagedGrant maps the provider's staged-grant workflow
// information (P1-B) onto the IPC response: WHICH grant awaits approval,
// any staging failure, and the explicit approval next step. Metadata
// only — never credential material.
func surfaceStagedGrant(out map[string]interface{}, report *service.ProvisionReport, requestID string) {
	if report.StagedGrantID != "" {
		out["staged_grant_id"] = report.StagedGrantID
	}
	if report.StagingError != "" {
		out["staging_error"] = report.StagingError
	}
	if report.StagedGrantID != "" || report.StagingError != "" {
		out["approve_next_step"] = "aegiskeys access provision approve --request " + requestID
	}
}
