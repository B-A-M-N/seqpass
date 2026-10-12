package ipc

import (
	"encoding/base64"
	"fmt"
	"time"
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
	MethodRecipientStatus = "recipient.status"     // recipient acceptance/application readback (CV-10)
	MethodHealth          = "health"
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
)

// Role is the explicit IPC security domain (SP-TUI-04). It replaces the
// old isAdmin boolean at every dispatch decision: each socket admits
// exactly one role, and each role admits exactly its method set.
type Role int

const (
	RoleAgent Role = iota
	RoleIntake
	RoleAdmin
)

// AgentAllowlist is the untrusted harness-facing surface. No plaintext intake
// or retrieval, no admin actions — and no intake methods: an agent can
// request a handoff and poll its own status, but can never supply,
// approve, or read back the sensitive value (QR-02).
var AgentAllowlist = map[string]bool{
	MethodCatalog:         true,
	MethodUseSubmit:       true,
	MethodTransferSubmit:  true,
	MethodStatus:          true,
	MethodOpsMine:         true,
	MethodRecipientStatus: true,
	MethodRelayRequest:    true,
	MethodRelayStatus:     true,
	MethodRelayCancel:     true,
	MethodHealth:          true,
}

// IntakeAllowlist is the trusted human-side surface (QR-02/SP-TUI-04):
// review pending requests, supply payloads, authorize or reject. Only
// intake.fulfill carries plaintext, and only inbound.
var IntakeAllowlist = map[string]bool{
	MethodIntakeInspect: true,
	MethodIntakeFulfill: true,
	MethodIntakeReject:  true,
	MethodIntakeCancel:  true,
	MethodIntakeRequest: true,
	MethodHealth:        true,
}

// AdminAllowlist = agent surface + intake surface + trusted operator
// actions. Operators are trusted humans: they may fulfill from the
// admin terminal as well as the intake socket.
var AdminAllowlist = map[string]bool{
	MethodCatalog:         true,
	MethodUseSubmit:       true,
	MethodTransferSubmit:  true,
	MethodStatus:          true,
	MethodOpsMine:         true,
	MethodRelayRequest:    true,
	MethodRelayStatus:     true,
	MethodRelayCancel:     true,
	MethodIntakeInspect:   true,
	MethodIntakeFulfill:   true,
	MethodIntakeReject:    true,
	MethodIntakeCancel:    true,
	MethodIntakeRequest:   true,
	MethodOpsPending:      true,
	MethodOpsReady:        true,
	MethodApproveUse:      true,
	MethodRejectUse:       true,
	MethodApproveTransfer: true,
	MethodRejectTransfer:  true,
	MethodSecretAdd:       true,
	MethodSecretStage:     true,
	MethodDestAdd:         true,
	MethodPolicyAdd:       true,
	MethodPolicySet:       true,
	MethodDestUpdate:      true,
	MethodExecuteUse:      true,
	MethodExecuteTransfer: true,
	MethodOpShow:          true,
	MethodVerifyOutcome:   true,
	MethodRecipientStatus: true,
	MethodHealth:          true,
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
