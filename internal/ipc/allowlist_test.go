package ipc

import (
	"strings"
	"testing"
)

// Agent surface must not include admin methods.
func TestAgentAllowlistExcludesAdmin(t *testing.T) {
	for m := range AgentAllowlist {
		if strings.HasPrefix(m, "admin.") {
			t.Fatalf("agent allowlist contains admin method %s", m)
		}
	}
	for _, m := range []string{
		MethodApproveUse, MethodRejectUse,
		MethodApproveTransfer, MethodRejectTransfer,
		MethodSecretAdd, MethodSecretStage, MethodDestAdd, MethodPolicyAdd,
		MethodExecuteUse, MethodExecuteTransfer, MethodOpsPending, MethodOpsReady,
		MethodOpShow, MethodVerifyOutcome,
	} {
		if AgentAllowlist[m] {
			t.Fatalf("agent may call %s", m)
		}
		if !AdminAllowlist[m] {
			t.Fatalf("admin missing %s", m)
		}
	}
	// Core harness tools stay available.
	for _, m := range []string{MethodCatalog, MethodUseSubmit, MethodTransferSubmit, MethodStatus} {
		if !AgentAllowlist[m] {
			t.Fatalf("agent missing %s", m)
		}
	}
	if !AgentAllowlist[MethodHandoffReceipt] {
		t.Fatal("agent cannot relay a recipient-signed offline receipt")
	}
	if !AgentAllowlist[MethodHandoffRetrieve] || RecipientAllowlist[MethodHandoffRetrieve] {
		t.Fatal("capsule retrieval is not confined to the requesting agent surface")
	}
	if RecipientAllowlist[MethodHandoffReceipt] {
		t.Fatal("recipient-only socket unexpectedly accepts courier receipt submissions")
	}
}
