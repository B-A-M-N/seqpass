package service

// P0-B regressions: the save_and_use lifecycle is a real durable
// continuation, not an unconditional deferral. Saving NEVER authorizes
// use; the recorded intent progresses only through the existing
// SubmitUse/ApproveUse/ExecuteUse machinery.

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// saveAndUse provisions with a recorded intent and returns the report.
func saveAndUse(t *testing.T, svc *Service, m *mockBrokerChild, requestID, binding, operation string) (*ProvisionReport, *types.SecretReference) {
	t.Helper()
	req := aegiskeys.ProvisionRequest{
		RequestID: requestID, Value: "save-use-secret-" + requestID, Service: "svc", Label: "L" + requestID,
		Kind: "api-key", Binding: binding, Operations: []string{operation},
	}
	intent := &UseIntent{Operation: operation, Params: map[string]string{}}
	report, ref, err := svc.ProvisionCredential(context.Background(), "intake:test", IntakeSaveAndUse, req, intent)
	if err != nil {
		t.Fatal(err)
	}
	return report, ref
}

// TestSaveAndUsePendingNeverDispatches: a recorded intent does NOT create
// a use request or dispatch anything while the grant is not usable.
func TestSaveAndUsePendingNeverDispatches(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	report, ref := saveAndUse(t, svc, m, "prov-sau-pend-1", "seqpass/sau/pend", "test.credential_save")
	if !report.Saved {
		t.Fatalf("save_and_use did not save: %+v", report)
	}
	if report.IntentState != types.ProvisionUseIntentPending {
		t.Fatalf("intent state = %q, want pending", report.IntentState)
	}
	if report.UseResult == nil || report.UseResult.Executed {
		t.Fatalf("pending intent must not execute: %+v", report.UseResult)
	}
	// NO use request exists: nothing was dispatched, nothing queued.
	it, err := svc.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID)
	if err != nil || it == nil {
		t.Fatalf("intent not durable: %v", err)
	}
	if it.OpID != "" {
		t.Fatalf("pending intent created a use request %q — dispatch without approvals", it.OpID)
	}
	if it.Principal != "intake:test" || it.Operation != "test.credential_save" {
		t.Fatalf("intent lost the recorded workflow: %+v", it)
	}
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d use requests exist for a pending intent — dispatch without approvals", n)
	}
}

// TestSaveAndUseBothApprovalsExecute: with the grant approved (provider
// ready) AND the operator's independent operation approval, the recorded
// workflow executes through the normal driver. A recovered continuation
// (second poll) never duplicates the dispatch.
func TestSaveAndUseBothApprovalsExecute(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := saveAndUse(t, svc, m, "prov-sau-exec-2", "seqpass/sau/exec", "test.credential_save")
	allowPolicy(t, svc, "intake:test", ref.ID, "test.credential_save", "*")

	// Step 5: the operator approves the staged resolver grant.
	m.grantReady(ref.ProvisionRequestID)
	// Step 6: the poll (continuation) submits the recorded workflow.
	report, ref2, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if report.IntentState != types.ProvisionUseIntentSubmitted || report.UseResult == nil || report.UseResult.OpID == "" {
		t.Fatalf("continuation did not submit the recorded intent: %+v", report)
	}
	opID := report.UseResult.OpID
	// Independent operation approval, then the normal driver executes.
	if err := svc.ApproveUse(opID, "operator", -1); err != nil {
		t.Fatalf("operation approval failed: %v", err)
	}
	if _, err := svc.ExecuteUse(context.Background(), opID, "worker"); err != nil {
		t.Fatalf("approved recorded workflow failed to execute: %v", err)
	}
	st, _ := svc.db.GetUse(opID)
	if st == nil || st.Status != types.StatusCompleted {
		t.Fatalf("recorded workflow status = %+v, want completed", st)
	}
	// A recovered continuation (second poll) reconciles the SAME op —
	// never a duplicate dispatch.
	report2, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref2.ProvisionRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if report2.IntentState != types.ProvisionUseIntentCompleted {
		t.Fatalf("second poll intent state = %q, want completed", report2.IntentState)
	}
	if report2.UseResult == nil || report2.UseResult.OpID != opID || !report2.UseResult.Executed {
		t.Fatalf("second poll did not reconcile the recorded op: %+v", report2.UseResult)
	}
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d use requests exist for the recorded intent, want exactly 1", n)
	}
}

// TestSaveAndUseDriftBlocksIntent: identity drift before dispatch blocks
// the recorded workflow (blocked, no request created).
func TestSaveAndUseDriftBlocksIntent(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := saveAndUse(t, svc, m, "prov-sau-drift-3", "seqpass/sau/drift", "test.credential_save")
	m.divergeStatusResponse(ref.ProvisionRequestID, "rec-evilX", "bid-evilX")
	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
	if err == nil {
		t.Fatalf("divergent poll succeeded: %+v", report)
	}
	if report == nil || report.IntentState != types.ProvisionUseIntentBlocked {
		t.Fatalf("intent not blocked after drift: %+v", report)
	}
	it, _ := svc.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID)
	if it == nil || it.State != types.ProvisionUseIntentBlocked {
		t.Fatalf("durable intent state = %+v, want blocked", it)
	}
	if it.OpID != "" {
		t.Fatalf("blocked intent created a use request: %q", it.OpID)
	}
}

// TestSaveAndUseDeniedSubmissionSavesStands: policy denial at submission
// fails the recorded workflow while the SAVE stands independently.
func TestSaveAndUseDeniedSubmissionSavesStands(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	// NO policy allow: SubmitUse will deny.
	report, ref := saveAndUse(t, svc, m, "prov-sau-deny-4", "seqpass/sau/deny", "test.credential_save")
	if !report.Saved {
		t.Fatalf("save must stand independently of the use denial: %+v", report)
	}
	// The grant approval proceeds; the continuation hits the denial.
	m.grantReady(ref.ProvisionRequestID)
	report2, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if report2.IntentState != types.ProvisionUseIntentFailed {
		t.Fatalf("denied intent state = %q, want failed", report2.IntentState)
	}
	if report2.UseResult == nil || report2.UseResult.Executed {
		t.Fatalf("denied intent must not execute: %+v", report2.UseResult)
	}
}

// TestSaveAndUseUncertainReconcilesNotRepeats: an uncertain external side
// effect is RECONCILED by the continuation — never blindly repeated.
func TestSaveAndUseUncertainReconcilesNotRepeats(t *testing.T) {
	ensureObservedDrivers()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.uncertain"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := saveAndUse(t, svc, m, "prov-sau-unc-5", "seqpass/sau/unc", "test.uncertain")
	allowPolicy(t, svc, "intake:test", ref.ID, "test.uncertain", "*")
	m.grantReady(ref.ProvisionRequestID)
	report, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if report.IntentState != types.ProvisionUseIntentSubmitted || report.UseResult == nil || report.UseResult.OpID == "" {
		t.Fatalf("continuation did not submit: %+v", report)
	}
	opID := report.UseResult.OpID
	if err := svc.ApproveUse(opID, "operator", -1); err != nil {
		t.Fatal(err)
	}
	// Dispatch uncertainty: the driver fails post-dispatch.
	if _, err := svc.ExecuteUse(context.Background(), opID, "worker"); err == nil {
		t.Fatal("uncertain driver unexpectedly succeeded")
	}
	st, _ := svc.db.GetUse(opID)
	if st == nil || st.Status != types.StatusUncertain {
		t.Fatalf("post-dispatch status = %+v, want uncertain", st)
	}
	// Continuation polls RECONCILE: same op, no new dispatch.
	for i := 0; i < 2; i++ {
		r, _, err := svc.ProvisionStatusReport(context.Background(), "intake:test", ref.ProvisionRequestID)
		if err != nil {
			t.Fatal(err)
		}
		if r.UseResult == nil || r.UseResult.OpID != opID {
			t.Fatalf("poll %d did not reconcile the recorded op: %+v", i+1, r.UseResult)
		}
		if r.UseResult.Executed || !strings.Contains(r.UseResult.Err, "uncertain") {
			t.Fatalf("poll %d misreported uncertainty: %+v", i+1, r.UseResult)
		}
	}
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d use requests exist after uncertain dispatch, want exactly 1 (reconcile, not repeat)", n)
	}
}

// TestSaveAndUseConcurrentContinuationSingleOp: concurrent continuation
// polls race through the TakeProvisionUseIntent CAS — exactly one use
// request is ever created for the recorded intent. The continuation is
// driven DIRECTLY behind a barrier (no provider round trip to
// desynchronize the racers).
func TestSaveAndUseConcurrentContinuationSingleOp(t *testing.T) {
	ensureTestCredentialSaveDriver()
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"test.credential_save"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	_, ref := saveAndUse(t, svc, m, "prov-sau-conc-6", "seqpass/sau/conc", "test.credential_save")
	allowPolicy(t, svc, "intake:test", ref.ID, "test.credential_save", "*")
	// Mark the reference ready WITHOUT a provider round trip (durable
	// transition) so the racers reach the pending-branch immediately.
	if _, err := svc.db.TransitionSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady,
		ref.RecordID, ref.BindingID, false, types.ProvisionReconcileCommitted); err != nil {
		t.Fatal(err)
	}
	ref.ReconcileStatus = types.ProvisionReconcileReady

	const racers = 8
	// intentRacerHook widens the exact pre-CAS window so the racers
	// deterministically interleave at the ordering point the production
	// code must get right (CAS before SubmitUse).
	release := make(chan struct{})
	var hold sync.WaitGroup
	prev := intentRacerHook
	intentRacerHook = func() {
		hold.Done()
		<-release
	}
	defer func() { intentRacerHook = prev }()
	start := make(chan struct{})
	var wg sync.WaitGroup
	opIDs := make([]string, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		hold.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			report := &ProvisionReport{RefID: ref.ID}
			svc.progressProvisionUseIntent(context.Background(), "intake:test", ref, report)
			if report.UseResult != nil {
				opIDs[i] = report.UseResult.OpID
			}
		}(i)
	}
	close(start)
	hold.Wait() // every racer is now parked exactly before the intent CAS
	close(release)
	wg.Wait()
	unique := map[string]bool{}
	for _, id := range opIDs {
		if id != "" {
			unique[id] = true
		}
	}
	if len(unique) > 1 {
		t.Fatalf("concurrent continuations produced %d distinct use requests: %v", len(unique), opIDs)
	}
	n, err := svc.db.CountUseRequestsByRef(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n > 1 {
		t.Fatalf("%d use requests exist after concurrent continuations, want <=1", n)
	}
}

// ensureObservedDrivers registers the ExternalPostcondition drivers from
// verify_test.go (observe/uncertain) with their verifiers.
func ensureObservedDrivers() {
	observeOnce.Do(func() {
		secureops.Register(observeDriver{})
		_ = secureops.RegisterVerifierEx("test.observe", "test-observer", "v1", stubVerifier{})
	})
	uncertainOnce.Do(func() {
		secureops.Register(uncertainDriver{})
		_ = secureops.RegisterVerifierEx("test.uncertain", "test-uncertain-observer", "v1", stubVerifier{})
	})
}
