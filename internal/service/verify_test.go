package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/secretbridge/secretbridge/internal/metadata"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// stubOutcome controls the synthetic observer below. Tests run
// sequentially within a package, so a package-level switch is safe.
var (
	stubMu     sync.Mutex
	stubState  secureops.OutcomeState = secureops.OutcomeSatisfied
	stubErr    error
	stubDetail = "stub observation"
)

func setStub(state secureops.OutcomeState, err error) {
	stubMu.Lock()
	defer stubMu.Unlock()
	stubState, stubErr = state, err
	stubDetail = "stub observation"
}

type stubVerifier struct{}

func (stubVerifier) Verify(ctx context.Context, in secureops.UseInput, r secureops.SafeResult) (secureops.Outcome, error) {
	stubMu.Lock()
	defer stubMu.Unlock()
	if stubErr != nil {
		return secureops.Outcome{Detail: "observer down"}, stubErr
	}
	return secureops.Outcome{State: stubState, Detail: stubDetail, EvidenceRef: "stub-evidence"}, nil
}

// observeDriver is the synthetic state-changing operation used to qualify
// verification semantics (CV-01/CV-02 validation). Unlike the read-only
// github drivers, it declares ExternalPostcondition, so completion
// requires an independent observation from stubVerifier.
type observeDriver struct{}

func (observeDriver) Name() string { return "test.observe" }
func (observeDriver) Completion() secureops.CompletionMode {
	return secureops.ExternalPostcondition
}
func (observeDriver) RequiresDestination() bool { return false }
func (observeDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic observed op", Completion: secureops.ExternalPostcondition}
}
func (observeDriver) AllowedParams() []string { return []string{} }
func (observeDriver) Resource(params map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "observe"}
}
func (observeDriver) Validate(secureops.UseInput) error { return nil }
func (observeDriver) Execute(ctx context.Context, cred secureops.Credential, in secureops.UseInput) (secureops.SafeResult, error) {
	return secureops.SafeResult{Summary: "observed ok", Data: map[string]interface{}{"ok": true}}, nil
}

type uncertainDriver struct{}

func (uncertainDriver) Name() string { return "test.uncertain" }
func (uncertainDriver) Completion() secureops.CompletionMode {
	return secureops.ExternalPostcondition
}
func (uncertainDriver) RequiresDestination() bool { return false }
func (uncertainDriver) Describe() secureops.DriverInfo {
	return secureops.DriverInfo{Description: "synthetic dispatch ambiguity", Completion: secureops.ExternalPostcondition}
}
func (uncertainDriver) AllowedParams() []string { return []string{} }
func (uncertainDriver) Resource(map[string]string) secureops.ResourceDescriptor {
	return secureops.ResourceDescriptor{Kind: "test", Identifier: "uncertain"}
}
func (uncertainDriver) Validate(secureops.UseInput) error { return nil }
func (uncertainDriver) Execute(context.Context, secureops.Credential, secureops.UseInput) (secureops.SafeResult, error) {
	return secureops.SafeResult{}, errors.New("remote response lost after dispatch")
}

var (
	observeOnce   sync.Once
	uncertainOnce sync.Once
)

func ensureObserveDriver(t *testing.T) {
	t.Helper()
	observeOnce.Do(func() {
		secureops.Register(observeDriver{})
		if err := secureops.RegisterVerifierEx("test.observe", "test-observer", "v1", stubVerifier{}); err != nil {
			t.Fatalf("register test observer: %v", err)
		}
	})
	setStub(secureops.OutcomeSatisfied, nil)
}

func ensureUncertainDriver(t *testing.T) {
	t.Helper()
	uncertainOnce.Do(func() {
		secureops.Register(uncertainDriver{})
		if err := secureops.RegisterVerifierEx("test.uncertain", "test-uncertain-observer", "v1", stubVerifier{}); err != nil {
			t.Fatalf("register uncertain observer: %v", err)
		}
	})
	setStub(secureops.OutcomeSatisfied, nil)
}

// completeObservedOp drives a test.observe op to completed through the
// durable claim/finalize path (never by hand-editing the receipt).
func completeObservedOp(t *testing.T, svc *Service) string {
	t.Helper()
	sr := &types.SecretReference{ID: "obs", Name: "obs", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("obs", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "obs", "test.observe", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "obs", Operation: "test.observe", Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ur, _ := svc.DB().GetUse(id)
	attempt, claimed, err := svc.DB().ClaimUse(ur.ID, ur.OpHash, ur.DestDigest, ur.Revision, "op", ur.CreatedAt)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusCompleted, "test.observe", map[string]interface{}{"ok": true}); err != nil {
		t.Fatal(err)
	}
	return id
}

// Transfers with no verifier report inconclusive: the ack proves durable
// acceptance, not application (SC-06/SC-14, CV-01).
func TestVerifyTransferInconclusiveWithoutVerifier(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	id := setupTransferFixture(t, svc)
	if _, err := svc.ExecuteTransfer(context.Background(), id, "op"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "transfer", id, false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.State != metadata.ObsInconclusive {
		t.Fatalf("state = %q, want inconclusive", v.State)
	}
	status, err := svc.StatusDetail("uid:1000", "transfer", id)
	if err != nil || status.EffectiveOutcome != "accepted" || !strings.Contains(status.NextAction, "do not resend") {
		t.Fatalf("recipient acceptance was conflated with application: %+v %v", status, err)
	}
	if v.ObservationID == "" {
		t.Fatal("observation was not persisted with an ID")
	}
	// Foreign principals cannot probe another agent's outcome.
	if _, err := svc.VerifyOutcome(context.Background(), "uid:9999", "transfer", id, false); err == nil {
		t.Fatal("foreign principal verified another agent's op")
	}
	// Non-completed ops cannot be verified.
	id2, err := svc.SubmitTransfer("uid:1000", &types.TransferRequest{SecretRef: "cert1", DestinationID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyOutcome(context.Background(), "uid:1000", "transfer", id2, false); err == nil {
		t.Fatal("pending op verified")
	}
}

// A satisfied observation flows through and never rewrites the receipt.
func TestVerifySatisfiedWithRegisteredVerifier(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	id := completeObservedOp(t, svc)
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.State != metadata.ObsSatisfied || v.Detail != "stub observation" {
		t.Fatalf("unexpected verification: %+v", v)
	}
	if v.VerifierID != "test-observer" || v.VerifierVersion != "v1" {
		t.Fatalf("observation lost verifier identity: %+v", v)
	}
	r, _ := svc.DB().GetReceipt(id)
	if r.ResultType != "test.observe" {
		t.Fatalf("verification rewrote the receipt: %+v", r)
	}
}

// CV-01: a confirmed contradictory observation produces a contradicted
// record that is terminally distinct from satisfied — never collapsed
// into "unverified".
func TestVerifyContradictedDistinctFromSatisfied(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	id := completeObservedOp(t, svc)
	setStub(secureops.OutcomeSatisfied, nil)
	sat, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || sat.State != metadata.ObsSatisfied {
		t.Fatalf("satisfied: %+v %v", sat, err)
	}
	setStub(secureops.OutcomeContradicted, nil)
	con, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || con.State != metadata.ObsContradicted {
		t.Fatalf("contradicted: %+v %v", con, err)
	}
	hist, err := svc.DB().ListObservations(id)
	if err != nil || len(hist) != 2 {
		t.Fatalf("history = %d, %v; want both observations retained", len(hist), err)
	}
	if hist[0].State != metadata.ObsSatisfied || hist[1].State != metadata.ObsContradicted {
		t.Fatalf("history order wrong: %+v", hist)
	}
	latest, err := svc.DB().LatestObservation(id)
	if err != nil || latest.State != metadata.ObsContradicted {
		t.Fatalf("latest = %+v %v; contradiction must stay visible", latest, err)
	}
	// The contradiction is exposed through the agent-visible status path
	// so the operator can reconcile instead of seeing "completed" alone.
	st, err := svc.StatusDetail("uid:1000", "use", id)
	if err != nil || !st.HasObservation || st.VerifyState != metadata.ObsContradicted {
		t.Fatalf("status hides the contradiction: %+v %v", st, err)
	}
	if st.EffectiveOutcome != "contradicted" || !strings.Contains(st.NextAction, "reconcile") {
		t.Fatalf("contradiction projected as clean completion: %+v", st)
	}
}

func TestPostDispatchDriverErrorIsReconciledWithoutReplay(t *testing.T) {
	ensureUncertainDriver(t)
	svc := testService(t)
	seedRef(t, svc, "uncertain-secret", "")
	if err := svc.vault.Store("uncertain-secret", []byte("synthetic-token")); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "uncertain-secret", "test.uncertain", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "uncertain-secret", Operation: "test.uncertain", Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteUse(context.Background(), id, "worker"); err == nil || strings.Contains(err.Error(), "remote response lost") {
		t.Fatalf("driver error was not safely handled: %v", err)
	}
	st, err := svc.StatusDetail("uid:1000", "use", id)
	if err != nil || st.Status != types.StatusUncertain || st.EffectiveOutcome != "uncertain" || !strings.Contains(st.NextAction, "do not replay") {
		t.Fatalf("ambiguous dispatch not exposed for reconciliation: %+v %v", st, err)
	}
	if st.HasReceipt {
		t.Fatal("uncertain execution unexpectedly has a completion receipt")
	}
	if _, err := svc.ExecuteUse(context.Background(), id, "worker-again"); err == nil {
		t.Fatal("uncertain operation was replayed")
	}
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || v.State != metadata.ObsSatisfied {
		t.Fatalf("independent reconciliation failed: %+v %v", v, err)
	}
	st, err = svc.StatusDetail("uid:1000", "use", id)
	if err != nil || st.Status != types.StatusUncertain || st.EffectiveOutcome != "satisfied" {
		t.Fatalf("reconciliation rewrote execution state instead of composing outcome: %+v %v", st, err)
	}
}

// P2-8: a verification-history read failure surfaces as
// verification_unavailable — never as "no verification performed", and
// never as a failed status call. Fault injection drops the observations
// table through a second handle after a real completed op exists.
func TestStatusDetailVerificationUnavailable(t *testing.T) {
	ensureObserveDriver(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	id := completeObservedOp(t, svc)
	// Sanity: with no observation recorded, absence reads clean.
	st, err := svc.StatusDetail("uid:1000", "use", id)
	if err != nil || st.HasObservation || st.VerifyUnavailable || st.VerifyState != "" {
		t.Fatalf("clean absence misreported: %+v %v", st, err)
	}
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("DROP TABLE outcome_observations"); err != nil {
		t.Fatal(err)
	}
	st, err = svc.StatusDetail("uid:1000", "use", id)
	if err != nil {
		t.Fatalf("status failed instead of reporting unavailable: %v", err)
	}
	if !st.VerifyUnavailable || st.VerifyState != "verification_unavailable" {
		t.Fatalf("read failure hidden: %+v", st)
	}
	if st.HasObservation {
		t.Fatal("unreadable observation presented as present")
	}
	if !st.HasReceipt || st.Status != "completed" {
		t.Fatalf("execution facts lost alongside verification: %+v", st)
	}
}

// CV-01: observer failures and malformed verifier output are check-failed,
// never proof of success or failure.
func TestVerifyCheckFailedPaths(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	id := completeObservedOp(t, svc)
	// Unavailable observer.
	setStub(secureops.OutcomeSatisfied, errors.New("transport down"))
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || v.State != metadata.ObsCheckFailed {
		t.Fatalf("observer error: %+v %v; want check-failed", v, err)
	}
	st, err := svc.StatusDetail("uid:1000", "use", id)
	if err != nil || st.EffectiveOutcome != "uncertain" || !strings.Contains(st.NextAction, "verification") {
		t.Fatalf("failed observation presented as clean completion: %+v %v", st, err)
	}
	// Malformed evidence: empty/unknown outcome state.
	setStub("", nil)
	v, err = svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || v.State != metadata.ObsCheckFailed {
		t.Fatalf("unknown state: %+v %v; want check-failed", v, err)
	}
	setStub(secureops.OutcomeState("bogus"), nil)
	v, err = svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil || v.State != metadata.ObsCheckFailed {
		t.Fatalf("bogus state: %+v %v; want check-failed", v, err)
	}
}

// CV-02: read-only drivers report response_validated — an honest contract
// label, never a claim of independent external verification.
func TestVerifyReadOnlyResponseValidated(t *testing.T) {
	ensureObserveDriver(t)
	svc := testService(t)
	sr := &types.SecretReference{ID: "gh", Name: "gh", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("gh", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "gh", "github.get_repo", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "gh", Operation: "github.get_repo", Params: map[string]string{"repo": "o/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ur, _ := svc.DB().GetUse(id)
	attempt, claimed, err := svc.DB().ClaimUse(ur.ID, ur.OpHash, ur.DestDigest, ur.Revision, "op", ur.CreatedAt)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusCompleted, "github.get_repo", map[string]interface{}{"full_name": "o/r"}); err != nil {
		t.Fatal(err)
	}
	v, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.State != metadata.ObsResponseValidated {
		t.Fatalf("read-only state = %q, want response_validated", v.State)
	}
}

// CV-03: observations survive a broker restart; a stale observation can
// never silently overwrite the newer contradiction.
func TestVerifyObservationsSurviveRestart(t *testing.T) {
	ensureObserveDriver(t)
	dir := t.TempDir()
	dbPath := dir + "/v.db"
	svc, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	sr := &types.SecretReference{ID: "obs", Name: "obs", Owner: "test"}
	if err := svc.AddSecretRef(sr); err != nil {
		t.Fatal(err)
	}
	if err := svc.vault.Store("obs", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	allowPolicy(t, svc, "uid:1000", "obs", "test.observe", "*")
	id, err := svc.SubmitUse("uid:1000", &types.UseRequest{
		SecretRef: "obs", Operation: "test.observe", Params: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUse(id, "operator", -1); err != nil {
		t.Fatal(err)
	}
	ur, _ := svc.DB().GetUse(id)
	attempt, claimed, err := svc.DB().ClaimUse(ur.ID, ur.OpHash, ur.DestDigest, ur.Revision, "op", ur.CreatedAt)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := svc.DB().FinalizeOp("use", id, attempt, types.StatusCompleted, "test.observe", map[string]interface{}{"ok": true}); err != nil {
		t.Fatal(err)
	}
	setStub(secureops.OutcomeContradicted, nil)
	if _, err := svc.VerifyOutcome(context.Background(), "uid:1000", "use", id, false); err != nil {
		t.Fatal(err)
	}
	_ = svc.Close()
	svc2, err := New(Config{DBPath: dbPath, VaultType: "memory-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	hist, err := svc2.DB().ListObservations(id)
	if err != nil || len(hist) != 1 || hist[0].State != metadata.ObsContradicted {
		t.Fatalf("history lost across restart: %+v %v", hist, err)
	}
}
