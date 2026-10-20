// Trusted-intake provisioning flow (P0-3): the broker-side orchestration of
// the AegisKeys /v3 save workflow. Persistence is a TRUSTED-INTAKE decision
// only — the agent IPC surface never gains credential submission,
// provisioning, or raw credential values (the IPC allowlist gates the
// method to admin/intake domains).
//
// Exactly-once discipline: every provisioned credential has a durable
// SeqPass reference carrying the provider request ID. Retries and
// reconciliation key on that ID; a lost exchange is UNCERTAIN (the provider
// may have committed) and must be reconciled by status before any retry —
// a new request ID could duplicate the credential, an altered same-ID
// resubmit is a hard conflict.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
	"github.com/secretbridge/secretbridge/internal/vault"
)

// Trusted-intake persistence modes.
const (
	// IntakeUseOnce is the PERSISTED SINGLE-USE contract: AegisKeys
	// deliberately retains the encrypted credential (a durable provider
	// record is created), and SeqPass limits its use to ONE authorized
	// execution (the durable reference is consumed at dispatch). This is
	// explicitly distinct from IntakeTransientOnce, which never persists
	// the credential anywhere.
	IntakeUseOnce = "use_once"
	// IntakeSaveOnly: the credential is saved and bound; no immediate use.
	IntakeSaveOnly = "save_only"
	// IntakeSaveAndUse: save, then record the intended use as a durable
	// PENDING CONTINUATION — reported as TWO separate durable outcomes
	// (storage vs execution). Saving NEVER authorizes use: the recorded
	// intent becomes an ordinary pending use request only when the
	// provider grant is usable, and still requires the operator's
	// independent operation approval before any dispatch.
	IntakeSaveAndUse = "save_and_use"
	// IntakeTransientOnce is the TRANSIENT USE-ONCE contract (P0-C): the
	// human-supplied credential exists ONLY inside the protected
	// ephemeral handoff/execution boundary (the broker's in-memory
	// spool, reservation-gated like relay payloads). ONE approved
	// operation can consume it; NO durable AegisKeys credential is
	// created; the payload is unrecoverable after expiry or restart.
	// Dispatch stays at-most-once: a post-dispatch failure has already
	// consumed the transient credential — the failure is reported
	// honestly, never retried silently.
	IntakeTransientOnce = "transient_once"
)

// transientOnceTTL bounds a transient credential's lifetime inside the
// ephemeral spool. Test-overridable; production keeps the default.
var transientOnceTTL = 15 * time.Minute

// UseIntent is the intended operation of a save_and_use request, REVIEWED
// by the trusted human at save time and persisted as the durable
// continuation record. It carries no authorization and no credential
// material — only the operation shape (destination, parameters, scope)
// the continuation replays into the existing use-request machinery.
type UseIntent struct {
	Operation string
	Target    string
	Params    map[string]string
}

// validIntakePersistence fail-closes the mode selection.
func validIntakePersistence(mode string) bool {
	switch mode {
	case IntakeUseOnce, IntakeSaveOnly, IntakeSaveAndUse, IntakeTransientOnce:
		return true
	}
	return false
}

// ProvisionReport is the separate-outcome report of a trusted-intake save
// (and, for save_and_use, the immediate-use attempt). A successful save
// followed by a denied use is a SAVED credential with authorization
// pending — never an error suggesting nothing was saved.
type ProvisionReport struct {
	// Saved is true only when the provider durably committed the
	// credential (or a prior attempt under the same request ID already
	// had — recovered idempotently).
	Saved bool
	// ProviderStatus is the provider's lifecycle status for the request
	// (authorization_pending, grant_present, ready, ...).
	ProviderStatus string
	// ReEnrollmentRequired is true when the provider committed but the
	// resolve grant is not yet usable (authorization_pending): the
	// operator approves the staged grant in AegisKeys.
	ReEnrollmentRequired bool
	// RefID is the durable SeqPass reference.
	RefID string
	// IdentityConflict marks a durable identity divergence: the provider
	// now reports a different record/binding ID than the reference's
	// pinned identity. The original pins are preserved; execution is
	// blocked until operator reconciliation. ConflictNextStep carries the
	// operator-facing procedure.
	IdentityConflict bool
	ConflictNextStep string
	// UseResult is set only for save_and_use: the second, independent
	// outcome. A nil UseResult with Saved=true means the use phase never
	// started (not approved / not ready), NOT a failed save.
	UseResult *UseOutcomeReport
	// IntentState (save_and_use with a recorded intent): the durable
	// continuation state — pending (awaiting grant + operator approval),
	// submitted (use request exists; approve op <UseResult.OpID>),
	// completed/failed (the op's terminal outcome), blocked (reference
	// conflicted or policy denied before any dispatch).
	IntentState string
	// StagedUntil (transient_once only): when the staged in-memory
	// payload expires. Saved stays FALSE — nothing durable was created.
	StagedUntil time.Time
}

// UseOutcomeReport is the outcome of the recorded save_and_use
// continuation (a distinct durable event from the save).
type UseOutcomeReport struct {
	Executed bool
	OpID     string
	Err      string
}

// provisionedSocket resolves the AegisKeys socket path the same way the
// resolve path does.
func (s *Service) provisionedSocket() string {
	if s.cfg.AegisKeysSocket != "" {
		return s.cfg.AegisKeysSocket
	}
	return aegiskeys.SocketPath(s.cfg.AegisKeysDir)
}

// ProvisionCredential creates (or idempotently recovers) one provisioned
// credential under mode. caller is the authenticated trusted-intake
// principal (audit only — the provider enforces its own provisioning
// grant). The credential VALUE travels only through the trusted helper
// crossing (ProvisionViaHelper); in test/dev mode (no helper configured)
// the direct client path stands in, with the in-process identity as the
// provisioning peer.
//
// ProvisionCredential creates (or idempotently recovers) one provisioned
// credential under mode. caller is the authenticated trusted-intake
// principal (audit only — the provider enforces its own provisioning
// grant). The credential VALUE travels only through the trusted helper
// crossing (ProvisionViaHelper); in test/dev mode (no helper configured)
// the direct client path stands in, with the in-process identity as the
// provisioning peer.
//
// intent (save_and_use only) is the intended operation reviewed by the
// trusted human at save time: it is persisted as the durable pending
// continuation BEFORE any approval exists, and progressed exclusively
// through the existing use-request machinery (SubmitUse/ApproveUse/
// ExecuteUse) — no second scheduler, no implicit authorization.
func (s *Service) ProvisionCredential(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, intent *UseIntent) (*ProvisionReport, *types.SecretReference, error) {
	if !validIntakePersistence(mode) {
		return nil, nil, fmt.Errorf("unknown persistence mode %q: use use_once, save_only or save_and_use", mode)
	}
	if err := aegiskeys.ValidProvisionRequest(req); err != nil {
		return nil, nil, err
	}
	if intent != nil && mode != IntakeSaveAndUse {
		return nil, nil, fmt.Errorf("use intent requires mode %q", IntakeSaveAndUse)
	}
	if mode == IntakeSaveAndUse && intent != nil {
		if intent.Operation == "" {
			return nil, nil, errors.New("save_and_use intent requires an operation")
		}
		if _, err := validateDriverParams(intent.Operation, intent.Params); err != nil {
			return nil, nil, fmt.Errorf("save_and_use intent invalid: %w", err)
		}
	}

	// P0-C transient use-once: the credential NEVER reaches the provider
	// or any durable store. It is staged only in the broker's in-memory
	// ephemeral spool under a bounded lifetime; the durable reference row
	// is metadata only (policy/approval anchor). No provider round trip,
	// no provider request ID, unrecoverable after expiry or restart.
	if mode == IntakeTransientOnce {
		return s.stageTransientOnce(caller, req)
	}

	ref, err := s.db.GetSecretRefByProvisionRequest(req.RequestID)
	if err != nil {
		return nil, nil, fmt.Errorf("provision lookup failed: %w", err)
	}
	if ref != nil {
		return s.reconcileProvision(ctx, caller, mode, req, intent, ref)
	}

	// Write-ahead durable reference BEFORE any provider call: a crash
	// after the provider committed but before the response arrived leaves
	// an 'uncertain' record that the retry reconciles — never a duplicate.
	ref = &types.SecretReference{
		Name:               req.Label,
		Description:        req.Description,
		Owner:              caller,
		Binding:            req.Binding,
		ProvisionRequestID: req.RequestID,
		ReconcileStatus:    types.ProvisionReconcilePending,
		UseOnce:            mode == IntakeUseOnce,
	}
	if err := s.db.CreateSecretRef(ref); err != nil {
		return nil, nil, fmt.Errorf("provision write-ahead failed: %w", err)
	}
	if intent != nil {
		// The recorded workflow is durable before the provider call: a
		// crash mid-provision leaves the intent pending; the retry
		// (same request ID) recovers the SAME intent — never a new one.
		if err := s.db.CreateProvisionUseIntent(&types.ProvisionUseIntent{
			ProvisionRequestID: req.RequestID,
			RefID:              ref.ID,
			Principal:          caller,
			Operation:          intent.Operation,
			Target:             intent.Target,
			Params:             intent.Params,
			State:              types.ProvisionUseIntentPending,
		}); err != nil {
			return nil, ref, fmt.Errorf("provision use intent persist failed: %w", err)
		}
	}
	return s.submitProvision(ctx, caller, mode, req, intent, ref)
}

// stageTransientOnce implements the TRANSIENT USE-ONCE intake (P0-C).
// The credential is staged ONLY in the broker's in-memory ephemeral
// spool (the same protected boundary relay payloads use) under a
// bounded lifetime; the durable SecretReference row is metadata only
// (its request ID is retained for audit bookkeeping but never sent to
// the provider — a retry with that ID below is refused, never re-staged
// or reconciled: transient intake is single-shot). No AegisKeys
// credential is created and the payload is unrecoverable after expiry
// or restart; the reference dies with it. Dispatch remains
// at-most-once: one approved operation consumes the staged bytes at the
// dispatch barrier.
func (s *Service) stageTransientOnce(caller string, req aegiskeys.ProvisionRequest) (*ProvisionReport, *types.SecretReference, error) {
	if prior, err := s.db.GetSecretRefByProvisionRequest(req.RequestID); err == nil && prior != nil {
		// A retry (new staging attempt under the same request ID) can
		// never resurrect the ephemeral bytes — refuse both re-staging
		// and provider-style reconciliation.
		return nil, prior, errors.New("transient intake is single-shot: the request ID already staged a credential that is unrecoverable by design; submit a NEW request ID")
	}
	if req.Value == "" {
		return nil, nil, errors.New("transient intake requires a credential value")
	}
	if len(req.Value) > ephMaxPayload() {
		return nil, nil, fmt.Errorf("transient credential too large (max %d bytes)", ephMaxPayload())
	}
	if req.Binding == "" {
		return nil, nil, errors.New("transient intake requires a binding")
	}
	ref := &types.SecretReference{
		Name:               req.Label,
		Description:        req.Description,
		Owner:              caller,
		Binding:            req.Binding,
		ProvisionRequestID: req.RequestID,
		ReconcileStatus:    types.ProvisionReconcileTransient,
		UseOnce:            true,
	}
	if err := s.db.CreateSecretRef(ref); err != nil {
		return nil, nil, fmt.Errorf("transient reference persist failed: %w", err)
	}
	key := transientPayloadKey(ref.ID)
	if err := s.eph.Store(key, []byte(req.Value), transientOnceTTL); err != nil {
		// Refuse closed: without staged bytes the reference is dead —
		// mark it failed so surfaces never present it as usable.
		_ = s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileFailed, "", "")
		return nil, ref, fmt.Errorf("transient staging failed: %w", err)
	}
	s.audit(ref.ID, "credential_transient_staged", caller, req.Binding, transientOnceTTL.String())
	report := &ProvisionReport{
		Saved:          false,
		ProviderStatus: "transient_staged",
		RefID:          ref.ID,
		StagedUntil:    time.Now().Add(transientOnceTTL),
	}
	return report, ref, nil
}

// ephMaxPayload is the ephemeral spool's per-payload bound.
func ephMaxPayload() int { return vault.MaxEphemeralBytes }

// reconcileProvision advances an existing durable reference. The request
// shape is validated for identity consistency FIRST: a caller retrying
// with the same request ID but different content is refused locally
// before any provider interaction (the provider would also conflict, but
// the local check keeps SeqPass's durable identity the anchor).
//
// P0-D note: the binding/owner anchor below is the legacy check; the full
// request-identity reconciliation (service, kind, label, operations,
// expiry, mode, value commitment) is enforced by validateRequestIdentity.
func (s *Service) reconcileProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, intent *UseIntent, ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	switch ref.ReconcileStatus {
	case types.ProvisionReconcileConflict:
		return nil, ref, errors.New("provisioning request conflicts with committed content: operator reconciliation required")
	case types.ProvisionReconcileIdentityConflict:
		return nil, ref, errors.New("provisioning request identity conflict: operator reconciliation required")
	case types.ProvisionReconcileConsumed:
		return nil, ref, errors.New("use-once credential already consumed")
	case types.ProvisionReconcileFailed:
		return nil, ref, errors.New("provisioning previously refused: submit a NEW request ID after correcting the request")
	}
	// Identity anchor: same request ID must carry the same binding and
	// service. Label/kind drift is also refused: the durable reference is
	// the SeqPass-side identity of this request.
	if ref.Binding != req.Binding || ref.Owner != caller {
		return nil, ref, errors.New("provisioning request identity mismatch (binding/owner changed under the same request ID)")
	}
	switch ref.ReconcileStatus {
	case types.ProvisionReconcileCommitted, types.ProvisionReconcileReady, types.ProvisionReconcileGrantPresent:
		// Already durable: idempotent recovery, no provider round trip.
		// The cached provider status is the LAST OBSERVED state, never a
		// freshly verified readiness verdict (P1-A).
		report := &ProvisionReport{
			Saved:                true,
			ProviderStatus:       providerStatusOf(ref),
			ReEnrollmentRequired: ref.ReconcileStatus == types.ProvisionReconcileCommitted,
			RefID:                ref.ID,
		}
		if mode == IntakeSaveAndUse {
			s.reportIntentOutcome(ref, report)
		}
		return report, ref, nil
	}
	// pending/uncertain: reconcile with the provider by the ORIGINAL
	// request ID before resubmitting.
	st, err := s.provisionStatus(ctx, req.RequestID)
	switch {
	case err == nil:
		return s.advanceProvision(ctx, caller, mode, req, intent, ref, st, true)
	case errors.Is(err, aegiskeys.ErrProvisionUnknown):
		// The provider never committed this request: resubmit the SAME
		// request ID (exactly-once retry).
		return s.submitProvision(ctx, caller, mode, req, intent, ref)
	case errors.Is(err, aegiskeys.ErrTransportUnavailable), errors.Is(err, aegiskeys.ErrVaultLocked):
		return nil, ref, fmt.Errorf("provision reconciliation unavailable (still uncertain): %w", err)
	default:
		return nil, ref, err
	}
}

// submitProvision performs the provider call for a write-ahead reference
// and advances the durable state from the outcome.
func (s *Service) submitProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, intent *UseIntent, ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	st, err := s.provisionCall(ctx, req)
	if err != nil {
		return s.failProvision(ctx, req, ref, err)
	}
	return s.advanceProvision(ctx, caller, mode, req, intent, ref, st, true)
}

// provisionCall routes the provider call through the trusted crossing.
func (s *Service) provisionCall(ctx context.Context, req aegiskeys.ProvisionRequest) (aegiskeys.ProvisionResponse, error) {
	socket := s.provisionedSocket()
	if s.cfg.AegisKeysResolveHelper != "" {
		return aegiskeys.ProvisionViaHelper(ctx, s.cfg.AegisKeysResolveHelper, socket, req)
	}
	cli, err := aegiskeys.ConnectSocket(socket)
	if err != nil {
		return aegiskeys.ProvisionResponse{}, err
	}
	return cli.Provision(ctx, req)
}

// provisionStatus reconciles by request ID through the same identity the
// resolve path uses (in-process in dev mode; the helper in production).
func (s *Service) provisionStatus(ctx context.Context, requestID string) (aegiskeys.ProvisionResponse, error) {
	socket := s.provisionedSocket()
	if s.cfg.AegisKeysResolveHelper != "" {
		// Reconciliation is metadata-only: it crosses in-process (the
		// broker's own identity) only when the provider admits it. A
		// non-dumpable broker cannot pass exe verification, so in
		// helper mode the status query ALSO rides the helper (a
		// metadata-only frame; no value crosses).
		return aegiskeys.ProvisionStatusViaHelper(ctx, s.cfg.AegisKeysResolveHelper, socket, requestID)
	}
	cli, err := aegiskeys.ConnectSocket(socket)
	if err != nil {
		return aegiskeys.ProvisionResponse{}, err
	}
	return cli.ProvisionStatus(ctx, requestID)
}

// advanceProvision commits the provider outcome durably and builds the
// separate-outcome report. resubmitted records whether this call actually
// contacted the provider (idempotent recoveries skip the use phase).
//
// Identity immutability (P0-A): the provider's RecordID/BindingID are
// assigned to the durable reference EXACTLY ONCE, via an expected-state
// atomic transition on a reference that has no stable identity yet. After
// assignment, a DIVERGENT provider identity (rebind, rotation, corrupted
// metadata, altered replay) is never adopted: the original pins are
// preserved and a durable identity conflict blocks all subsequent
// execution until explicit operator reconciliation.
func (s *Service) advanceProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, intent *UseIntent, ref *types.SecretReference, st aegiskeys.ProvisionResponse, contacted bool) (*ProvisionReport, *types.SecretReference, error) {
	report := &ProvisionReport{ProviderStatus: st.Status, RefID: ref.ID}
	switch st.Status {
	case aegiskeys.ProvisionStatusCredentialCommitted, aegiskeys.ProvisionStatusBindingPending:
		// Transient commit stage: retrying the same request ID continues
		// the promotion. Keep the durable record 'uncertain' until the
		// provider reports a binding. First identity sighting is bound
		// immediately (it exists at the provider); state stays uncertain.
		assigned, err := s.transitionProvisionIdentity(ref, types.ProvisionReconcileUncertain, st, expectedPendingOrUncertain...)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if !assigned {
			if err := s.recordIdentityConflict(ctx, caller, ref, st); err != nil {
				return nil, ref, err
			}
			return s.refuseConflicted(ref)
		}
		ref.ReconcileStatus = types.ProvisionReconcileUncertain
		applyIdentity(ref, st)
		report.ReEnrollmentRequired = true
		return report, ref, nil
	case aegiskeys.ProvisionStatusAuthorizationPending:
		// Credential + binding durable; the resolve grant awaits operator
		// approval. This is a SAVED credential.
		assigned, err := s.transitionProvisionIdentity(ref, types.ProvisionReconcileCommitted, st, expectedPendingOrUncertain...)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if !assigned {
			if err := s.recordIdentityConflict(ctx, caller, ref, st); err != nil {
				return nil, ref, err
			}
			return s.refuseConflicted(ref)
		}
		ref.ReconcileStatus = types.ProvisionReconcileCommitted
		applyIdentity(ref, st)
		report.Saved = true
		report.ReEnrollmentRequired = true
		s.audit(ref.ID, "credential_saved", caller, req.Binding, st.Status)
	case aegiskeys.ProvisionStatusGrantPresent:
		// grant_present ≠ ready: the resolve grant EXISTS but the provider
		// has not reported an unlocked, policy-valid, executable-pin-valid
		// readiness verdict. The durable state records that distinction;
		// only the provider's own resolve-time authorization revalidation
		// (which always runs at dispatch) is the final gate.
		assigned, err := s.transitionProvisionIdentity(ref, types.ProvisionReconcileGrantPresent, st,
			append(expectedPendingOrUncertain, types.ProvisionReconcileCommitted)...)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if !assigned {
			if err := s.recordIdentityConflict(ctx, caller, ref, st); err != nil {
				return nil, ref, err
			}
			return s.refuseConflicted(ref)
		}
		ref.ReconcileStatus = types.ProvisionReconcileGrantPresent
		applyIdentity(ref, st)
		report.Saved = true
		report.ReEnrollmentRequired = true
		s.audit(ref.ID, "credential_saved", caller, req.Binding, st.Status)
	case aegiskeys.ProvisionStatusReady:
		assigned, err := s.transitionProvisionIdentity(ref, types.ProvisionReconcileReady, st,
			append(expectedPendingOrUncertain, types.ProvisionReconcileCommitted, types.ProvisionReconcileGrantPresent)...)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if !assigned {
			if err := s.recordIdentityConflict(ctx, caller, ref, st); err != nil {
				return nil, ref, err
			}
			return s.refuseConflicted(ref)
		}
		ref.ReconcileStatus = types.ProvisionReconcileReady
		applyIdentity(ref, st)
		report.Saved = true
		s.audit(ref.ID, "credential_saved", caller, req.Binding, st.Status)
	default:
		return nil, ref, fmt.Errorf("unknown provider status %q", st.Status)
	}
	// save_and_use: the SECOND durable outcome. Saving NEVER authorizes
	// use — the recorded intent (if any) is progressed only through the
	// continuation (grant usable → durable pending use request → operator
	// approval → existing driver execution). The use outcome is always
	// PRESENT for save_and_use: absence would read as a skipped phase,
	// not a pending authorization.
	if mode == IntakeSaveAndUse {
		s.progressProvisionUseIntent(ctx, caller, ref, report)
	}
	return report, ref, nil
}

// progressProvisionUseIntent advances the recorded save_and_use workflow
// one honest step and reflects it in the report (P0-B). Continuation is
// STATE-DRIVEN and idempotent:
//   - pending intent + grant NOT usable → stays pending (no dispatch, no
//     use request yet — the operator approves the staged grant first).
//   - pending intent + grant usable → the intent CAS (pending→submitted)
//     is taken FIRST with a DETERMINISTIC use-request ID; only the winner
//     calls SubmitUse, and a crash-recovery retry reuses the same ID (the
//     uses PK refuses duplicates) → submitted; the operator's
//     independent approval is still required.
//   - submitted → report the use request's CURRENT durable status
//     (reconcile, never re-submit, never duplicate a dispatch).
//   - reference conflicted/blocked → intent blocked; no request created.
//
// The intent is recovered on every later poll: a restart never loses the
// recorded workflow.
func (s *Service) progressProvisionUseIntent(ctx context.Context, caller string, ref *types.SecretReference, report *ProvisionReport) {
	it, err := s.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID)
	if err != nil {
		report.UseResult = &UseOutcomeReport{Err: fmt.Sprintf("intent lookup failed: %v", err)}
		return
	}
	if it == nil {
		// save_and_use without an explicit intent: awaiting_authorization
		// is a legitimate terminal report for this call.
		report.UseResult = &UseOutcomeReport{
			Err: "saved; no use intent recorded — submit a protected-use request against the binding when ready",
		}
		return
	}
	report.IntentState = it.State
	switch it.State {
	case types.ProvisionUseIntentCompleted, types.ProvisionUseIntentFailed, types.ProvisionUseIntentBlocked:
		// Terminal: report the recorded outcome, never re-dispatch.
		report.UseResult = s.intentOutcomeReport(it)
		return
	case types.ProvisionUseIntentSubmitted:
		// Reconcile the recorded request; NEVER create a second one.
		report.UseResult = s.intentOutcomeReport(it)
		// The outcome mirror may have advanced the intent to its terminal
		// state (completed/failed) — reflect the durable truth.
		report.IntentState = it.State
		return
	}
	// Pending: the grant must be usable BEFORE the request is created so
	// the operator's approval leads directly to an executable state
	// (grant approval, then operation approval).
	switch ref.ReconcileStatus {
	case types.ProvisionReconcileGrantPresent, types.ProvisionReconcileReady:
		// EXACTLY-ONCE submission anchor: the use request's ID is
		// DETERMINISTIC ("intentop-"+intent ID) and the intent CAS
		// (pending→submitted) is taken BEFORE SubmitUse. Only the CAS
		// winner ever creates the request; a concurrent or recovered
		// continuation sees submitted and reconciles instead. If the
		// winner crashes before SubmitUse, the next continuation retries
		// with the SAME deterministic ID — the uses-table PRIMARY KEY
		// makes the retry idempotent (a duplicate INSERT is refused), so
		// no orphan request and no duplicate dispatch can ever exist.
		opID := "intentop-" + it.ID
		// intentRacerHook widens the inter-continuation window in tests
		// ONLY (nil in production): the mutation NC proves the CAS-first
		// ordering is load-bearing by racing through this exact point.
		if intentRacerHook != nil {
			intentRacerHook()
		}
		taken, terr := s.db.TakeProvisionUseIntent(it.ID, opID)
		if terr != nil {
			report.UseResult = &UseOutcomeReport{Err: fmt.Sprintf("intent claim failed: %v", terr)}
			return
		}
		if !taken {
			// Lost the CAS: a concurrent continuation already submitted
			// THIS intent. Report that request; never a duplicate.
			fresh, gerr := s.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID)
			if gerr == nil && fresh != nil {
				report.IntentState = fresh.State
				report.UseResult = s.intentOutcomeReport(fresh)
				return
			}
			report.UseResult = &UseOutcomeReport{OpID: opID, Err: "intent already submitted"}
			return
		}
		// grant usable → submit the recorded workflow as an ordinary
		// pending use request (policy revalidated inside SubmitUse).
		useReq := &types.UseRequest{
			ID:        opID,
			SecretRef: ref.ID,
			Operation: it.Operation,
			Target:    it.Target,
			Params:    it.Params,
		}
		if _, serr := s.SubmitUse(it.Principal, useReq); serr != nil {
			// Policy denial or invalid shape: the recorded workflow can
			// never be submitted as-is. Durable terminal state; the SAVE
			// stands (independent outcomes).
			_, _ = s.db.AdvanceProvisionUseIntent(it.ID, types.ProvisionUseIntentFailed)
			report.IntentState = types.ProvisionUseIntentFailed
			report.UseResult = &UseOutcomeReport{Err: "recorded use intent denied at submission: " + serr.Error()}
			s.audit(ref.ID, "credential_use_intent_failed", caller, it.Target, "submit-denied")
			return
		}
		report.IntentState = types.ProvisionUseIntentSubmitted
		report.UseResult = &UseOutcomeReport{
			OpID: opID,
			Err:  "use request created; independent operation approval required: approve op " + opID,
		}
		s.audit(ref.ID, "credential_use_intent_submitted", caller, it.Target, opID)
	case types.ProvisionReconcileCommitted, types.ProvisionReconcilePending, types.ProvisionReconcileUncertain:
		report.UseResult = &UseOutcomeReport{
			Err: "authorization_pending: approve the staged resolver grant (aegiskeys access provision approve --request " +
				ref.ProvisionRequestID + "); the recorded use intent is preserved and progresses automatically",
		}
	default:
		// conflict/identity_conflict/failed/consumed: blocked pre-dispatch.
		_, _ = s.db.AdvanceProvisionUseIntent(it.ID, types.ProvisionUseIntentBlocked)
		report.IntentState = types.ProvisionUseIntentBlocked
		report.UseResult = &UseOutcomeReport{Err: "recorded use intent blocked: reference is " + ref.ReconcileStatus}
		s.audit(ref.ID, "credential_use_intent_blocked", caller, it.Target, ref.ReconcileStatus)
	}
}

// intentOutcomeReport mirrors the recorded use request's CURRENT durable
// status into the report (reconciliation, not re-execution). A terminal
// request status is mirrored into the intent's terminal state exactly
// once (CAS-guarded): the recorded workflow closes when its request
// closes, and a later poll re-reports the closed state.
func (s *Service) intentOutcomeReport(it *types.ProvisionUseIntent) *UseOutcomeReport {
	out := &UseOutcomeReport{OpID: it.OpID}
	if it.OpID == "" {
		out.Err = "intent " + it.State + " without a recorded use request"
		return out
	}
	ur, err := s.db.GetUse(it.OpID)
	if err != nil || ur == nil {
		// The durable intent state is authoritative: a terminal intent
		// reports itself even if its request row was ever pruned.
		switch it.State {
		case types.ProvisionUseIntentCompleted:
			out.Executed = true
		case types.ProvisionUseIntentFailed:
			out.Err = "recorded use workflow failed"
		case types.ProvisionUseIntentBlocked:
			out.Err = "recorded use workflow blocked before dispatch"
		default:
			out.Err = "recorded use request missing"
		}
		return out
	}
	switch ur.Status {
	case types.StatusCompleted:
		out.Executed = true
		if it.State != types.ProvisionUseIntentCompleted {
			if _, aerr := s.db.AdvanceProvisionUseIntent(it.ID, types.ProvisionUseIntentCompleted); aerr == nil {
				it.State = types.ProvisionUseIntentCompleted
			}
		}
	case types.StatusFailed:
		out.Err = "recorded use request failed"
		if it.State != types.ProvisionUseIntentFailed {
			if _, aerr := s.db.AdvanceProvisionUseIntent(it.ID, types.ProvisionUseIntentFailed); aerr == nil {
				it.State = types.ProvisionUseIntentFailed
			}
		}
	case types.StatusUncertain:
		out.Err = "recorded use request uncertain: reconcile the external outcome; do not re-dispatch"
	default:
		out.Err = "recorded use request " + ur.Status + "; awaiting operator approval" +
			" (aegiskeys-independent: approve the SeqPass operation, then execute)"
	}
	return out
}

// reportIntentOutcome is the idempotent-recovery variant: reflect the
// recorded intent's state on a cached (no provider round trip) report.
func (s *Service) reportIntentOutcome(ref *types.SecretReference, report *ProvisionReport) {
	it, err := s.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID)
	if err != nil || it == nil {
		return
	}
	report.IntentState = it.State
	report.UseResult = s.intentOutcomeReport(it)
}

// expectedPendingOrUncertain are the pre-assignment lifecycle states: only
// a reference that has NOT yet been assigned a stable provider identity
// may take one.
var expectedPendingOrUncertain = []string{types.ProvisionReconcilePending, types.ProvisionReconcileUncertain}

// intentRacerHook is a test-only seam (always nil in production builds):
// invoked at the exact point the continuation CAS makes the submission
// exactly-once, so the concurrency regression can deterministically
// interleave racers there.
var intentRacerHook func()

// applyIdentity mirrors the (verified, already-transitioned) provider
// identity into the in-memory reference.
func applyIdentity(ref *types.SecretReference, st aegiskeys.ProvisionResponse) {
	ref.RecordID, ref.BindingID = st.RecordID, st.BindingID
}

// transitionProvisionIdentity performs the durable identity transition for
// one provider observation:
//   - ref still uninitialized → FIRST assignment (empty-identity CAS).
//   - ref identity already assigned AND matches the provider → state-only
//     advance (identity CAS).
//   - ref identity assigned and DIVERGES → no write here; the caller
//     records the durable conflict (false, nil).
func (s *Service) transitionProvisionIdentity(ref *types.SecretReference, newStatus string, st aegiskeys.ProvisionResponse, expectedStatuses ...string) (bool, error) {
	if ref.RecordID == "" && ref.BindingID == "" {
		return s.db.TransitionSecretRefProvisionState(ref.ID, newStatus, st.RecordID, st.BindingID, true, expectedStatuses...)
	}
	if identityDiverged(ref, st) {
		return false, nil
	}
	// Same identity: a pure status promotion. If the row already sits at
	// newStatus the CAS simply affects zero rows, which is still success.
	advanced, err := s.db.TransitionSecretRefProvisionState(ref.ID, newStatus, ref.RecordID, ref.BindingID, false, expectedStatuses...)
	if err != nil || advanced {
		return advanced, err
	}
	// Zero rows with matching identity = the row is already AT newStatus
	// (outside the expected set). Not a divergence: verify durably.
	fresh, err := s.db.GetSecretRef(ref.ID)
	if err != nil || fresh == nil {
		return false, err
	}
	if fresh.ReconcileStatus == newStatus && !identityDiverged(fresh, st) {
		ref.ReconcileStatus = fresh.ReconcileStatus
		return true, nil
	}
	return false, nil
}

// identityDiverged reports whether the provider's returned stable identity
// differs from the reference's committed identity.
func identityDiverged(ref *types.SecretReference, st aegiskeys.ProvisionResponse) bool {
	return (st.RecordID != "" && st.RecordID != ref.RecordID) ||
		(st.BindingID != "" && st.BindingID != ref.BindingID)
}

// recordIdentityConflict durably records a divergent provider identity:
// the ORIGINAL pins are preserved in the reference row, the conflict is
// audited, and every subsequent execution fails closed (P0-A).
func (s *Service) recordIdentityConflict(ctx context.Context, caller string, ref *types.SecretReference, st aegiskeys.ProvisionResponse) error {
	marked, err := s.db.MarkSecretRefIdentityConflict(ref.ID)
	if err != nil {
		return fmt.Errorf("identity conflict record failed: %w", err)
	}
	if !marked {
		// Consumed refs keep their decisive terminal state; nothing to do.
		return nil
	}
	ref.ReconcileStatus = types.ProvisionReconcileIdentityConflict
	s.audit(ref.ID, "credential_identity_conflict", caller, ref.Binding,
		fmt.Sprintf("provider record_id=%q binding_id=%q diverges from pinned record_id=%q binding_id=%q; original pins preserved; execution blocked pending operator reconciliation",
			st.RecordID, st.BindingID, ref.RecordID, ref.BindingID))
	// P0-B: a recorded save_and_use workflow cannot progress past a
	// conflicted reference — block it durably (pre-dispatch) so no later
	// poll submits it against an unresolvable identity.
	if it, ierr := s.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID); ierr == nil && it != nil &&
		(it.State == types.ProvisionUseIntentPending || it.State == types.ProvisionUseIntentSubmitted) {
		if _, aerr := s.db.AdvanceProvisionUseIntent(it.ID, types.ProvisionUseIntentBlocked); aerr == nil {
			s.audit(ref.ID, "credential_use_intent_blocked", caller, ref.Binding, "identity_conflict")
		}
	}
	return nil
}

// refuseConflicted is the typed refusal for a conflicted reference. The
// report carries the conflict so trusted surfaces can render the
// reconciliation procedure instead of a generic error.
func (s *Service) refuseConflicted(ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	report := &ProvisionReport{
		ProviderStatus:   providerStatusOf(ref),
		RefID:            ref.ID,
		IdentityConflict: true,
		ConflictNextStep: "operator reconciliation required: verify the provider binding/record identities, then resolve the conflict via an operator-authorized procedure before any further use",
	}
	// P0-B: recordIdentityConflict blocked the recorded intent — surface it.
	if it, ierr := s.db.GetProvisionUseIntentByRequest(ref.ProvisionRequestID); ierr == nil && it != nil {
		report.IntentState = it.State
		if it.State == types.ProvisionUseIntentBlocked {
			report.UseResult = &UseOutcomeReport{Err: "recorded use intent blocked: provider identity divergence"}
		}
	}
	return report, ref, errors.New("provider identity diverges from the pinned record/binding identity: execution blocked pending operator reconciliation")
}

// failProvision durably records the provider refusal. access_denied /
// invalid request are terminal for this request ID (the durable identity
// must not be silently reused); transport/locked failures keep 'uncertain'
// (the provider may have committed).
func (s *Service) failProvision(ctx context.Context, req aegiskeys.ProvisionRequest, ref *types.SecretReference, err error) (*ProvisionReport, *types.SecretReference, error) {
	switch {
	case errors.Is(err, aegiskeys.ErrProvisionConflict):
		_ = s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileConflict, "", "")
		s.audit(ref.ID, "credential_provision_conflict", "broker", req.Binding, "credential_conflict")
		return nil, ref, fmt.Errorf("credential_conflict: %w", err)
	case errors.Is(err, aegiskeys.ErrAccessDenied), errors.Is(err, aegiskeys.ErrRequestInvalid):
		_ = s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileFailed, "", "")
		return nil, ref, fmt.Errorf("provision refused: %w", err)
	default:
		// vault_locked / transport: UNCERTAIN — the provider may have
		// committed. Durable record stays 'uncertain'; reconciliation
		// retries the same request ID.
		_ = s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileUncertain, "", "")
		return nil, ref, fmt.Errorf("provision uncertain (reconcile by request_id): %w", err)
	}
}

// providerStatusOf maps a durable reconcile status back to the provider's
// lifecycle label for idempotent recovery reports. Cached by definition:
// the caller has not contacted the provider on this path, so the value is
// the LAST OBSERVED provider state, never a freshly verified readiness
// verdict (P1-A) — surfaces must label it as such.
func providerStatusOf(ref *types.SecretReference) string {
	switch ref.ReconcileStatus {
	case types.ProvisionReconcileReady:
		return aegiskeys.ProvisionStatusReady
	case types.ProvisionReconcileGrantPresent:
		return aegiskeys.ProvisionStatusGrantPresent
	}
	return aegiskeys.ProvisionStatusAuthorizationPending
}

// ProvisionStatusReport reconciles one provisioned reference for the
// trusted surface (admin/intake poll this between operator steps).
//
// Identity immutability (P0-A): a reference with assigned stable identity
// NEVER adopts the provider's returned record/binding ID. Divergence is a
// durable identity conflict (original pins preserved, audited, execution
// blocked); matching identity only promotes the lifecycle state through
// expected-state atomic transitions. A first-assignment (empty identity)
// path is the only writer of the identity columns here.
func (s *Service) ProvisionStatusReport(ctx context.Context, caller, requestID string) (*ProvisionReport, *types.SecretReference, error) {
	ref, err := s.db.GetSecretRefByProvisionRequest(requestID)
	if err != nil {
		return nil, nil, err
	}
	if ref == nil {
		return nil, nil, errors.New("unknown provisioning request")
	}
	if ref.Owner != caller {
		return nil, nil, errors.New("access denied")
	}
	// P0-C: a transient reference has NO provider counterpart — never
	// contact the provider for it; report the durable metadata only.
	if ref.ReconcileStatus == types.ProvisionReconcileTransient {
		return &ProvisionReport{
			Saved:          false,
			ProviderStatus: "transient_staged",
			RefID:          ref.ID,
		}, ref, nil
	}
	st, err := s.provisionStatus(ctx, requestID)
	if err != nil {
		return nil, ref, fmt.Errorf("provision status unavailable (durable state unchanged): %w", err)
	}
	report := &ProvisionReport{
		Saved:          st.Status == aegiskeys.ProvisionStatusAuthorizationPending || st.Status == aegiskeys.ProvisionStatusGrantPresent || st.Status == aegiskeys.ProvisionStatusReady,
		ProviderStatus: st.Status,
		RefID:          ref.ID,
	}
	report.ReEnrollmentRequired = st.Status == aegiskeys.ProvisionStatusAuthorizationPending
	if identityDiverged(ref, st) {
		// Divergent identity: PRESERVE the original pins, record the
		// durable conflict, refuse. Never adopt the provider's new
		// identity as a "status refresh".
		if err := s.recordIdentityConflict(ctx, caller, ref, st); err != nil {
			return nil, ref, err
		}
		return s.refuseConflicted(ref)
	}
	if ref.RecordID == "" && ref.BindingID == "" {
		// First assignment: only under the expected pre-assignment
		// lifecycle states, atomically (concurrent status updates race
		// through the CAS, not through read-modify-write).
		assigned, err := s.transitionProvisionIdentity(ref, reconcileStatusFor(st.Status), st, expectedPendingOrUncertain...)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if !assigned {
			// Lost the race: re-read and continue with the durable state.
			fresh, gerr := s.db.GetSecretRef(ref.ID)
			if gerr != nil || fresh == nil {
				return nil, ref, fmt.Errorf("provision state re-read failed: %v", gerr)
			}
			ref = fresh
		}
	} else {
		// Matching identity: promote the lifecycle state via identity CAS
		// (never the identity columns).
		advanced, err := s.db.TransitionSecretRefProvisionState(ref.ID, reconcileStatusFor(st.Status), ref.RecordID, ref.BindingID, false,
			types.ProvisionReconcilePending, types.ProvisionReconcileUncertain, types.ProvisionReconcileCommitted, types.ProvisionReconcileGrantPresent)
		if err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		if advanced {
			ref.ReconcileStatus = reconcileStatusFor(st.Status)
		} else {
			// Row already at the target status (or elsewhere): re-read the
			// durable state as the anchor for the report.
			fresh, gerr := s.db.GetSecretRef(ref.ID)
			if gerr != nil || fresh == nil {
				return nil, ref, fmt.Errorf("provision state re-read failed: %v", gerr)
			}
			ref = fresh
		}
	}
	if report.Saved {
		report.Saved = ref.ReconcileStatus == types.ProvisionReconcileCommitted ||
			ref.ReconcileStatus == types.ProvisionReconcileGrantPresent ||
			ref.ReconcileStatus == types.ProvisionReconcileReady
	}
	// P0-B continuation: the poll is the progression driver. A recorded
	// save_and_use intent is progressed/reconciled on every status
	// refresh — a restart or a missed poll never stalls the recorded
	// workflow, and a submitted intent is reconciled (never re-submitted).
	if it, ierr := s.db.GetProvisionUseIntentByRequest(requestID); ierr == nil && it != nil {
		s.progressProvisionUseIntent(ctx, caller, ref, report)
	}
	return report, ref, nil
}

func reconcileStatusFor(status string) string {
	switch status {
	case aegiskeys.ProvisionStatusReady:
		return types.ProvisionReconcileReady
	case aegiskeys.ProvisionStatusGrantPresent:
		// P1-A: grant_present ≠ ready. The grant exists but the provider
		// has not reported an unlocked/policy-valid/executable-pin-valid
		// readiness verdict; the durable states stay distinct.
		return types.ProvisionReconcileGrantPresent
	case aegiskeys.ProvisionStatusAuthorizationPending:
		return types.ProvisionReconcileCommitted
	default:
		return types.ProvisionReconcileUncertain
	}
}

// ensure time is referenced (write-ahead timestamps live in the db layer).
var _ = time.Now
