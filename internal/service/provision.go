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
)

// Trusted-intake persistence modes.
const (
	// IntakeUseOnce: the credential is saved in AegisKeys and consumable
	// for exactly one authorized execution.
	IntakeUseOnce = "use_once"
	// IntakeSaveOnly: the credential is saved and bound; no immediate use.
	IntakeSaveOnly = "save_only"
	// IntakeSaveAndUse: save, then attempt an immediate authorized use —
	// reported as TWO separate durable outcomes (storage vs execution).
	IntakeSaveAndUse = "save_and_use"
)

// validIntakePersistence fail-closes the mode selection.
func validIntakePersistence(mode string) bool {
	switch mode {
	case IntakeUseOnce, IntakeSaveOnly, IntakeSaveAndUse:
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
}

// UseOutcomeReport is the execution outcome of the immediate use attempt
// (save_and_use only): a distinct durable event from the save.
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
// Reconcile-before-recreate: an existing durable reference under the same
// request ID drives the whole flow — pending/uncertain reconcile by
// status (resubmitting the SAME request ID when the provider never
// committed), committed/ready return idempotently, conflict/failed fail
// closed until the operator reconciles.
func (s *Service) ProvisionCredential(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest) (*ProvisionReport, *types.SecretReference, error) {
	if !validIntakePersistence(mode) {
		return nil, nil, fmt.Errorf("unknown persistence mode %q: use use_once, save_only or save_and_use", mode)
	}
	if err := aegiskeys.ValidProvisionRequest(req); err != nil {
		return nil, nil, err
	}

	ref, err := s.db.GetSecretRefByProvisionRequest(req.RequestID)
	if err != nil {
		return nil, nil, fmt.Errorf("provision lookup failed: %w", err)
	}
	if ref != nil {
		return s.reconcileProvision(ctx, caller, mode, req, ref)
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
	return s.submitProvision(ctx, caller, mode, req, ref)
}

// reconcileProvision advances an existing durable reference. The request
// shape is validated for identity consistency FIRST: a caller retrying
// with the same request ID but different content is refused locally
// before any provider interaction (the provider would also conflict, but
// the local check keeps SeqPass's durable identity the anchor).
func (s *Service) reconcileProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	switch ref.ReconcileStatus {
	case types.ProvisionReconcileConflict:
		return nil, ref, errors.New("provisioning request conflicts with committed content: operator reconciliation required")
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
	case types.ProvisionReconcileCommitted, types.ProvisionReconcileReady:
		// Already durable: idempotent recovery, no provider round trip.
		return &ProvisionReport{
			Saved:                true,
			ProviderStatus:       providerStatusOf(ref),
			ReEnrollmentRequired: ref.ReconcileStatus == types.ProvisionReconcileCommitted,
			RefID:                ref.ID,
		}, ref, nil
	}
	// pending/uncertain: reconcile with the provider by the ORIGINAL
	// request ID before resubmitting.
	st, err := s.provisionStatus(ctx, req.RequestID)
	switch {
	case err == nil:
		return s.advanceProvision(ctx, caller, mode, req, ref, st, true)
	case errors.Is(err, aegiskeys.ErrProvisionUnknown):
		// The provider never committed this request: resubmit the SAME
		// request ID (exactly-once retry).
		return s.submitProvision(ctx, caller, mode, req, ref)
	case errors.Is(err, aegiskeys.ErrTransportUnavailable), errors.Is(err, aegiskeys.ErrVaultLocked):
		return nil, ref, fmt.Errorf("provision reconciliation unavailable (still uncertain): %w", err)
	default:
		return nil, ref, err
	}
}

// submitProvision performs the provider call for a write-ahead reference
// and advances the durable state from the outcome.
func (s *Service) submitProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	st, err := s.provisionCall(ctx, req)
	if err != nil {
		return s.failProvision(ctx, req, ref, err)
	}
	return s.advanceProvision(ctx, caller, mode, req, ref, st, true)
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
func (s *Service) advanceProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, ref *types.SecretReference, st aegiskeys.ProvisionResponse, contacted bool) (*ProvisionReport, *types.SecretReference, error) {
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
	// save_and_use: the SECOND durable outcome. Only a ready credential
	// can be used immediately; otherwise the report carries the saved
	// state with an explicit non-executed use outcome — the operator
	// approves the staged grant, and the normal protected-use flow
	// executes later. The use outcome is always PRESENT for save_and_use:
	// absence would read as a skipped phase, not a pending authorization.
	if mode == IntakeSaveAndUse {
		if ref.ReconcileStatus != types.ProvisionReconcileReady {
			report.UseResult = &UseOutcomeReport{
				Executed: false,
				Err:      "authorization_pending: approve the staged resolver grant, then submit a protected-use request against the binding",
			}
			return report, ref, nil
		}
		report.UseResult = s.immediateUse(ctx, caller, req, ref)
	}
	return report, ref, nil
}

// expectedPendingOrUncertain are the pre-assignment lifecycle states: only
// a reference that has NOT yet been assigned a stable provider identity
// may take one.
var expectedPendingOrUncertain = []string{types.ProvisionReconcilePending, types.ProvisionReconcileUncertain}

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
	return nil
}

// refuseConflicted is the typed refusal for a conflicted reference. The
// report carries the conflict so trusted surfaces can render the
// reconciliation procedure instead of a generic error.
func (s *Service) refuseConflicted(ref *types.SecretReference) (*ProvisionReport, *types.SecretReference, error) {
	return &ProvisionReport{
		ProviderStatus:   providerStatusOf(ref),
		RefID:            ref.ID,
		IdentityConflict: true,
		ConflictNextStep: "operator reconciliation required: verify the provider binding/record identities, then resolve the conflict via an operator-authorized procedure before any further use",
	}, ref, errors.New("provider identity diverges from the pinned record/binding identity: execution blocked pending operator reconciliation")
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

// immediateUse executes the immediate-use half of save_and_use through the
// normal protected-use authorization path. This implementation defers to
// the existing flow: an immediate use still requires an APPROVED operation
// (the approval machinery is unchanged — provisioning never grants live
// authorization), so the report's UseResult states that no execution was
// possible yet, with the exact next step. It never fabricates an
// execution outcome.
func (s *Service) immediateUse(ctx context.Context, caller string, req aegiskeys.ProvisionRequest, ref *types.SecretReference) *UseOutcomeReport {
	s.audit(ref.ID, "credential_use_deferred", caller, req.Binding, "authorization_pending")
	return &UseOutcomeReport{
		Executed: false,
		Err:      "authorization_pending: submit a protected-use request against the binding; provisioning never grants live authorization",
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
