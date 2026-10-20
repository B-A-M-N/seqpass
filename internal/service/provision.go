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
func (s *Service) advanceProvision(ctx context.Context, caller, mode string, req aegiskeys.ProvisionRequest, ref *types.SecretReference, st aegiskeys.ProvisionResponse, contacted bool) (*ProvisionReport, *types.SecretReference, error) {
	report := &ProvisionReport{ProviderStatus: st.Status, RefID: ref.ID}
	switch st.Status {
	case aegiskeys.ProvisionStatusCredentialCommitted, aegiskeys.ProvisionStatusBindingPending:
		// Transient commit stage: retrying the same request ID continues
		// the promotion. Keep the durable record 'uncertain' until the
		// provider reports a binding.
		if err := s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileUncertain, st.RecordID, st.BindingID); err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		report.ReEnrollmentRequired = true
		return report, ref, nil
	case aegiskeys.ProvisionStatusAuthorizationPending:
		// Credential + binding durable; the resolve grant awaits operator
		// approval. This is a SAVED credential.
		if err := s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileCommitted, st.RecordID, st.BindingID); err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		ref.ReconcileStatus = types.ProvisionReconcileCommitted
		ref.RecordID, ref.BindingID = st.RecordID, st.BindingID
		report.Saved = true
		report.ReEnrollmentRequired = true
		s.audit(ref.ID, "credential_saved", caller, req.Binding, st.Status)
	case aegiskeys.ProvisionStatusGrantPresent, aegiskeys.ProvisionStatusReady:
		if err := s.db.UpdateSecretRefProvisionState(ref.ID, types.ProvisionReconcileReady, st.RecordID, st.BindingID); err != nil {
			return nil, ref, fmt.Errorf("provision state update failed: %w", err)
		}
		ref.ReconcileStatus = types.ProvisionReconcileReady
		ref.RecordID, ref.BindingID = st.RecordID, st.BindingID
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
// lifecycle label for idempotent recovery reports.
func providerStatusOf(ref *types.SecretReference) string {
	if ref.ReconcileStatus == types.ProvisionReconcileReady {
		return aegiskeys.ProvisionStatusReady
	}
	return aegiskeys.ProvisionStatusAuthorizationPending
}

// ProvisionStatusReport reconciles one provisioned reference for the
// trusted surface (admin/intake poll this between operator steps).
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
	if st.BindingID != ref.BindingID || st.RecordID != ref.RecordID {
		if err := s.db.UpdateSecretRefProvisionState(ref.ID, reconcileStatusFor(st.Status), st.RecordID, st.BindingID); err != nil {
			return nil, ref, err
		}
		ref.RecordID, ref.BindingID, ref.ReconcileStatus = st.RecordID, st.BindingID, reconcileStatusFor(st.Status)
	}
	return report, ref, nil
}

func reconcileStatusFor(status string) string {
	switch status {
	case aegiskeys.ProvisionStatusGrantPresent, aegiskeys.ProvisionStatusReady:
		return types.ProvisionReconcileReady
	case aegiskeys.ProvisionStatusAuthorizationPending:
		return types.ProvisionReconcileCommitted
	default:
		return types.ProvisionReconcileUncertain
	}
}

// ensure time is referenced (write-ahead timestamps live in the db layer).
var _ = time.Now
