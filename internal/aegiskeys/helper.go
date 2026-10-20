package aegiskeys

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// Credential-resolution helper protocol (P0-1).
//
// The long-lived SeqPass broker sets PR_SET_DUMPABLE=0 (§11 crash-output
// control: it stages relay payloads in memory, and non-dumpability is the
// only mechanism that also blocks piped core collectors and unprivileged
// ptrace). AegisKeys authenticates Unix-socket peers by reading
// /proc/<pid>/exe — which the kernel refuses for a non-dumpable process
// even to the same UID — so an in-broker resolve fails at the
// peer-identity layer before any grant is consulted.
//
// The fix is NOT to weaken the broker's non-dumpability. Instead the
// broker resolves each credential through a short-lived helper process:
//
//   - The helper is the same SeqPass executable running the
//     `resolve-helper` subcommand. It is a separate, explicitly pinned
//     executable identity in the AegisKeys grant model (UID + executable
//     path [+ hash]) — never an agent-supplied path or UID.
//   - It is spawned only by the trusted broker's authorized execution
//     path, once per approved operation, with a private CLOEXEC
//     socketpair inherited as fd 3. It never listens; direct agent
//     connections are unrepresentable.
//   - It carries binding identity, authorized operation, and operation ID
//     (all three hash-pinned by the SeqPass approval) — never secrets —
//     over the inherited descriptor. Credential material returns only
//     into the broker's trusted execution boundary on the same
//     descriptor; stdout/stderr carry nothing.
//   - Core dumps are disabled via RLIMIT_CORE=0 only. PR_SET_DUMPABLE
//     stays AT THE DEFAULT (1): the helper's whole purpose is that
//     AegisKeys can verify /proc/<pid>/exe. A crash therefore cannot
//     persist the single in-flight credential to disk (the rlimit blocks
//     file-backed cores; a piped collector receives a heap holding at
//     most the one in-flight credential), while same-UID process-memory
//     exposure remains possible for the helper's millisecond-scale
//     lifetime. In the isolated topology the helper runs as the trusted
//     service UID, whose own domain is the credential boundary anyway;
//     the agent UID cannot ptrace it. In the documented best-effort
//     same-user mode the helper adds no agent-side protection — nothing
//     in that mode does.
//   - Minimal lifetime: one request, one response, exit.
//
// P0-3 provisioning rides the same mechanism: HelperRequest.Provision
// switches the exchange to trusted provisioning — the credential VALUE
// crosses on the same private descriptor, the helper forwards it to the
// provider's /v3/intake/credentials under the helper's PROVISIONING grant
// (a distinct executable grant from the resolve grant), and only metadata
// returns. The broker-side entry is ProvisionViaHelper; the same
// spawn/reap discipline (kill+Wait exactly once on every path) applies.
//
// Approval-bypass review: the helper is not an authorization surface. It
// performs no approval decisions and grants nothing; it only forwards the
// already-approved (binding, operation, operation_id) triple to AegisKeys,
// whose grant + operation-allowlist enforcement is unchanged. A same-user
// process could spawn the helper with its own request, but in the isolated
// topology it would then authenticate with the agent UID, which no helper
// grant admits.

// helperMaxRequestBytes bounds the framed request (binding + operation +
// operation ID are bounded strings; 4KiB is generous). Provisioning
// requests (below) carry the credential value across the same crossing and
// use their own bound.
const helperMaxRequestBytes = 4096

// helperMaxProvisionRequestBytes bounds a provisioning request frame: the
// provider's 32KiB value bound plus request metadata slack.
const helperMaxProvisionRequestBytes = MaxProvisionValueLen + 4096

// helperMaxResponseBytes bounds the framed response: the credential wire
// bounds (maxValueBytes) plus framing slack for components.
const helperMaxResponseBytes = maxValueBytes + 4096

// HelperRequest is the framed request the broker writes to the inherited
// descriptor. No field is ever a secret: binding identity, logical
// operation, correlation token, and the hardened-parent attestation
// (nonce + ed25519 signature over AttestCanonicalString, made by the
// NON-DUMPABLE executor with its in-memory key). The signing key never
// crosses this protocol — the helper carries the attestation, it does not
// hold the key.
type HelperRequest struct {
	Binding     string `json:"binding"`
	Operation   string `json:"operation"`
	OperationID string `json:"operation_id,omitempty"`
	// Stable identity pins (P0-3 rebind protection): carried through to
	// the provider's resolve request so a rebind of the binding NAME
	// cannot silently redirect an approved operation. Empty on pre-P0-3
	// refs.
	BindingID   string `json:"binding_id,omitempty"`
	RecordID    string `json:"record_id,omitempty"`
	AttestNonce string `json:"attest_nonce,omitempty"`
	AttestSig   []byte `json:"attest_sig,omitempty"`
	// Provision, when non-nil, switches this helper exchange from resolve
	// to trusted provisioning (P0-3): the same private inherited
	// descriptor is the trusted crossing for the credential VALUE. The
	// helper performs no persistence decisions — it forwards the
	// already-trusted request to AegisKeys' /v3/intake/credentials under
	// the helper executable's provisioning grant, and returns only
	// metadata. Never agent-reachable: this field can only be populated by
	// the broker's trusted intake execution path.
	Provision *HelperProvisionRequest `json:"provision,omitempty"`
	// StatusRequest, when non-nil, is a METADATA-ONLY reconciliation
	// exchange: GET /v3/intake/requests/<id> with no credential material
	// in either direction. In helper mode the broker cannot query
	// provisioning status directly (exe verification), so reconciliation
	// rides the same trusted crossing.
	StatusRequest *HelperStatusRequest `json:"status_request,omitempty"`
}

// HelperStatusRequest reconciles one provisioning request by ID.
type HelperStatusRequest struct {
	RequestID string `json:"request_id"`
}

// HelperProvisionRequest is the provider request body the helper forwards.
// Field-for-field the aegiskeys.ProvisionRequest the provider validates;
// the value is the only secret and crosses only this descriptor.
type HelperProvisionRequest struct {
	RequestID   string     `json:"request_id"`
	Value       string     `json:"value"`
	Service     string     `json:"service"`
	Label       string     `json:"label"`
	Kind        string     `json:"kind"`
	Binding     string     `json:"binding"`
	Operations  []string   `json:"operations"`
	Description string     `json:"description,omitempty"`
	EnvVarHint  string     `json:"env_var_hint,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// StagedResolverGrant, when set, asks AegisKeys to STAGE (never
	// enable) the resolve grant through its durable approval machinery.
	// AttestKey pins the executor's current public half so the staged
	// grant is attest-enforced from birth.
	StagedResolverGrant *ProvisionResolverGrant `json:"resolver_grant,omitempty"`
}

// HelperResponse is the framed response. On success it carries credential
// material — the only copy outside the broker's own memory, delivered on
// the private inherited descriptor. On failure Error carries the sentinel
// name (vault_locked, binding_unavailable, access_denied,
// transport_unavailable, protocol_mismatch, request_invalid) and never any
// credential material.
type HelperResponse struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Binding    string            `json:"binding,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Value      string            `json:"value,omitempty"`
	Components map[string]string `json:"components,omitempty"`
	// Provision carries the v3 provisioning response metadata on the
	// provisioning exchange (nil on resolve exchanges and on failures).
	Provision *ProvisionResponse `json:"provision,omitempty"`
}

// SocketPath exposes the default AegisKeys broker socket path for a config
// directory (used by the helper subcommand and the broker side alike).
func SocketPath(configDir string) string { return socketPath(configDir) }

// writeFramed writes one 4-byte big-endian length-prefixed JSON frame.
func writeFramed(w io.Writer, v interface{}, max int) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > max {
		return fmt.Errorf("frame exceeds %d bytes", max)
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// readFramed reads one length-prefixed JSON frame with the given bound.
func readFramed(r io.Reader, v interface{}, max int) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > uint32(max) {
		return fmt.Errorf("frame length %d outside (0, %d]", n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// helperSentinel maps a typed error to the wire sentinel name. The
// provisioning additions (credential_conflict, request_unknown) mirror the
// provider's v3ServiceError table; resolve responses never carry them, so
// the shared table has no collision.
func helperSentinel(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrVaultLocked):
		return "vault_locked"
	case errors.Is(err, ErrBindingUnavailable):
		return "binding_unavailable"
	case errors.Is(err, ErrAccessDenied):
		return "access_denied"
	case errors.Is(err, ErrProtocolMismatch):
		return "protocol_mismatch"
	case errors.Is(err, ErrRequestInvalid):
		return "request_invalid"
	case errors.Is(err, ErrProvisionConflict):
		return "credential_conflict"
	case errors.Is(err, ErrProvisionUnknown):
		return "request_unknown"
	default:
		return "transport_unavailable"
	}
}

// sentinelError maps a wire sentinel name back to the typed error.
func sentinelError(name string) error {
	switch name {
	case "vault_locked":
		return ErrVaultLocked
	case "binding_unavailable":
		return ErrBindingUnavailable
	case "access_denied":
		return ErrAccessDenied
	case "protocol_mismatch":
		return ErrProtocolMismatch
	case "request_invalid":
		return ErrRequestInvalid
	case "credential_conflict":
		return ErrProvisionConflict
	case "request_unknown":
		return ErrProvisionUnknown
	default:
		return ErrTransportUnavailable
	}
}

// runHelperExchange performs one complete trusted helper exchange (broker
// side): spawn the helper with a private CLOEXEC socketpair as fd 3, write
// the framed request, read the framed response, and reap the child on
// EVERY path (kill-then-Wait exactly once on early return — the P1
// discipline). req carries the request; maxReq bounds the outbound frame
// (resolve 4KiB, provisioning value+slack). The response is validated for
// frame bounds only; mode-specific validation stays with the caller.
//
// The context bounds the whole exchange: a helper that hangs is killed via
// exec.CommandContext, and the broker treats a lost exchange as
// transport_unavailable — never as a reason to retry creation elsewhere.
// A credential-conflict sentinel is deliberately NOT retried here: the
// durable request identity exists with different content, and only the
// caller's reconciliation decides what that means.
func runHelperExchange(ctx context.Context, helperPath, aegisSocket string, req HelperRequest, maxReq int) (HelperResponse, error) {
	if helperPath == "" {
		return HelperResponse{}, fmt.Errorf("%w: resolve helper not configured", ErrTransportUnavailable)
	}
	if aegisSocket == "" {
		return HelperResponse{}, fmt.Errorf("%w: AegisKeys socket not configured", ErrTransportUnavailable)
	}

	server, child, err := socketPair()
	if err != nil {
		return HelperResponse{}, fmt.Errorf("%w: socketpair: %v", ErrTransportUnavailable, err)
	}
	defer server.Close() //nolint:errcheck — best-effort close of a private pair

	// The child itself is always time-bounded: a caller without a deadline
	// still gets a helper that is killed rather than waited on forever.
	cmdCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
	}
	cmd := helperCommand(cmdCtx, helperPath, aegisSocket, child)
	// stdout/stderr go to io.Discard: the helper must never have a path by
	// which credential material could reach captured output, and its own
	// diagnostics are sentinel-framed on the descriptor.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		child.Close() //nolint:errcheck
		return HelperResponse{}, fmt.Errorf("%w: start resolve helper: %v", ErrTransportUnavailable, err)
	}
	// The parent no longer needs its end once the child holds it.
	child.Close() //nolint:errcheck

	// Exactly-once reaping (P1): every early return below must kill the
	// child if it is still running and Wait() it exactly once — an
	// unreaped helper is a zombie for the broker's remaining lifetime,
	// and repeated failed exchanges would accumulate them. exec.
	// CommandContext's eventual kill does not replace the caller's
	// obligation to reap.
	waited := false
	waitOnce := func() {
		if waited {
			return
		}
		waited = true
		_ = cmd.Wait()
	}
	abortWith := func(origErr error) (HelperResponse, error) {
		if cmd.Process != nil {
			_ = cmd.Process.Kill() // no-op (ErrProcessDone) if it already exited
		}
		waitOnce()
		return HelperResponse{}, origErr
	}

	// Socket deadline: the caller's deadline plus slack for the helper's
	// startup and exit, or the child budget when the caller passed none.
	deadline := time.Now().Add(12 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d.Add(2 * time.Second)
	}
	if err := server.SetDeadline(deadline); err != nil {
		return abortWith(fmt.Errorf("%w: helper exchange: %v", ErrTransportUnavailable, err))
	}

	if err := writeFramed(server, req, maxReq); err != nil {
		return abortWith(fmt.Errorf("%w: helper request: %v", ErrTransportUnavailable, err))
	}

	var resp HelperResponse
	if err := readFramed(server, &resp, helperMaxResponseBytes); err != nil {
		return abortWith(fmt.Errorf("%w: helper exchange: %v", ErrTransportUnavailable, err))
	}

	// The helper is one-shot; reap it. CommandContext has killed it already
	// if the context deadline fired during the exchange.
	waitErr := cmd.Wait()
	waited = true
	if waitErr != nil {
		return HelperResponse{}, fmt.Errorf("%w: resolve helper exited: %v", ErrTransportUnavailable, waitErr)
	}
	if !resp.OK {
		return HelperResponse{}, sentinelError(resp.Error)
	}
	return resp, nil
}

// ResolveViaHelper performs one credential resolution through the trusted
// helper executable (broker side). helperPath is operator configuration
// (systemd unit / installation config); it is never agent-supplied. The
// helper is spawned with a private CLOEXEC socketpair as fd 3; the request
// and the credential response travel only over that descriptor.
// attestKey is the executor's in-memory ed25519 private key: each request
// is signed over AttestCanonicalString with a fresh nonce (hardened-parent
// attestation) — the helper carries the signature but never sees the key.
// A nil key sends an unattested request (grants without an attest pin).
func ResolveViaHelper(ctx context.Context, helperPath, aegisSocket, binding, operation, operationID string, attestKey crypto.Signer) (CredentialMaterial, error) {
	return ResolvePinnedViaHelper(ctx, helperPath, aegisSocket, ResolvePin{Binding: binding, Operation: operation, OperationID: operationID}, attestKey)
}

// ResolvePinnedViaHelper is ResolveViaHelper with stable identity pins
// (P0-3 rebind protection): bindingID/recordID travel through the helper
// frame to the provider, which denies generically when a pin no longer
// matches — a rebind of the binding NAME cannot silently redirect an
// approved operation. attestBindingRef (the canonical-string binding
// reference) is the NAME when present (the executor signs the reference it
// holds), the stable ID otherwise — mirroring the provider's
// bindingRefForAttest.
func ResolvePinnedViaHelper(ctx context.Context, helperPath, aegisSocket string, pin ResolvePin, attestKey crypto.Signer) (CredentialMaterial, error) {
	binding, operation, operationID := pin.Binding, pin.Operation, pin.OperationID
	if binding == "" && pin.BindingID == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	if !validOperationName(operation) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation", ErrRequestInvalid)
	}
	if operationID != "" && !validOperationID(operationID) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation_id", ErrRequestInvalid)
	}

	// One small request frame (<= 4KiB) — the socket buffer absorbs it, so
	// the synchronous write cannot deadlock against the child's read. The
	// attestation (when the executor holds a key) is fresh per request.
	req := HelperRequest{Binding: binding, BindingID: pin.BindingID, RecordID: pin.RecordID, Operation: operation, OperationID: operationID}
	if attestKey != nil {
		attestRef := binding
		if attestRef == "" {
			attestRef = pin.BindingID
		}
		nonce, nerr := newAttestNonce()
		if nerr != nil {
			return CredentialMaterial{}, fmt.Errorf("%w: attest nonce: %v", ErrTransportUnavailable, nerr)
		}
		sig, serr := signAttestation(attestKey, attestRef, operation, operationID, nonce)
		if serr != nil {
			return CredentialMaterial{}, fmt.Errorf("%w: attest sign: %v", ErrTransportUnavailable, serr)
		}
		req.AttestNonce = nonce
		req.AttestSig = sig
	}
	resp, err := runHelperExchange(ctx, helperPath, aegisSocket, req, helperMaxRequestBytes)
	if err != nil {
		return CredentialMaterial{}, err
	}
	// Re-validate the response with the same wire rules as a direct
	// resolve: binding echo, component bounds, non-empty material.
	respRef := resp.Binding
	if respRef == "" {
		respRef = pin.BindingID
	}
	wantRef := binding
	if wantRef == "" {
		wantRef = pin.BindingID
	}
	if respRef != wantRef {
		return CredentialMaterial{}, fmt.Errorf("%w: binding mismatch", ErrProtocolMismatch)
	}
	if resp.Value == "" && len(resp.Components) == 0 {
		return CredentialMaterial{}, fmt.Errorf("%w: empty credential", ErrProtocolMismatch)
	}
	if len(resp.Value) > maxValueBytes || len(resp.Components) > maxComponents {
		return CredentialMaterial{}, fmt.Errorf("%w: credential bounds", ErrProtocolMismatch)
	}
	for key, val := range resp.Components {
		if key == "" || len(key) > 128 || len(val) > maxComponentBytes {
			return CredentialMaterial{}, fmt.Errorf("%w: component bounds", ErrProtocolMismatch)
		}
	}
	return CredentialMaterial{Binding: resp.Binding, Kind: resp.Kind, Value: resp.Value, Components: resp.Components}, nil
}

// ProvisionViaHelper performs one trusted provisioning exchange through the
// same trusted helper executable (broker side, P0-3). The credential VALUE
// crosses to the provider only over the private inherited descriptor — the
// same trusted crossing as resolve — under the helper's PROVISIONING grant
// (a distinct executable grant: provisioning authority is separate from
// resolve authority on the AegisKeys side).
//
// Return contract:
//   - ErrProvisionConflict: the durable request identity exists with
//     DIFFERENT content (or promotion collided with an operator-managed
//     binding). The caller must reconcile via ProvisionStatus and report
//     a conflict — never silently retry with a new request ID and never
//     auto-retry with the same one.
//   - ErrVaultLocked: the provider vault is locked; retry with the SAME
//     request ID after the operator unlocks.
//   - ErrTransportUnavailable on uncertain exchanges: the provider MAY
//     have committed. The caller MUST reconcile via ProvisionStatus with
//     the original request ID before any retry decision.
//   - Success: resp carries the durable metadata (record/binding IDs and
//     lifecycle status) — never credential material.
func ProvisionViaHelper(ctx context.Context, helperPath, aegisSocket string, req ProvisionRequest) (ProvisionResponse, error) {
	if err := ValidProvisionRequest(req); err != nil {
		return ProvisionResponse{}, err
	}
	hreq := HelperRequest{Provision: &HelperProvisionRequest{
		RequestID:           req.RequestID,
		Value:               req.Value,
		Service:             req.Service,
		Label:               req.Label,
		Kind:                req.Kind,
		Binding:             req.Binding,
		Operations:          req.Operations,
		Description:         req.Description,
		EnvVarHint:          req.EnvVarHint,
		ExpiresAt:           req.ExpiresAt,
		StagedResolverGrant: req.ResolverGrant,
	}}
	resp, err := runHelperExchange(ctx, helperPath, aegisSocket, hreq, helperMaxProvisionRequestBytes)
	if err != nil {
		return ProvisionResponse{}, err
	}
	if resp.Provision == nil {
		return ProvisionResponse{}, fmt.Errorf("%w: provisioning response missing metadata", ErrProtocolMismatch)
	}
	if resp.Provision.RequestID != req.RequestID {
		return ProvisionResponse{}, fmt.Errorf("%w: request_id echo mismatch", ErrProtocolMismatch)
	}
	return *resp.Provision, nil
}

// ProvisionStatusViaHelper reconciles one provisioning request through the
// trusted helper (broker side, P0-3). METADATA ONLY: no credential material
// crosses in either direction — the request is a request ID, the response
// is lifecycle metadata. It rides the helper because a non-dumpable broker
// cannot pass the provider's exe verification directly.
//
// Return contract mirrors ProvisionViaHelper: ErrProvisionUnknown means the
// provider has NO durable entry under this request ID (the exactly-once
// reconciliation signal that a resubmit of the SAME ID is safe);
// transport failures leave the durable state uncertain.
func ProvisionStatusViaHelper(ctx context.Context, helperPath, aegisSocket, requestID string) (ProvisionResponse, error) {
	if requestID == "" {
		return ProvisionResponse{}, fmt.Errorf("%w: request_id", ErrRequestInvalid)
	}
	hreq := HelperRequest{StatusRequest: &HelperStatusRequest{RequestID: requestID}}
	resp, err := runHelperExchange(ctx, helperPath, aegisSocket, hreq, helperMaxRequestBytes)
	if err != nil {
		return ProvisionResponse{}, err
	}
	if resp.Provision == nil {
		return ProvisionResponse{}, fmt.Errorf("%w: provisioning status missing metadata", ErrProtocolMismatch)
	}
	if resp.Provision.RequestID != requestID {
		return ProvisionResponse{}, fmt.Errorf("%w: request_id echo mismatch", ErrProtocolMismatch)
	}
	return *resp.Provision, nil
}

// HelperServe is the helper side of the protocol: it runs on the inherited
// socketpair descriptor, reads exactly one HelperRequest, resolves it
// through the AegisKeys broker at aegisSocket, and writes exactly one
// HelperResponse. Credential material is written ONLY to the descriptor —
// never to stdout or stderr, which this function does not touch. It
// returns nil once a well-formed response (success OR broker denial) was
// delivered, and an error only when no response could be delivered; the
// caller exits the process either way.
//
// The exchange is deadline-bounded both ways: the one-shot helper must
// never sit on a descriptor that never speaks (minimality includes
// failing fast).
func HelperServe(conn net.Conn, aegisSocket string) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// One read against the larger (provisioning) bound: the resolve mode
	// re-asserts its own tighter bound after decode, so an oversized
	// resolve request is still rejected — the frame is consumed either
	// way, so there is no fallback re-read (a bound failure mid-frame
	// leaves the stream misaligned).
	var req HelperRequest
	if err := readFramed(conn, &req, helperMaxProvisionRequestBytes); err != nil {
		// A malformed request is a broker bug or tampering: no response
		// frame can be trusted to help; exit non-zero with no output.
		return fmt.Errorf("helper: read request: %w", err)
	}
	if req.Provision == nil {
		body, merr := json.Marshal(req)
		if merr != nil || len(body) > helperMaxRequestBytes {
			return fmt.Errorf("helper: read request: resolve frame bounds")
		}
	}
	// The resolve/provision itself is budgeted; extend the descriptor
	// deadline to cover it plus the response write.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if req.StatusRequest != nil {
		resp, err := statusInHelper(aegisSocket, req.StatusRequest.RequestID)
		if err != nil {
			resp := HelperResponse{OK: false, Error: helperSentinel(err)}
			if werr := writeFramed(conn, resp, helperMaxResponseBytes); werr != nil {
				return fmt.Errorf("helper: write error response: %w", werr)
			}
			// Sentinel delivered (request_unknown is a valid reconciliation
			// answer, not a helper failure: the broker decides).
			return nil
		}
		if werr := writeFramed(conn, resp, helperMaxResponseBytes); werr != nil {
			return fmt.Errorf("helper: write response: %w", werr)
		}
		return nil
	}
	if req.Provision != nil {
		resp, err := provisionInHelper(aegisSocket, req)
		if err != nil {
			resp := HelperResponse{OK: false, Error: helperSentinel(err)}
			if werr := writeFramed(conn, resp, helperMaxResponseBytes); werr != nil {
				return fmt.Errorf("helper: write error response: %w", werr)
			}
			// Sentinel denial delivered (this includes the provider's
			// credential_conflict: the durable identity exists and the
			// broker must reconcile, never blind-retry).
			return nil
		}
		if werr := writeFramed(conn, resp, helperMaxResponseBytes); werr != nil {
			return fmt.Errorf("helper: write response: %w", werr)
		}
		return nil
	}
	mat, err := resolveInHelper(aegisSocket, req)
	if err != nil {
		resp := HelperResponse{OK: false, Error: helperSentinel(err)}
		if werr := writeFramed(conn, resp, helperMaxResponseBytes); werr != nil {
			return fmt.Errorf("helper: write error response: %w", werr)
		}
		// The sentinel denial WAS delivered: the broker reconstructs the
		// typed error from it. Exit code 0 = "response delivered".
		return nil
	}
	resp := HelperResponse{OK: true, Binding: mat.Binding, Kind: mat.Kind, Value: mat.Value, Components: mat.Components}
	if err := writeFramed(conn, resp, helperMaxResponseBytes); err != nil {
		return fmt.Errorf("helper: write response: %w", err)
	}
	return nil
}

// resolveInHelper performs the actual broker resolve on the helper side,
// with a short overall budget so the process lifetime stays minimal.
func resolveInHelper(aegisSocket string, req HelperRequest) (CredentialMaterial, error) {
	if req.Binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	if !validOperationName(req.Operation) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation", ErrRequestInvalid)
	}
	if req.OperationID != "" && !validOperationID(req.OperationID) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation_id", ErrRequestInvalid)
	}
	// Identity-pin bounds (P0-3): same grammar the broker validates; the
	// helper refuses to courier malformed pins rather than forwarding them.
	if req.BindingID != "" && !validOperationID(req.BindingID) {
		return CredentialMaterial{}, fmt.Errorf("%w: binding_id", ErrRequestInvalid)
	}
	if req.RecordID != "" && !validOperationID(req.RecordID) {
		return CredentialMaterial{}, fmt.Errorf("%w: record_id", ErrRequestInvalid)
	}
	// Attestation pass-through bounds (mirror the broker's request
	// validation; the helper is a courier, not the signer).
	if (req.AttestNonce != "") != (len(req.AttestSig) > 0) {
		return CredentialMaterial{}, fmt.Errorf("%w: attestation requires both nonce and signature", ErrRequestInvalid)
	}
	if len(req.AttestNonce) > 128 || len(req.AttestSig) > ed25519.SignatureSize {
		return CredentialMaterial{}, fmt.Errorf("%w: attestation bounds", ErrRequestInvalid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cli, err := ConnectSocket(aegisSocket)
	if err != nil {
		return CredentialMaterial{}, err
	}
	return cli.ResolvePinned(ctx, ResolvePin{
		Binding:     req.Binding,
		BindingID:   req.BindingID,
		RecordID:    req.RecordID,
		Operation:   req.Operation,
		OperationID: req.OperationID,
		AttestNonce: req.AttestNonce,
		AttestSig:   req.AttestSig,
	})
}

// provisionInHelper performs the trusted provisioning forward on the
// helper side, with a short overall budget so the process lifetime stays
// minimal. The helper holds no authorization logic: the provider enforces
// the provisioning grant (helper executable identity + requested
// service/kind) and the durable request-ID identity contract.
func provisionInHelper(aegisSocket string, req HelperRequest) (HelperResponse, error) {
	p := req.Provision
	if p == nil || p.RequestID == "" || p.Value == "" {
		return HelperResponse{}, fmt.Errorf("%w: provision", ErrRequestInvalid)
	}
	preq := ProvisionRequest{
		RequestID:     p.RequestID,
		Value:         p.Value,
		Service:       p.Service,
		Label:         p.Label,
		Kind:          p.Kind,
		Binding:       p.Binding,
		Operations:    p.Operations,
		Description:   p.Description,
		EnvVarHint:    p.EnvVarHint,
		ExpiresAt:     p.ExpiresAt,
		ResolverGrant: p.StagedResolverGrant,
	}
	if err := ValidProvisionRequest(preq); err != nil {
		return HelperResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cli, err := ConnectSocket(aegisSocket)
	if err != nil {
		return HelperResponse{}, err
	}
	out, err := cli.Provision(ctx, preq)
	if err != nil {
		return HelperResponse{}, err
	}
	return HelperResponse{OK: true, Provision: &out}, nil
}

// statusInHelper reconciles one provisioning request (helper side,
// metadata only — no credential material crosses in either direction).
func statusInHelper(aegisSocket, requestID string) (HelperResponse, error) {
	if requestID == "" {
		return HelperResponse{}, fmt.Errorf("%w: request_id", ErrRequestInvalid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cli, err := ConnectSocket(aegisSocket)
	if err != nil {
		return HelperResponse{}, err
	}
	out, err := cli.ProvisionStatus(ctx, requestID)
	if err != nil {
		return HelperResponse{}, err
	}
	return HelperResponse{OK: true, Provision: &out}, nil
}

// newAttestNonce generates a fresh single-use nonce (hardened-parent
// attestation; the broker treats replayed request content as a fresh
// signature requirement, so a stale nonce is useless to an attacker).
func newAttestNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// signAttestation signs the broker's canonical request string with the
// executor's in-memory ed25519 key. Only ed25519 keys are accepted: the
// grant pin format is a hex ed25519 public key.
func signAttestation(key crypto.Signer, binding, operation, operationID, nonce string) ([]byte, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attest key must be ed25519, got %T", key.Public())
	}
	_ = pub
	opts := crypto.Hash(0) //nolint:staticcheck — ed25519 signs raw bytes
	return key.Sign(nil, AttestCanonicalString(binding, operation, operationID, nonce), opts)
}

// ExecutorAttestKey is the hardened executor's in-memory ed25519 key pair
// (P0-1 attestation). The broker is long-lived and non-dumpable
// (PR_SET_DUMPABLE=0): its memory is the one same-UID-unreadable store the
// kernel provides, so the private key held there cannot be read or forged
// by same-UID code. Generate one at broker startup and pass it to every
// ResolveViaHelper call; publish the hex public half to the operator for
// the AegisKeys grant's attest_key pin.
type ExecutorAttestKey struct {
	Private crypto.Signer
}

// NewExecutorAttestKey generates a fresh ed25519 key pair.
func NewExecutorAttestKey() (*ExecutorAttestKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_ = pub
	return &ExecutorAttestKey{Private: priv}, nil
}

// NewExecutorAttestKeyFromSeed derives a deterministic ed25519 key from a
// 32-byte seed. The restart strategy's stable-key mode: an operator
// provisions the seed through systemd's encrypted-credential mechanism
// (LoadCredentialEncrypted — decrypted by PID 1 into the unit's read-only
// credential mount, never an ordinary file owned by the service UID), so
// the key pair survives restarts and the AegisKeys grant's attest_key pin
// stays valid across unattended restarts. The seed must be exactly
// ed25519.SeedSize bytes; anything else is refused, not truncated.
func NewExecutorAttestKeyFromSeed(seed []byte) (*ExecutorAttestKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("attest seed must be exactly %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &ExecutorAttestKey{Private: priv}, nil
}

// LoadAttestSeedFile reads a provisioned seed file (systemd credential or
// an equivalent root-owned secret). It is a hardened read: symlinks
// refused, group/world-readable files refused, owner must be the broker
// identity or root, and the content must be exactly 32 bytes. The seed is
// a secret: it must never live in a file the service's same-UID peers can
// read — the encrypted-credential mount is the intended source.
func LoadAttestSeedFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("attest seed: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("attest seed %s is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("attest seed %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("attest seed %s must not be group/world-accessible (%v)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid := uint32(os.Geteuid())
		if st.Uid != 0 && st.Uid != uid {
			return nil, fmt.Errorf("attest seed %s is owned by uid %d, want root or %d", path, st.Uid, uid)
		}
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attest seed read: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("attest seed %s must be exactly %d bytes, got %d", path, ed25519.SeedSize, len(seed))
	}
	return seed, nil
}

// PublicHex returns the hex-encoded public key for the operator's grant
// attest_key pin (display/audit only — never a secret, never agent-visible).
func (k *ExecutorAttestKey) PublicHex() string {
	pub, ok := k.Private.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return hex.EncodeToString(pub)
}

// helperDescriptorNumber is the fd the broker passes to the helper.
const helperDescriptorNumber = 3

// LoadHelperConnAt opens the given inherited descriptor for the helper
// subcommand. Exported for the cmd wiring and for tests that re-exec a
// test binary in helper mode.
func LoadHelperConnAt(fd int) (net.Conn, error) {
	if fd < 3 {
		return nil, fmt.Errorf("fd %d is not an inherited descriptor", fd)
	}
	f := os.NewFile(uintptr(fd), "seqpass-resolve-helper-fd")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not a file descriptor", fd)
	}
	conn, err := net.FileConn(f)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	f.Close() //nolint:errcheck — FileConn duplicated the descriptor
	return conn, nil
}
