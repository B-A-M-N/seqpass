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
// Approval-bypass review: the helper is not an authorization surface. It
// performs no approval decisions and grants nothing; it only forwards the
// already-approved (binding, operation, operation_id) triple to AegisKeys,
// whose grant + operation-allowlist enforcement is unchanged. A same-user
// process could spawn the helper with its own request, but in the isolated
// topology it would then authenticate with the agent UID, which no helper
// grant admits.

// helperMaxRequestBytes bounds the framed request (binding + operation +
// operation ID are bounded strings; 4KiB is generous).
const helperMaxRequestBytes = 4096

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
	AttestNonce string `json:"attest_nonce,omitempty"`
	AttestSig   []byte `json:"attest_sig,omitempty"`
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

// helperSentinel maps a sentinel error to its wire name so the broker side
// reconstructs the same typed error the in-process path would return.
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
	default:
		return ErrTransportUnavailable
	}
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
//
// The context bounds the whole exchange: a helper that hangs is killed via
// exec.CommandContext, and the broker treats a lost exchange as
// transport_unavailable — never as a reason to retry creation elsewhere.
func ResolveViaHelper(ctx context.Context, helperPath, aegisSocket, binding, operation, operationID string, attestKey crypto.Signer) (CredentialMaterial, error) {
	if helperPath == "" {
		return CredentialMaterial{}, fmt.Errorf("%w: resolve helper not configured", ErrTransportUnavailable)
	}
	if aegisSocket == "" {
		return CredentialMaterial{}, fmt.Errorf("%w: AegisKeys socket not configured", ErrTransportUnavailable)
	}
	if binding == "" {
		return CredentialMaterial{}, ErrBindingUnavailable
	}
	if !validOperationName(operation) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation", ErrRequestInvalid)
	}
	if operationID != "" && !validOperationID(operationID) {
		return CredentialMaterial{}, fmt.Errorf("%w: operation_id", ErrRequestInvalid)
	}

	server, child, err := socketPair()
	if err != nil {
		return CredentialMaterial{}, fmt.Errorf("%w: socketpair: %v", ErrTransportUnavailable, err)
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
		return CredentialMaterial{}, fmt.Errorf("%w: start resolve helper: %v", ErrTransportUnavailable, err)
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
	abortWith := func(origErr error) (CredentialMaterial, error) {
		if cmd.Process != nil {
			_ = cmd.Process.Kill() // no-op (ErrProcessDone) if it already exited
		}
		waitOnce()
		return CredentialMaterial{}, origErr
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

	// One small request frame (<= 4KiB) — the socket buffer absorbs it, so
	// the synchronous write cannot deadlock against the child's read. The
	// attestation (when the executor holds a key) is fresh per request.
	req := HelperRequest{Binding: binding, Operation: operation, OperationID: operationID}
	if attestKey != nil {
		nonce, nerr := newAttestNonce()
		if nerr != nil {
			return abortWith(fmt.Errorf("%w: attest nonce: %v", ErrTransportUnavailable, nerr))
		}
		sig, serr := signAttestation(attestKey, binding, operation, operationID, nonce)
		if serr != nil {
			return abortWith(fmt.Errorf("%w: attest sign: %v", ErrTransportUnavailable, serr))
		}
		req.AttestNonce = nonce
		req.AttestSig = sig
	}
	if err := writeFramed(server, req, helperMaxRequestBytes); err != nil {
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
		return CredentialMaterial{}, fmt.Errorf("%w: resolve helper exited: %v", ErrTransportUnavailable, waitErr)
	}
	if !resp.OK {
		return CredentialMaterial{}, sentinelError(resp.Error)
	}
	// Re-validate the response with the same wire rules as a direct
	// resolve: binding echo, component bounds, non-empty material.
	if resp.Binding != binding {
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
	var req HelperRequest
	if err := readFramed(conn, &req, helperMaxRequestBytes); err != nil {
		// A malformed request is a broker bug or tampering: no response
		// frame can be trusted to help; exit non-zero with no output.
		return fmt.Errorf("helper: read request: %w", err)
	}
	// The resolve itself is budgeted (resolveInHelper); extend the
	// descriptor deadline to cover it plus the response write.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
	return cli.ResolveAttested(ctx, req.Binding, req.Operation, req.OperationID, req.AttestNonce, req.AttestSig)
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
