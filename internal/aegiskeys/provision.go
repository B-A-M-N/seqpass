// Trusted provisioning client (P0-3): the SeqPass consumer side of the
// AegisKeys /v3/intake/credentials contract. The credential VALUE crosses
// only into the trusted helper path (the same private inherited descriptor
// the resolve path uses) — never the agent-visible IPC surface, never
// logs/argv/env of any long-lived process, and never SeqPass's database.
package aegiskeys

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProvisionRequest mirrors broker.ProvisionRequest. Field names and
// semantics are the provider's contract (AegisKeys/internal/broker/
// provision.go): request_id is the durable idempotency anchor; operations
// is the protected-use scope (>= 1); binding is the stable name the
// credential will be resolvable under.
type ProvisionRequest struct {
	RequestID   string   `json:"request_id"`
	Value       string   `json:"value"`
	Service     string   `json:"service"`
	Label       string   `json:"label"`
	Kind        string   `json:"kind"`
	Binding     string   `json:"binding"`
	Operations  []string `json:"operations"`
	Description string   `json:"description,omitempty"`
	EnvVarHint  string   `json:"env_var_hint,omitempty"`
	// ExpiresAt, when set, bounds the credential's validity (RFC3339 on
	// the wire, matching *time.Time JSON semantics).
	ExpiresAt     *time.Time              `json:"expires_at,omitempty"`
	ResolverGrant *ProvisionResolverGrant `json:"resolver_grant,omitempty"`
}

// ProvisionResolverGrant asks the provider to STAGE (never enable) the
// resolve grant the binding needs, through AegisKeys' existing durable
// approval machinery. Empty ExecutablePath pins the trusted intake caller
// (the helper executable identity); the hash is always computed
// server-side from the installed binary. AttestKey pins the executor's
// hex ed25519 public half for an attest-key grant — AegisKeys verifies it
// matches what the executor actually publishes before staging.
type ProvisionResolverGrant struct {
	ExecutablePath string     `json:"executable_path,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	AttestKey      string     `json:"attest_key,omitempty"`
}

// ProvisionResponse mirrors broker.ProvisionResponse: metadata only, never
// credential material.
type ProvisionResponse struct {
	RequestID          string `json:"request_id"`
	RecordID           string `json:"record_id,omitempty"`
	BindingID          string `json:"binding_id,omitempty"`
	BindingName        string `json:"binding,omitempty"`
	Status             string `json:"status"`
	StagedGrantID      string `json:"staged_grant_id,omitempty"`
	StagingDisposition string `json:"staging_disposition,omitempty"`
	StagingError       string `json:"staging_error,omitempty"`
}

// Provision status sentinels (broker.ProvisioningRequestStatus values the
// consumer acts on). credential_committed/binding_pending are transient
// commit stages recovered by retrying the same request ID;
// authorization_pending means the credential+binding are durable but the
// resolve grant is not yet approved; grant_present/ready mean the stored
// credential is resolvable.
const (
	ProvisionStatusCredentialCommitted  = "credential_committed"
	ProvisionStatusBindingPending       = "binding_pending"
	ProvisionStatusAuthorizationPending = "authorization_pending"
	ProvisionStatusGrantPresent         = "grant_present"
	ProvisionStatusReady                = "ready"
)

// Provision wire bounds (mirror the broker's maxProvision* limits).
const (
	MaxProvisionValueLen = 32 * 1024
	MaxProvisionLabelLen = 128
	MaxProvisionHintLen  = 256
	// maxProvisionResponseBytes bounds the decoded response body: a
	// provisioning response is small metadata; anything larger is a
	// protocol violation.
	maxProvisionResponseBytes = 16 * 1024
)

// ValidProvisionRequest performs the consumer-side pre-flight of the
// normalized request shape, mirroring the broker's normalizeProvisionRequest
// grammar so malformed requests fail locally with a precise error instead
// of a remote request_invalid. The value bound is enforced here too: the
// credential material must fit the provider's 32KiB bound before it is
// ever handed to the trusted crossing.
func ValidProvisionRequest(req ProvisionRequest) error {
	switch {
	case req.RequestID == "" || len(req.RequestID) > 128:
		return fmt.Errorf("%w: request_id", ErrRequestInvalid)
	case req.Value == "" || len(req.Value) > MaxProvisionValueLen:
		return fmt.Errorf("%w: value", ErrRequestInvalid)
	case req.Service == "" || len(req.Service) > 128:
		return fmt.Errorf("%w: service", ErrRequestInvalid)
	case req.Label == "" || len(req.Label) > MaxProvisionLabelLen:
		return fmt.Errorf("%w: label", ErrRequestInvalid)
	case req.Kind == "" || len(req.Kind) > 64:
		return fmt.Errorf("%w: kind", ErrRequestInvalid)
	case req.Binding == "" || len(req.Binding) > 128:
		return fmt.Errorf("%w: binding", ErrRequestInvalid)
	case len(req.Operations) == 0:
		return fmt.Errorf("%w: operations must be non-empty (operation-scoped binding contract)", ErrRequestInvalid)
	}
	for _, op := range req.Operations {
		if !validOperationName(op) {
			return fmt.Errorf("%w: operation %q", ErrRequestInvalid, op)
		}
	}
	if len(req.Description) > MaxProvisionHintLen || len(req.EnvVarHint) > MaxProvisionHintLen {
		return fmt.Errorf("%w: description/env_var_hint", ErrRequestInvalid)
	}
	return nil
}

// v3 error sentinels from the provider's v3ServiceError table.
var (
	// ErrProvisionConflict: replayed request ID with altered content, or a
	// promotion collision. Fail closed: NEVER auto-retry under the same ID
	// after this — the durable identity exists with different content.
	ErrProvisionConflict = fmt.Errorf("credential_conflict")
	// ErrProvisionUnknown: request ID has no durable entry.
	ErrProvisionUnknown = fmt.Errorf("request_unknown")
)

// Provision submits one trusted-intake credential creation. It is called
// ONLY by the trusted helper path (the caller already authenticated to
// AegisKeys via /proc/<pid>/exe): the provisioning grant pins the helper
// executable identity, exactly like the resolve grant.
//
// On any UNCERTAIN result (transport failure after the body was sent, 5xx,
// vault_locked mid-commit) the caller must reconcile with ProvisionStatus
// using the original request ID before deciding whether to retry — a blind
// retry with a NEW request ID could duplicate the credential, which is the
// exact failure mode the durable identity exists to prevent.
func (c *Client) Provision(ctx context.Context, req ProvisionRequest) (ProvisionResponse, error) {
	if c == nil || c.http == nil {
		return ProvisionResponse{}, ErrTransportUnavailable
	}
	if err := ValidProvisionRequest(req); err != nil {
		return ProvisionResponse{}, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return ProvisionResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://aegiskeys.local/v3/intake/credentials", strings.NewReader(string(body)))
	if err != nil {
		return ProvisionResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.ContentLength = int64(len(body))
	resp, err := c.http.Do(httpReq)
	if err != nil {
		// The request MAY have been received and committed: uncertain.
		return ProvisionResponse{}, fmt.Errorf("%w: post (uncertain — reconcile by request_id): %v", ErrTransportUnavailable, err)
	}
	defer resp.Body.Close()
	return decodeProvisionResponse(resp)
}

// ProvisionStatus reconciles one durable provisioning request by its
// original request ID. GET /v3/intake/requests/<id>. Never submits
// credential material.
func (c *Client) ProvisionStatus(ctx context.Context, requestID string) (ProvisionResponse, error) {
	if c == nil || c.http == nil {
		return ProvisionResponse{}, ErrTransportUnavailable
	}
	if requestID == "" || len(requestID) > 128 {
		return ProvisionResponse{}, fmt.Errorf("%w: request_id", ErrRequestInvalid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://aegiskeys.local/v3/intake/requests/"+requestID, nil)
	if err != nil {
		return ProvisionResponse{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ProvisionResponse{}, fmt.Errorf("%w: %v", ErrTransportUnavailable, err)
	}
	defer resp.Body.Close()
	return decodeProvisionResponse(resp)
}

// decodeProvisionResponse strictly decodes a bounded v3 provisioning
// response: non-2xx maps the provider's sentinel table onto typed errors;
// 2xx bodies must be small, well-formed, and free of unknown fields — the
// response is metadata, so anything unexpected is a protocol violation,
// never a best-effort parse.
func decodeProvisionResponse(resp *http.Response) (ProvisionResponse, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		switch resp.StatusCode {
		case http.StatusConflict:
			return ProvisionResponse{}, ErrProvisionConflict
		case http.StatusNotFound:
			return ProvisionResponse{}, ErrProvisionUnknown
		case http.StatusForbidden:
			return ProvisionResponse{}, ErrAccessDenied
		case http.StatusLocked:
			return ProvisionResponse{}, ErrVaultLocked
		case http.StatusBadRequest:
			return ProvisionResponse{}, ErrRequestInvalid
		default:
			return ProvisionResponse{}, fmt.Errorf("%w: %s", ErrProtocolMismatch, resp.Status)
		}
	}
	var out ProvisionResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxProvisionResponseBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return ProvisionResponse{}, fmt.Errorf("%w: provision decode", ErrProtocolMismatch)
	}
	if out.RequestID == "" {
		return ProvisionResponse{}, fmt.Errorf("%w: provision response missing request_id", ErrProtocolMismatch)
	}
	return out, nil
}
