package aegiskeys

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func testResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)), Request: req,
	}
}

// T13: grant/socket unavailable -> typed transport error, no credential.
func TestResolveUnavailable(t *testing.T) {
	cli, err := ConnectSocket(filepath.Join(t.TempDir(), "nope.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Resolve(ctx, "some/binding", "git.fetch", "op-1")
	if !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected transport_unavailable, got %v", err)
	}
}

func TestEmptyBinding(t *testing.T) {
	cli, err := ConnectSocket(filepath.Join(t.TempDir(), "nope.sock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.Resolve(context.Background(), "", "git.fetch", "op-1")
	if !errors.Is(err, ErrBindingUnavailable) {
		t.Fatalf("expected binding_unavailable, got %v", err)
	}
}

func TestResolveV2UsesLogicalComponentKey(t *testing.T) {
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v2/resolve" {
			t.Fatalf("path = %q, want v2", req.URL.Path)
		}
		if req.Header.Get("X-Seqpass-Op") != "op-1" {
			t.Fatalf("correlation id missing: %v", req.Header)
		}
		return testResponse(req, http.StatusOK, `{"protocol":"v2","binding":"b","value":"primary","component_entries":[{"key":"tenant-id","env_var":"TENANT_ENV","value":"tenant"},{"key":"cert","value":"cert-data"}]}`), nil
	})}}
	material, err := cli.Resolve(context.Background(), "b", "git.fetch", "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if material.Components["tenant-id"] != "tenant" || material.Components["cert"] != "cert-data" {
		t.Fatalf("logical component identity lost: %+v", material)
	}
	if _, ok := material.Components["TENANT_ENV"]; ok {
		t.Fatal("v2 component map is keyed by environment hint, not logical key")
	}
}

// TestResolveV2BodyCarriesOperationAndOperationID pins the operation-aware
// resolve contract: the body must carry the logical operation and the
// correlation token, not just the binding. Operation-scoped broker bindings
// authorize on `operation`; a binding-only body fails closed remotely, and
// worse, omits the audit correlation the operator reviews.
func TestResolveV2BodyCarriesOperationAndOperationID(t *testing.T) {
	var got ResolveRequest
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		return testResponse(req, http.StatusOK, `{"protocol":"v2","binding":"b","value":"v"}`), nil
	})}}
	if _, err := cli.Resolve(context.Background(), "b", "git.push", "op-2026-10-19-001"); err != nil {
		t.Fatal(err)
	}
	if got.Binding != "b" || got.Operation != "git.push" || got.OperationID != "op-2026-10-19-001" {
		t.Fatalf("resolve body = %+v", got)
	}
}

// TestResolveV2NotFoundDoesNotFallback pins the no-downgrade rule: a 404 on
// /v2/resolve (missing binding, unknown route, misconfigured path) must NOT
// be silently reinterpreted as "v1 only" — the v1 endpoint is reachable only
// through the explicit legacy opt-in.
func TestResolveV2NotFoundDoesNotFallback(t *testing.T) {
	var paths []string
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return testResponse(req, http.StatusNotFound, "not found"), nil
	})}}
	_, err := cli.Resolve(context.Background(), "b", "git.fetch", "")
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("expected protocol_mismatch without fallback, got %v", err)
	}
	if len(paths) != 1 || paths[0] != "/v2/resolve" {
		t.Fatalf("automatic fallback observed: %v", paths)
	}
}

// TestResolveLegacyModeUsesV1 verifies the explicit legacy opt-in reaches
// the v1 endpoint and preserves its response-key semantics.
func TestResolveLegacyModeUsesV1(t *testing.T) {
	var paths []string
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return testResponse(req, http.StatusOK, `{"binding":"b","value":"primary","components":{"TENANT_ENV":"tenant"}}`), nil
	})}}
	cli.SetLegacyProtocol(true)
	material, err := cli.Resolve(context.Background(), "b", "git.fetch", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/v1/resolve" {
		t.Fatalf("legacy mode paths = %v", paths)
	}
	if material.Components["TENANT_ENV"] != "tenant" || len(material.Components) != 1 {
		t.Fatalf("v1 response keys were silently reinterpreted: %+v", material)
	}
}

func TestResolveRejectsInvalidOperation(t *testing.T) {
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("HTTP issued despite invalid operation")
		return nil, nil
	})}}
	for _, op := range []string{"", "Git Push", "git push", "GIT.PUSH", strings.Repeat("x", 65)} {
		if _, err := cli.Resolve(context.Background(), "b", op, ""); !errors.Is(err, ErrRequestInvalid) {
			t.Fatalf("operation %q accepted: %v", op, err)
		}
	}
}

func TestResolveRejectsInvalidOperationID(t *testing.T) {
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("HTTP issued despite invalid operation_id")
		return nil, nil
	})}}
	for _, id := range []string{"bad id", "bad/id", strings.Repeat("x", 129)} {
		if _, err := cli.Resolve(context.Background(), "b", "git.fetch", id); !errors.Is(err, ErrRequestInvalid) {
			t.Fatalf("operation_id %q accepted: %v", id, err)
		}
	}
}

func TestResolveV2RejectsDuplicateLogicalKeys(t *testing.T) {
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return testResponse(req, http.StatusOK, `{"protocol":"v2","binding":"b","component_entries":[{"key":"tenant","value":"one"},{"key":"tenant","value":"two"}]}`), nil
	})}}
	if _, err := cli.Resolve(context.Background(), "b", "git.fetch", ""); !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("duplicate logical component key accepted: %v", err)
	}
}

func TestValidOperationNameGrammar(t *testing.T) {
	for _, op := range []string{"git.fetch", "git.push", "http.request", "process.run", "transfer", "a"} {
		if !validOperationName(op) {
			t.Fatalf("valid operation %q rejected", op)
		}
	}
	for _, op := range []string{"", "Transfer", "git fetch", "op/slash", strings.Repeat("x", 65)} {
		if validOperationName(op) {
			t.Fatalf("invalid operation %q accepted", op)
		}
	}
}

// AegisKeys added this metadata field to v3 provisioning responses. The
// strict decoder must accept the known field while continuing to reject
// genuinely unknown response fields.
func TestDecodeProvisionResponseAcceptsStagingDisposition(t *testing.T) {
	resp := testResponse(nil, http.StatusOK, `{"request_id":"req-1","status":"ready","staging_disposition":"staged"}`)
	out, err := decodeProvisionResponse(resp)
	if err != nil {
		t.Fatalf("decode v3 provision response: %v", err)
	}
	if out.StagingDisposition != "staged" {
		t.Fatalf("staging disposition = %q, want staged", out.StagingDisposition)
	}
}
