package aegiskeys

import (
	"context"
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
	_, err = cli.Resolve(ctx, "some/binding", "op-1")
	if !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected transport_unavailable, got %v", err)
	}
}

func TestEmptyBinding(t *testing.T) {
	cli, err := ConnectSocket(filepath.Join(t.TempDir(), "nope.sock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.Resolve(context.Background(), "", "op-1")
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
	material, err := cli.Resolve(context.Background(), "b", "op-1")
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

func TestResolveFallsBackToV1ComponentMapSemantics(t *testing.T) {
	var paths []string
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		if req.URL.Path == "/v2/resolve" {
			return testResponse(req, http.StatusNotFound, "not found"), nil
		}
		return testResponse(req, http.StatusOK, `{"binding":"b","value":"primary","components":{"TENANT_ENV":"tenant"}}`), nil
	})}}
	material, err := cli.Resolve(context.Background(), "b", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/v2/resolve" || paths[1] != "/v1/resolve" {
		t.Fatalf("fallback paths = %v", paths)
	}
	if material.Components["TENANT_ENV"] != "tenant" || len(material.Components) != 1 {
		t.Fatalf("v1 response keys were silently reinterpreted: %+v", material)
	}
}

func TestResolveV2RejectsDuplicateLogicalKeys(t *testing.T) {
	cli := &Client{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return testResponse(req, http.StatusOK, `{"protocol":"v2","binding":"b","component_entries":[{"key":"tenant","value":"one"},{"key":"tenant","value":"two"}]}`), nil
	})}}
	if _, err := cli.Resolve(context.Background(), "b", ""); !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("duplicate logical component key accepted: %v", err)
	}
}
