package secureops

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

// ParseHTTPOrigin is the registration grammar for pinned HTTP origins.
// Everything that is not exactly scheme://host[:port] is refused, so an
// origin can never smuggle a path, userinfo or credential-bearing query.
func TestParseHTTPOriginGrammar(t *testing.T) {
	good := []string{
		"https://api.example.com",
		"https://api.example.com:8443",
		"https://internal-service.staging.svc",
		"http://127.0.0.1:39999",
		"http://localhost:39999",
	}
	for _, o := range good {
		if _, err := ParseHTTPOrigin(o); err != nil {
			t.Errorf("ParseHTTPOrigin(%q) refused: %v", o, err)
		}
	}
	bad := []string{
		"",                                    // empty
		"https://",                            // no host
		"http://api.example.com",              // plain http, non-loopback
		"http://127.0.0.1",                    // loopback without port
		"https://u:p@api.example.com",         // userinfo
		"https://api.example.com/path",        // path in origin
		"https://api.example.com?q=1",         // query in origin
		"https://api.example.com#frag",        // fragment in origin
		"https://api.example.com:99999",       // port out of range
		"https://api.example.com:port",        // non-numeric port
		"https://api.example.com:",            // empty port
		"https://ho st",                       // space
		"https://ho_st",                       // underscore
		"https://-lead",                       // leading hyphen label
		"https://do..ble",                     // empty label
		"https://[::1]:8443",                  // IPv6 literal refused
		"ftp://api.example.com",               // wrong scheme
		"javascript:alert(1)",                 // scheme abuse
		"https://" + strings.Repeat("a", 300), // too long
	}
	for _, o := range bad {
		if _, err := ParseHTTPOrigin(o); err == nil {
			t.Errorf("ParseHTTPOrigin(%q) accepted", o)
		}
	}
}

// ValidateHTTPPath is the only agent-supplied degree of freedom. Smuggling
// grammars (percent escapes, dot segments, query/fragment, control bytes)
// must be unrepresentable.
func TestValidateHTTPPathGrammar(t *testing.T) {
	good := []string{
		"/v1/repos/o/r",
		"/user@example.com/profile",
		"/a/b/c.d-e~f$&g+h,i;j=k",
		"/",
	}
	for _, p := range good {
		if err := ValidateHTTPPath(p); err != nil {
			t.Errorf("ValidateHTTPPath(%q) refused: %v", p, err)
		}
	}
	bad := []string{
		"",                             // empty
		"v1/x",                         // no leading slash
		"/x//y",                        // empty segment
		"/a/../b",                      // dot-dot segment
		"/a/./b",                       // dot segment
		"/x?query=1",                   // query
		"/x#frag",                      // fragment
		"/x%2Fy",                       // percent escape
		"/x\r\nInject: 1",              // header smuggling
		"/x\x00",                       // NUL
		"/" + strings.Repeat("a", 600), // too long
	}
	for _, p := range bad {
		if err := ValidateHTTPPath(p); err == nil {
			t.Errorf("ValidateHTTPPath(%q) accepted", p)
		}
	}
}

// The full Execute path against a live pinned origin: authorization header
// only placement, projection shape, and refusals.
func TestHTTPRequestExecute(t *testing.T) {
	if _, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Skip("sandbox denies local TCP listeners")
	}
	const marker = "SECRET-HTTP-pin-7c1d2e3f4a5b"
	origin := ""
	redirectTarget := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirected":
			_, _ = w.Write([]byte(`{"echo":"` + r.Header.Get("Authorization") + `"}`))
		case "/redirect":
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		case "/missing":
			http.NotFound(w, r)
		default:
			if r.Header.Get("Authorization") != "Bearer "+marker {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status_field":"ok","count":3,"tags":["a","b"],"nested":{"secret":"x"},"echo":"` + r.Header.Get("Authorization") + `"}`))
		}
	}))
	defer srv.Close()
	origin = srv.URL
	redirectTarget = srv.URL + "/redirected"

	dest := &types.Destination{ID: "d1", Type: DestTypeHTTPPinned, Endpoint: origin}
	d, err := Lookup("http.request")
	if err != nil {
		t.Fatal(err)
	}

	res, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Target: "d1", Dest: dest,
			Params: map[string]string{"path": "/v1/thing"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), marker) {
		t.Fatalf("reflected credential reached model-visible output: %s", raw)
	}
	// Only projected top-level fields survive; the nested object and the
	// echoed header are dropped by the shape projection.
	for k := range res.Data {
		switch k {
		case "status_field", "count", "tags":
		default:
			t.Fatalf("unexpected key %q in model output", k)
		}
	}
	if res.Data["status_field"] != "ok" || res.Data["count"] != 3.0 {
		t.Fatalf("projection lost scalar fields: %v", res.Data)
	}
	if tags, ok := res.Data["tags"].([]interface{}); !ok || len(tags) != 2 {
		t.Fatalf("projection lost the flat array: %v", res.Data["tags"])
	}

	// Failure statuses surface the status code, never upstream body text.
	if _, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Target: "d1", Dest: dest,
			Params: map[string]string{"path": "/missing"}}); err == nil ||
		!strings.Contains(err.Error(), "404") {
		t.Fatalf("want status-code refusal, got %v", err)
	}

	// Redirects are refused: a credentialed GET must not follow the remote.
	if _, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Target: "d1", Dest: dest,
			Params: map[string]string{"path": "/redirect"}}); err == nil {
		t.Fatal("credentialed redirect was followed")
	}

	// The agent cannot steer the request off the pin: an invalid path is
	// refused before any network I/O.
	for _, p := range []string{"", "no-slash", "/a//b", "/a/../b", "/x?y=1"} {
		if _, err := d.Execute(context.Background(), Credential{Value: marker},
			UseInput{Operation: "http.request", Target: "d1", Dest: dest,
				Params: map[string]string{"path": p}}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}

	// A wrong-type destination fails closed.
	if _, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Target: "d1",
			Dest:   &types.Destination{ID: "d2", Type: "file", Endpoint: "/tmp/x"},
			Params: map[string]string{"path": "/v1"}}); err == nil {
		t.Fatal("file destination accepted by http.request")
	}
	// A non-https origin is refused even as a registered destination.
	if _, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Target: "d1",
			Dest:   &types.Destination{ID: "d3", Type: DestTypeHTTPPinned, Endpoint: "http://api.example.com"},
			Params: map[string]string{"path": "/v1"}}); err == nil {
		t.Fatal("plain-http origin accepted")
	}
	// Missing destination fails closed.
	if _, err := d.Execute(context.Background(), Credential{Value: marker},
		UseInput{Operation: "http.request", Params: map[string]string{"path": "/v1"}}); err == nil {
		t.Fatal("missing destination accepted")
	}
	// Empty credential fails closed.
	if _, err := d.Execute(context.Background(), Credential{},
		UseInput{Operation: "http.request", Target: "d1", Dest: dest,
			Params: map[string]string{"path": "/v1/thing"}}); err == nil {
		t.Fatal("empty credential accepted")
	}
}

// Registration-time validation runs the same grammar, so a malformed pin
// is refused when the operator registers it, not after an approval exists.
func TestHTTPRequestDestinationValidation(t *testing.T) {
	d, err := Lookup("http.request")
	if err != nil {
		t.Fatal(err)
	}
	if !d.RequiresDestination() {
		t.Fatal("http.request must require a destination")
	}
	if err := d.Validate(UseInput{Params: map[string]string{"path": "/ok"}}); err != nil {
		t.Fatalf("submission-time validation refused a valid path: %v", err)
	}
	if err := d.Validate(UseInput{Params: map[string]string{"path": "bad"}}); err == nil {
		t.Fatal("submission-time validation accepted an invalid path")
	}
}

// Unknown param keys are already refused by the shared admission gate;
// this pins the http.request allowlist itself.
func TestHTTPRequestAllowedParams(t *testing.T) {
	d, _ := Lookup("http.request")
	if got := strings.Join(d.AllowedParams(), ","); got != "path" {
		t.Fatalf("AllowedParams = %q, want only path", got)
	}
	if d.Completion() != ResponseValidated {
		t.Fatal("read-only http.request must be ResponseValidated")
	}
	if _, err := Lookup("http.post"); err == nil {
		t.Fatal("a state-changing http operation must not exist")
	}
	if _, err := Lookup("http.raw"); err == nil {
		t.Fatal("an arbitrary-URL http operation must not exist")
	}
}
