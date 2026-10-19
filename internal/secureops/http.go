package secureops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func init() {
	Register(&httpRequest{})
}

// Pinned HTTP request profiles (objective §7): the trusted destination
// registration pins the origin; the agent supplies only a strictly
// validated path. There is deliberately no operation that lets the agent
// choose an arbitrary URL, method, header or body — a credentialed broker
// that forwards model-chosen destinations is a credential-exfiltration
// service, not a broker.
//
// What is pinned where:
//   - origin (scheme + host + port): destination endpoint, registered by
//     the operator on the admin surface, digest-bound into every approval.
//   - method: GET (read-only profile only). A state-changing HTTP profile
//     must be a typed driver with a real verifier, not a method parameter.
//   - credential placement: Authorization: Bearer <value> — the only
//     placement, so a profile that would need the credential in the URL
//     is structurally impossible, not merely discouraged.
//   - response budget: 15 s timeout, 256 KiB read cap, redirects refused
//     (a credentialed GET must never follow the remote elsewhere).
//   - output projection: the DTO is the closed shape below — top-level
//     scalar fields and flat arrays of scalars, bounded — never arbitrary
//     nested passthrough, and never redacted free-form output.

const (
	httpPathMax     = 512
	httpBodyMax     = 256 * 1024
	httpTimeout     = 15 * time.Second
	httpMaxFields   = 32
	httpMaxFieldStr = 512
	httpMaxArrayLen = 64
	httpOriginMax   = 255
)

// Destination type string for pinned HTTP origins. Registered on the admin
// surface; the endpoint must satisfy ParseHTTPOrigin.
const DestTypeHTTPPinned = "http-pinned"

// ParseHTTPOrigin validates a pinned origin: https://host[:port], no
// userinfo, no path, query or fragment. Plain http is accepted only for
// the loopback literals with an explicit port, so a qualification harness
// can point a profile at an httptest server without weakening production
// origins.
func ParseHTTPOrigin(raw string) (string, error) {
	if raw == "" || len(raw) > httpOriginMax {
		return "", errors.New("invalid origin: empty or too long")
	}
	rest := ""
	https := false
	switch {
	case strings.HasPrefix(raw, "https://"):
		https = true
		rest = raw[len("https://"):]
	case strings.HasPrefix(raw, "http://127.0.0.1:"),
		strings.HasPrefix(raw, "http://[::1]:"),
		strings.HasPrefix(raw, "http://localhost:"):
		rest = raw[len("http://"):]
	default:
		return "", errors.New("invalid origin: want https://host[:port] (loopback http allowed with explicit port)")
	}
	// Userinfo, path, query and fragment separators are all refused: the
	// pinned fact is exactly scheme + host + port.
	if rest == "" || strings.ContainsAny(rest, "@/?#") {
		return "", errors.New("invalid origin: want bare scheme://host[:port]")
	}
	host, port := rest, ""
	hasPort := false
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.HasSuffix(rest, "]") {
		host, port = rest[:i], rest[i+1:]
		hasPort = true
	}
	if hasPort {
		if port == "" || len(port) > 5 {
			return "", errors.New("invalid origin: port out of range")
		}
		n := 0
		for _, r := range port {
			if r < '0' || r > '9' {
				return "", errors.New("invalid origin: port must be numeric")
			}
			n = n*10 + int(r-'0')
		}
		if n < 1 || n > 65535 {
			return "", errors.New("invalid origin: port out of range")
		}
	} else if !https {
		return "", errors.New("invalid origin: loopback http requires an explicit port")
	}
	if host == "" || len(host) > httpOriginMax-8 {
		return "", errors.New("invalid origin: host missing or too long")
	}
	// Bracketed IPv6 literals are refused for determinism; names and IPv4
	// literals use the strict label grammar below.
	if strings.ContainsAny(host, "[]:") {
		return "", errors.New("invalid origin: malformed hostname")
	}
	if len(host) > 0 && (host[0] == '-' || host[0] == '.') || strings.Contains(host, "..") {
		return "", errors.New("invalid origin: malformed hostname")
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return "", errors.New("invalid origin: malformed hostname")
		}
	}
	return raw, nil
}

// ValidateHTTPPath enforces the only agent-supplied degree of freedom:
// a relative path built from RFC 3986 pchar bytes plus "/". No percent
// escapes (encoding tricks), no query or fragment, no ".." segment, no
// control characters — so header or request smuggling through the path
// is unrepresentable, and the value is safe to appear in the resource
// descriptor and audit trail.
func ValidateHTTPPath(raw string) error {
	if raw == "" || len(raw) > httpPathMax {
		return errors.New("invalid path: empty or too long")
	}
	if raw[0] != '/' {
		return errors.New("invalid path: must start with /")
	}
	if strings.Contains(raw, "//") {
		return errors.New("invalid path: empty segment")
	}
	for _, seg := range strings.Split(raw[1:], "/") {
		if seg == ".." || seg == "." {
			return errors.New("invalid path: dot segment")
		}
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-._~!$&'()*+,;=:@/", r):
		default:
			return errors.New("invalid path: unsupported character")
		}
	}
	return nil
}

type httpRequest struct{}

func (h *httpRequest) Name() string               { return "http.request" }
func (h *httpRequest) Completion() CompletionMode { return ResponseValidated }
func (h *httpRequest) RequiresDestination() bool  { return true }
func (h *httpRequest) Describe() DriverInfo {
	return DriverInfo{
		Description:  "Authorized GET against a pinned HTTPS origin (operator-registered); credential sent only as the bearer token, projected response only",
		Params:       []ParamInfo{{Name: "path", Description: "Absolute path on the pinned origin (plain characters, no query/fragment)"}},
		ResourceKind: "http.endpoint",
		Completion:   ResponseValidated,
		Destination:  true,
	}
}
func (h *httpRequest) AllowedParams() []string { return []string{"path"} }

func (h *httpRequest) Resource(params map[string]string) ResourceDescriptor {
	if err := ValidateHTTPPath(params["path"]); err != nil {
		return ResourceDescriptor{Kind: "http.endpoint", Identifier: "invalid"}
	}
	return ResourceDescriptor{Kind: "http.endpoint", Identifier: params["path"]}
}

func (h *httpRequest) Validate(in UseInput) error {
	if err := ValidateHTTPPath(in.Params["path"]); err != nil {
		return err
	}
	// Origin validation needs the destination record; at submission time it
	// is absent, and Execute re-checks everything with it present. The nil
	// case must not validate the endpoint loosely.
	if in.Dest != nil {
		_, err := ParseHTTPOrigin(in.Dest.Endpoint)
		return err
	}
	return nil
}

func (h *httpRequest) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
	if cred.Value == "" {
		return SafeResult{}, errors.New("no credential")
	}
	if in.Dest == nil {
		// Fail closed: without the pinned origin there is nothing to
		// authorize the request against.
		return SafeResult{}, errors.New("pinned destination missing")
	}
	if in.Dest.Type != DestTypeHTTPPinned {
		return SafeResult{}, fmt.Errorf("destination type %q is not %s", in.Dest.Type, DestTypeHTTPPinned)
	}
	origin, err := ParseHTTPOrigin(in.Dest.Endpoint)
	if err != nil {
		return SafeResult{}, err
	}
	if err := ValidateHTTPPath(in.Params["path"]); err != nil {
		return SafeResult{}, err
	}
	// URL assembled from two independently validated components.
	url := origin + in.Params["path"]

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return SafeResult{}, errors.New("request build failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.Value)
	// Redirects disabled: a credentialed GET must never follow the remote
	// server to another endpoint.
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects disabled for credentialed operations")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never surface transport diagnostics that could carry
		// credential-bearing headers or URLs.
		return SafeResult{}, errors.New("upstream request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return SafeResult{}, fmt.Errorf("http request failed with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpBodyMax+1))
	if err != nil {
		return SafeResult{}, errors.New("invalid response")
	}
	if len(body) > httpBodyMax {
		return SafeResult{}, errors.New("response too large")
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return SafeResult{}, errors.New("invalid response: want a JSON object")
	}
	return SafeResult{
		Summary: fmt.Sprintf("http request completed (status %d)", resp.StatusCode),
		Data:    projectFlat(doc, cred.Value),
	}, nil
}

// projectFlat is the closed response projection: top-level scalar fields
// and flat arrays of scalars only, bounded. Nested objects and arrays of
// arrays are dropped, not redacted — remote text is untrusted data and
// the agent-visible contract stays a known shape. JSON numbers arrive as
// float64 from encoding/json and are passed through; the shared
// ValidateSafeResult gate still bounds the whole result at the service
// boundary.
//
// cred is the resolved credential: a hostile or misbehaving origin can
// reflect the bearer token into response fields, so any projected value
// that contains it is dropped outright (the same construction-time
// discipline as the typed drivers, which project only named fields).
// This is a projection decision, not output redaction: nothing is
// partially masked or re-encoded.
func projectFlat(doc map[string]interface{}, cred string) map[string]interface{} {
	out := make(map[string]interface{}, len(doc))
	n := 0
	for k, v := range doc {
		if n >= httpMaxFields || k == "" || len(k) > maxKeyLen || strings.Contains(k, cred) {
			continue
		}
		switch t := v.(type) {
		case nil, bool, float64:
			out[k] = t
			n++
		case string:
			if strings.Contains(t, cred) {
				continue
			}
			out[k] = truncate(t, httpMaxFieldStr)
			n++
		case []interface{}:
			if len(t) > httpMaxArrayLen {
				continue
			}
			flat := make([]interface{}, 0, len(t))
			ok := true
			for _, e := range t {
				switch ev := e.(type) {
				case nil, bool, float64:
					flat = append(flat, ev)
				case string:
					if strings.Contains(ev, cred) {
						ok = false
						break
					}
					flat = append(flat, truncate(ev, httpMaxFieldStr))
				default:
					ok = false
				}
				if !ok {
					break
				}
			}
			if ok {
				out[k] = flat
				n++
			}
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) > max {
		r := []rune(s)
		if len(r) > max {
			r = r[:max]
		}
		return string(r)
	}
	return s
}
