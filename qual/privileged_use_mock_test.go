//go:build linux

package qual

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
)

// mockUpstream is the synthetic cross-broker fixture for the synthetic
// AegisKeys credential tier. It replaces a real AegisKeys deployment and a
// real credentialed provider with two in-process stdlib servers that speak
// the same wire contracts:
//
//   - the AegisKeys side serves HTTP-over-Unix /v1/status and /v2/resolve
//     exactly as internal/aegiskeys expects, rotates once after the first
//     authorized resolve, and durably appends one JSON line per resolve
//     (binding identity only — never a credential value);
//   - the provider side is the real credential-consuming application: any
//     HTTP GET whose bearer token matches the currently authorized value
//     gets a JSON response that deliberately echoes the credential both
//     literally and through JSON string escapes (the adversarial-echo
//     fixture required by qual/PRIVILEGED.md), while rotated-away values
//     are rejected with 401. Every request is recorded (path + bearer
//     digest) in a JSON-lines log the harness reads back as independent
//     observation.
//
// Both servers hold credential values only in memory. Only digests are
// written to retained evidence. The synthetic vault file is the durable
// backing store the mock loads at start, so the file-denial checks have a
// real protected target exactly like a live deployment.
type mockUpstream struct {
	mu sync.Mutex

	binding     string
	cred1       string
	cred2       string
	rotated     bool
	resolveSeq  int
	resolveLog  string
	providerLog string

	aegisLis *net.UnixListener
	provLis  net.Listener
	server   *http.Server
	provSrv  *http.Server
}

const (
	mockVaultPath = "vault.enc"
	mockMetaPath  = "broker.json"
)

func newMockUpstream(logsDir string, cred1, cred2 string) *mockUpstream {
	return &mockUpstream{
		binding:     "qual/synthetic",
		cred1:       cred1,
		cred2:       cred2,
		resolveLog:  filepath.Join(logsDir, "aegis-resolves.jsonl"),
		providerLog: filepath.Join(logsDir, "provider-requests.jsonl"),
	}
}

// startAegis creates the unix-socket AegisKeys endpoint. The socket and its
// directory are root-owned with the service group only, so the real broker
// service UID connects and the agent UID is denied at the kernel boundary.
// The credential is loaded from the root-owned synthetic vault file, so the
// file genuinely backs the served value (file-denial checks stay honest).
func (m *mockUpstream) startAegis(sockPath, vaultPath string, serviceGID uint32) error {
	stored, err := readSyntheticVaultFile(vaultPath)
	if err != nil {
		return err
	}
	if stored != m.cred1 {
		return fmt.Errorf("synthetic vault does not back the served credential")
	}
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return err
	}
	m.aegisLis = lis
	// connect(2) on a unix socket needs write permission on the inode, so
	// the socket itself must carry the service group, not just the
	// containing directory. -1 keeps the existing owner untouched (root in
	// the privileged tier, the harness user in the contract test).
	if err := os.Chown(sockPath, -1, int(serviceGID)); err != nil {
		return err
	}
	if err := os.Chmod(sockPath, 0660); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", m.handleStatus)
	mux.HandleFunc("/v2/resolve", m.handleResolveV2)
	mux.HandleFunc("/v1/resolve", m.handleResolveV1)
	m.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = m.server.Serve(lis) }()
	return nil
}

// startProvider begins the loopback TCP provider and returns its pinned
// origin in the http://127.0.0.1:<port> form ParseHTTPOrigin accepts.
func (m *mockUpstream) startProvider() (string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	m.provLis = lis
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleProvider)
	m.provSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = m.provSrv.Serve(lis) }()
	return "http://" + lis.Addr().String(), nil
}

// origin returns the provider's pinned loopback origin.
func (m *mockUpstream) origin() string {
	if m.provLis == nil {
		return ""
	}
	return "http://" + m.provLis.Addr().String()
}

// replayProviderGet sends one direct GET with an explicit bearer value and
// returns the HTTP status. Trusted-harness fixture validation only.
func replayProviderGet(t *testing.T, origin, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, origin+"/qual", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (m *mockUpstream) close() {
	if m.server != nil {
		_ = m.server.Close()
	}
	if m.provSrv != nil {
		_ = m.provSrv.Close()
	}
	if m.aegisLis != nil {
		_ = m.aegisLis.Close()
	}
	if m.provLis != nil {
		_ = m.provLis.Close()
	}
}

func writeJSONLine(path string, value map[string]interface{}) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	raw, err := json.Marshal(value)
	if err == nil {
		_, _ = f.Write(append(raw, '\n'))
	}
	_ = f.Close()
}

func (m *mockUpstream) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"protocol": "v1", "locked": false})
}

// bearerOf extracts the credential value the caller presented. The mock
// never validates anything but the exact current value: this is a fixture
// with one binding and one secret, not an identity system.
func bearerOf(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}

// handleResolveV2 implements the AegisKeys v2 resolve contract: binding
// echo, kind, and the current value. The first resolve returns the
// original synthetic value; every later resolve returns the rotated value
// and marks the rotation visible to the provider. Resolve counts land in
// the durable JSON-lines log — binding identity and sequence only.
func (m *mockUpstream) handleResolveV2(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Binding string `json:"binding"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if body.Binding != m.binding {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	m.resolveSeq++
	value := m.cred1
	if m.resolveSeq >= 2 {
		value = m.cred2
		m.rotated = true
	}
	writeJSONLine(m.resolveLog, map[string]interface{}{
		"seq": m.resolveSeq, "binding": body.Binding, "kind": "api-key",
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"protocol": "v2", "binding": body.Binding, "kind": "api-key", "value": value,
	})
}

// handleResolveV1 answers 404 so a real client keeps the v2 path; the
// fallback contract is exercised by unit tests, not by this fixture.
func (m *mockUpstream) handleResolveV1(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

// handleProvider is the real credential-consuming application. It admits
// only the currently authorized bearer value; once rotation has happened
// the prior value is rejected with 401 (the rotation scenario's
// "provider rejects the prior value" requirement). The 200 response
// deliberately echoes the credential literally ("echo") and through JSON
// string escapes ("escaped") so the broker's closed projection must drop
// both instead of redacting or passing them through. Requests are recorded
// with the bearer digest only.
func (m *mockUpstream) handleProvider(w http.ResponseWriter, r *http.Request) {
	bearer := bearerOf(r)
	m.mu.Lock()
	authorized := bearer == m.cred1 || bearer == m.cred2
	rotated := m.rotated
	prior := bearer == m.cred1
	m.mu.Unlock()
	sum := sha256.Sum256([]byte(bearer))
	admitted := authorized && !(rotated && prior)
	writeJSONLine(m.providerLog, map[string]interface{}{
		"path": r.URL.Path, "bearer_sha256": hex.EncodeToString(sum[:]),
		"authorized": authorized, "admitted": admitted,
	})
	if !admitted {
		if !authorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// The rotation contract: once the value has rotated, the prior
		// value is no longer accepted by the consuming application.
		http.Error(w, "rotated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"service": "qual-mock-provider",
		"path":    r.URL.Path,
		"rotated": rotated,
		"echo":    "Bearer " + bearer,
		"escaped": "\tBearer " + bearer + "\n",
	})
}

// resolveCount reads the durable resolve log: the independent record of
// how many times AegisKeys actually resolved the binding.
func (m *mockUpstream) resolveCount() (int, error) {
	return countJSONLines(m.resolveLog)
}

type providerRequest struct {
	Path         string `json:"path"`
	BearerSHA256 string `json:"bearer_sha256"`
	Authorized   bool   `json:"authorized"`
	Admitted     bool   `json:"admitted"`
}

// providerRequests reads the durable provider request log.
func (m *mockUpstream) providerRequests() ([]providerRequest, error) {
	raw, err := os.ReadFile(m.providerLog)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []providerRequest
	for _, line := range splitLines(string(raw)) {
		var req providerRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			return nil, fmt.Errorf("provider log line invalid: %w", err)
		}
		out = append(out, req)
	}
	return out, nil
}

// TestMockUpstreamContract validates the synthetic fixture on its own,
// without root or UID separation: the AegisKeys wire contract (status,
// v2 resolve, rotation, access denial), the provider admission contract
// (current value admitted, prior value rejected after rotation, unknown
// rejected), and the digest-only observation logs.
func TestMockUpstreamContract(t *testing.T) {
	dir := t.TempDir()
	cred1 := "SEQPASS-QUAL-CRED1-" + strings.Repeat("a", 32)
	cred2 := "SEQPASS-QUAL-CRED2-" + strings.Repeat("b", 32)
	vaultPath := filepath.Join(dir, mockVaultPath)
	if err := writeSyntheticVaultFile(vaultPath, cred1); err != nil {
		t.Fatal(err)
	}
	// Negative control: a vault that does not back the served credential
	// must refuse startup — otherwise the file-denial checks in the
	// privileged tier would guard an empty fixture.
	badVault := filepath.Join(dir, "bad.enc")
	if err := writeSyntheticVaultFile(badVault, "wrong"); err != nil {
		t.Fatal(err)
	}
	up := newMockUpstream(dir, cred1, cred2)
	defer up.close()
	if err := up.startAegis(filepath.Join(dir, "aegis.sock"), badVault, uint32(os.Getegid())); err == nil {
		t.Fatal("startAegis accepted a vault that does not back the credential")
	}
	if err := up.startAegis(filepath.Join(dir, "aegis.sock"), vaultPath, uint32(os.Getegid())); err != nil {
		t.Fatal(err)
	}
	origin, err := up.startProvider()
	if err != nil {
		t.Fatal(err)
	}

	cli, err := aegiskeys.ConnectSocket(filepath.Join(dir, "aegis.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Status(ctx); err != nil {
		t.Fatalf("status: %v", err)
	}
	mat1, err := cli.Resolve(ctx, "qual/synthetic", "http.request", "op-1")
	if err != nil || mat1.Value != cred1 {
		t.Fatalf("first resolve = %q, %v", mat1.Value, err)
	}
	mat2, err := cli.Resolve(ctx, "qual/synthetic", "http.request", "op-2")
	if err != nil || mat2.Value != cred2 {
		t.Fatalf("second resolve = %q, %v, want rotated value", mat2.Value, err)
	}
	if _, err := cli.Resolve(ctx, "qual/other", "http.request", "op-3"); !errors.Is(err, aegiskeys.ErrAccessDenied) {
		t.Fatalf("unknown binding = %v, want access denied", err)
	}

	// Provider admission: current value in, prior value rejected after
	// rotation, unknown value rejected.
	if got := replayProviderGet(t, origin, cred2); got != 200 {
		t.Fatalf("current value status = %d, want 200", got)
	}
	if got := replayProviderGet(t, origin, cred1); got != 401 {
		t.Fatalf("prior value status after rotation = %d, want 401", got)
	}
	if got := replayProviderGet(t, origin, "bogus"); got != 401 {
		t.Fatalf("unknown value status = %d, want 401", got)
	}

	// Observation logs carry identities and digests only. The unknown
	// binding was refused before logging, so only the two authorized
	// resolutions appear — the count counts authorized resolutions.
	n, err := up.resolveCount()
	if err != nil || n != 2 {
		t.Fatalf("resolve log = %d, %v, want 2", n, err)
	}
	requests, err := up.providerRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 {
		t.Fatalf("provider log = %d requests, want 3", len(requests))
	}
	if requests[0].BearerSHA256 != sha256Hex([]byte(cred2)) || !requests[0].Admitted {
		t.Fatalf("first provider request mismatch: %+v", requests[0])
	}
	if requests[1].Admitted || requests[1].BearerSHA256 != sha256Hex([]byte(cred1)) {
		t.Fatalf("replay request mismatch: %+v", requests[1])
	}
	logRaw, err := os.ReadFile(filepath.Join(dir, "aegis-resolves.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logRaw, []byte(cred1)) || bytes.Contains(logRaw, []byte(cred2)) {
		t.Fatal("resolve log carries credential material")
	}
}
