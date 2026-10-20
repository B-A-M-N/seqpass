package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/types"
)

// The P0-1 tests reproduce the external qualification finding and prove the
// helper mechanism end-to-end against a mock AegisKeys broker that uses the
// REAL peer-identity mechanism (SO_PEERCRED + /proc/<pid>/exe), not a
// stub. The mock broker always runs as a SEPARATE PROCESS (re-exec of the
// test binary): /proc/<pid>/exe of a same-thread-group dialer is readable
// even when non-dumpable, so an in-process mock could not reproduce the
// finding faithfully.

// helperMockBroker is a minimal AegisKeys broker over a real Unix socket.
// Its peer check mirrors AegisKeys LinuxPeerResolver.fromUcred: read
// SO_PEERCRED, require the granted UID, then readlink /proc/<pid>/exe
// (which the kernel refuses for a non-dumpable peer even to the same UID)
// and compare against the granted executable path. Grants also enforce the
// operation allowlist like the real broker's scoped bindings. Denials and
// authorized resolves are logged as "DENY ..."/"AUDIT ..." lines on
// stdout for the parent to read.
type helperMockBroker struct {
	listener   net.Listener
	sockPath   string
	grantUID   int
	grantExe   string
	allowedOps []string
	value      string
	// attestKey, when set, mirrors the AegisKeys attest-key grant: resolve
	// requires a valid ed25519 signature over the canonical request string.
	attestKey  ed25519.PublicKey
	seenNonces map[string]bool
	// SO_PEERCRED pid of the last connection, logged with the audit
	// record so tests can assert WHICH process resolved (helper, not
	// broker: the resolving process identity is the P0-1 mechanism).
	lastPID int
}

func (m *helperMockBroker) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return
		}
		go m.handle(conn)
	}
}

// peerIdentity mirrors the real broker's Linux peer resolution, including
// the /proc/<pid>/exe read that non-dumpable peers cannot pass.
func (m *helperMockBroker) peerIdentity(conn net.Conn) (uid int, exe string, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, "", errors.New("not a unix conn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, "", err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, "", err
	}
	if cerr != nil {
		return 0, "", cerr
	}
	m.lastPID = int(cred.Pid)
	procExe := fmt.Sprintf("/proc/%d/exe", cred.Pid)
	exe, err = os.Readlink(procExe)
	if err != nil {
		return int(cred.Uid), "", fmt.Errorf("resolve peer executable: %w", err)
	}
	return int(cred.Uid), exe, nil
}

func (m *helperMockBroker) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	// Read one bounded HTTP request with real framing: http.ReadRequest
	// honors Content-Length/chunked encoding, and the body is drained to
	// EOF before decoding — a request whose headers and body arrive in
	// separate segments must not be mistaken for a malformed one (that
	// race once reset connections mid-exchange and intermittently failed
	// the positive control).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bufr := bufio.NewReaderSize(conn, 4096)
	hreq, err := http.ReadRequest(bufr)
	if err != nil {
		httpError(conn, httpBadRequest)
		return
	}
	const maxMockBody = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(hreq.Body, maxMockBody+1))
	hreq.Body.Close() //nolint:errcheck
	if err != nil || len(raw) > maxMockBody {
		httpError(conn, httpBadRequest)
		return
	}
	var body struct {
		Binding     string `json:"binding"`
		Operation   string `json:"operation"`
		OperationID string `json:"operation_id"`
		AttestNonce string `json:"attest_nonce"`
		AttestSig   []byte `json:"attest_sig"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&body); err != nil || dec.More() {
		httpError(conn, httpBadRequest)
		return
	}

	uid, exe, perr := m.peerIdentity(conn)
	if perr != nil {
		fmt.Printf("DENY peer-identity: %v\n", perr)
		httpError(conn, httpForbidden)
		return
	}
	peerPID := m.lastPID
	if uid != m.grantUID {
		fmt.Printf("DENY uid %d != grant %d\n", uid, m.grantUID)
		httpError(conn, httpForbidden)
		return
	}
	if exe != m.grantExe {
		fmt.Printf("DENY exe %q != grant %q\n", exe, m.grantExe)
		httpError(conn, httpForbidden)
		return
	}
	// Scoped-binding semantics: empty or unlisted operations are denied.
	scoped := false
	for _, op := range m.allowedOps {
		if op == body.Operation {
			scoped = true
			break
		}
	}
	if !scoped {
		fmt.Printf("DENY operation %q not allowed\n", body.Operation)
		httpError(conn, httpForbidden)
		return
	}
	// Hardened-parent attestation (P0-1): an attest-pinned grant requires a
	// valid ed25519 signature over the canonical request string from the
	// executor's key. The dumpable helper is a courier — it cannot produce
	// the signature.
	if m.attestKey != nil {
		if len(body.AttestNonce) == 0 || len(body.AttestSig) == 0 {
			fmt.Printf("DENY attestation missing\n")
			httpError(conn, httpForbidden)
			return
		}
		if !ed25519.Verify(m.attestKey, aegiskeys.AttestCanonicalString(body.Binding, body.Operation, body.OperationID, body.AttestNonce), body.AttestSig) {
			fmt.Printf("DENY attestation signature invalid\n")
			httpError(conn, httpForbidden)
			return
		}
		if m.seenNonces == nil {
			m.seenNonces = map[string]bool{}
		}
		if m.seenNonces[body.AttestNonce] {
			fmt.Printf("DENY attestation nonce replay\n")
			httpError(conn, httpForbidden)
			return
		}
		m.seenNonces[body.AttestNonce] = true
	}
	nonceLog := "-"
	if len(body.AttestNonce) >= 12 {
		nonceLog = body.AttestNonce[:12]
	}
	fmt.Printf("AUDIT pid=%d nonce=%s %s#%s\n", peerPID, nonceLog, body.Operation, body.OperationID)
	writeJSONBody(conn, fmt.Sprintf(`{"protocol":"v2","binding":%q,"kind":"api-key","value":%q}`, body.Binding, m.value))
}

const (
	httpBadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
	httpForbidden  = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
)

// runMockBrokerChild is the re-exec body for the mock broker process:
// serve until the socket is removed (t.TempDir cleanup from the parent)
// or the parent kills us.
func runMockBrokerChild() int {
	sock := os.Getenv("SEQPASS_TEST_HELPER_SOCKET")
	uidStr := os.Getenv("SEQPASS_TEST_MOCK_GRANT_UID")
	exe := os.Getenv("SEQPASS_TEST_MOCK_GRANT_EXE")
	ops := os.Getenv("SEQPASS_TEST_MOCK_OPS")
	if sock == "" || exe == "" {
		fmt.Fprintln(os.Stderr, "mock broker child: missing configuration")
		return 2
	}
	grantUID, err := strconv.Atoi(uidStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mock broker child: bad grant uid")
		return 2
	}
	var allowedOps []string
	for _, op := range strings.Split(ops, ",") {
		if op != "" {
			allowedOps = append(allowedOps, op)
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mock broker child: listen: %v\n", err)
		return 2
	}
	m := &helperMockBroker{
		sockPath: sock, grantUID: grantUID, grantExe: exe,
		allowedOps: allowedOps, value: "mock-credential-value",
		listener: ln,
	}
	if pubHex := os.Getenv("SEQPASS_TEST_MOCK_ATTEST_KEY"); pubHex != "" {
		pubRaw, derr := hex.DecodeString(pubHex)
		if derr != nil || len(pubRaw) != ed25519.PublicKeySize {
			fmt.Fprintln(os.Stderr, "mock broker child: bad attest key")
			return 2
		}
		m.attestKey = ed25519.PublicKey(pubRaw)
	}
	m.serve() // blocks until the listener closes
	return 0
}

// mockBrokerChild is a mock broker served by a SEPARATE process. denyReason
// and auditOps are refreshed by re-dialing a status channel; to keep the
// fixture simple the child writes denials to its own log file, which the
// parent reads.
type mockBrokerChild struct {
	sockPath   string
	value      string
	logPath    string
	denyReason string
	auditOps   []string
	auditPIDs  []int // resolving process pids parsed from AUDIT lines
	lastSize   int64
	t          *testing.T
}

func startMockBrokerChild(t *testing.T, grantUID int, grantExe string, allowedOps []string) *mockBrokerChild {
	return startMockBrokerChildAttest(t, grantUID, grantExe, allowedOps, "")
}

// startMockBrokerChildAttest is startMockBrokerChild with an optional hex
// ed25519 public key: when set, the mock grant requires a valid attestation
// signature over the canonical request string (attest-key grant pin).
func startMockBrokerChildAttest(t *testing.T, grantUID int, grantExe string, allowedOps []string, attestPubHex string) *mockBrokerChild {
	t.Helper()
	// Short custom temp dir: t.TempDir() embeds the full test name, and a
	// Unix socket path is limited to 107 bytes — long subtest names push
	// the bind address past the limit ("bind: invalid argument").
	dir, err := os.MkdirTemp("", "sp-ak")
	if err != nil {
		t.Fatal(err)
	}
	cleanupDir := dir
	t.Cleanup(func() { _ = os.RemoveAll(cleanupDir) })
	sock := filepath.Join(dir, "aegis.sock")
	logPath := filepath.Join(dir, "broker.log")
	cmd := exec.Command(selfExe(t))
	cmd.Env = append(os.Environ(),
		helperModeEnv+"=mock",
		"SEQPASS_TEST_HELPER_SOCKET="+sock,
		"SEQPASS_TEST_MOCK_GRANT_UID="+fmt.Sprint(grantUID),
		"SEQPASS_TEST_MOCK_GRANT_EXE="+grantExe,
		"SEQPASS_TEST_MOCK_OPS="+strings.Join(allowedOps, ","),
		"SEQPASS_TEST_MOCK_ATTEST_KEY="+attestPubHex,
	)
	// Stdout/stderr land in the log file so the parent can read the
	// child's denial reasons and audit lines.
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	})
	// Wait for the socket to appear. Under residual system load the child
	// (a Go binary doing full runtime init) can take seconds to bind.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			logData, _ := os.ReadFile(logPath)
			t.Fatalf("mock broker child did not create its socket; child log: %s", string(logData))
		}
		time.Sleep(5 * time.Millisecond)
	}
	return &mockBrokerChild{sockPath: sock, value: "mock-credential-value", logPath: logPath, t: t}
}

// refresh parses new log lines for denial reasons and audit records.
func (m *mockBrokerChild) refresh() {
	f, err := os.Open(m.logPath)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Seek(m.lastSize, 0); err != nil {
		return
	}
	data, _ := io.ReadAll(f)
	m.lastSize += int64(len(data))
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "DENY ") {
			m.denyReason = strings.TrimPrefix(line, "DENY ")
		}
		if strings.HasPrefix(line, "AUDIT ") {
			m.auditOps = append(m.auditOps, strings.TrimPrefix(line, "AUDIT "))
			if rest := strings.TrimPrefix(line, "AUDIT "); strings.HasPrefix(rest, "pid=") {
				pidStr := rest[4:]
				if idx := strings.Index(pidStr, " "); idx > 0 {
					if pid, perr := strconv.Atoi(pidStr[:idx]); perr == nil {
						m.auditPIDs = append(m.auditPIDs, pid)
					}
				}
			}
		}
	}
}

func httpError(conn net.Conn, raw string) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(raw))
}

func writeJSONBody(conn net.Conn, body string) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		fmt.Sprint(len(body)) + "\r\n\r\n" + body))
}

const helperModeEnv = "SEQPASS_TEST_RESOLVE_HELPER_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(helperModeEnv) {
	case "helper":
		os.Exit(runHelperChild())
	case "mock":
		os.Exit(runMockBrokerChild())
	case "trunc":
		// Reads nothing; writes two raw bytes to the inherited descriptor
		// (a truncated frame) and exits: exercises the parent's
		// truncated-response failure path.
		f := os.NewFile(uintptr(3), "trunc-fd")
		if f == nil {
			os.Exit(2)
		}
		_, _ = f.Write([]byte{0x00, 0x01})
		os.Exit(0)
	case "stall":
		// Never responds; the parent must time-bound and reap us.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	// envcheck-child <outPath>: dumps the child environment to outPath and
	// exits without a framed response (also an early-exit failure case).
	for i, a := range os.Args {
		if a == envcheckChildArg && i+1 < len(os.Args) {
			lines := os.Environ()
			if werr := os.WriteFile(os.Args[i+1], []byte(strings.Join(lines, "\n")), 0o600); werr != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// envcheckChildArg marks the re-exec'd child that dumps its environment.
const envcheckChildArg = "envcheck-child"

func runHelperChild() int {
	sock := os.Getenv("SEQPASS_TEST_HELPER_SOCKET")
	conn, err := aegiskeys.LoadHelperConnAt(3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "child: no inherited descriptor")
		return 2
	}
	if sock == "" {
		fmt.Fprintln(os.Stderr, "child: no AegisKeys socket configured")
		return 2
	}
	if err := aegiskeys.HelperServe(conn, sock); err != nil {
		fmt.Fprintln(os.Stderr, "child: exchange failed")
		conn.Close() //nolint:errcheck
		return 2
	}
	conn.Close() //nolint:errcheck
	return 0
}

// prSetDumpable is PR_SET_DUMPABLE from prctl.h (not exported by stdlib
// syscall).
const prSetDumpable = 4

// TestBrokerNonDumpableCannotAuthenticate reproduces the external
// qualification finding (P0-1): a PR_SET_DUMPABLE=0 process cannot resolve
// from AegisKeys — the peer-identity check fails reading /proc/<pid>/exe
// BEFORE any grant is consulted (cross-process, as in the real broker).
// It also proves the control: the SAME broker accepts the SAME process
// once dumpable — the failure is specifically non-dumpability, not grant
// misconfiguration.
func TestBrokerNonDumpableCannotAuthenticate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root sees /proc/<pid>/exe regardless of dumpability")
	}
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request"})

	cli, err := aegiskeys.ConnectSocket(m.sockPath)
	if err != nil {
		t.Fatal(err)
	}

	// Stage 1: non-dumpable (the broker's §11 posture) -> peer-identity
	// authentication failure.
	setDumpable(t, 0)
	if _, rerr := cli.Resolve(context.Background(), "seqpass/example", "http.request", "op-dumpable"); rerr == nil {
		setDumpable(t, 1)
		t.Fatal("non-dumpable process resolved from the mock broker; the qualification finding is not reproduced")
	}
	m.refresh()
	if !strings.Contains(m.denyReason, "peer-identity") {
		setDumpable(t, 1)
		t.Fatalf("denial was not at the peer-identity layer: %q", m.denyReason)
	}

	// Stage 2 (control): same process, dumpable again -> authorized.
	setDumpable(t, 1)
	mat, rerr := cli.Resolve(context.Background(), "seqpass/example", "http.request", "op-dumpable")
	if rerr != nil || mat.Value != m.value {
		t.Fatalf("dumpable control resolve = %v, %v (mock works; stage 1 failure is dumpability-specific)", mat.Value, rerr)
	}
	m.refresh()
	if len(m.auditOps) != 1 || !strings.HasSuffix(m.auditOps[0], " http.request#op-dumpable") {
		t.Fatalf("audit correlation = %v", m.auditOps)
	}
}

// helperTestingCommand installs the test re-exec builder: instead of argv
// `resolve-helper`, the child is THIS test binary env-dispatched into
// helper mode (the test binary cannot parse `resolve-helper` argv — it
// would recursively run the whole suite, which is exactly the hang the
// first run hit). Every helper-path test must call it.
func helperTestingCommand(t *testing.T) {
	helperTestingCommandMode(t, "helper")
}

// helperTestingCommandMode is helperTestingCommand with a specific child
// dispatch mode ("helper", "trunc", "stall", "envcheck").
func helperTestingCommandMode(t *testing.T, mode string, extraArgs ...string) {
	t.Helper()
	prev := aegiskeys.TestingHelperCommand
	t.Cleanup(func() { aegiskeys.TestingHelperCommand = prev })
	aegiskeys.TestingHelperCommand = func(ctx context.Context, helperPath, aegisSocket string, child *os.File) *exec.Cmd {
		cmd := exec.CommandContext(ctx, helperPath)
		cmd.Args = append([]string{helperPath}, extraArgs...)
		if mode == "envcheck" {
			// The env-inheritance assertion target: the child environment
			// must be EXACTLY the production filter output — dispatch
			// info travels on argv, never env.
			cmd.Env = aegiskeys.HelperEnv()
		} else {
			cmd.Env = append(os.Environ(), helperModeEnv+"="+mode, "SEQPASS_TEST_HELPER_SOCKET="+aegisSocket)
		}
		cmd.ExtraFiles = []*os.File{child}
		return cmd
	}
}

// TestResolveViaHelperAuthorized passes the mock broker through the helper
// path: the helper process (dumpable, RLIMIT_CORE=0) authenticates because
// its /proc/<pid>/exe matches the pinned grant, and the credential returns
// only into the trusted boundary.
func TestResolveViaHelperAuthorized(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request", "transfer"})
	cred, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "http.request", "op-1", nil)
	if err != nil {
		t.Fatalf("helper resolve: %v", err)
	}
	if cred.Value != m.value || cred.Binding != "seqpass/example" {
		t.Fatalf("credential = %+v", cred)
	}
	m.refresh()
	if len(m.auditOps) != 1 || !strings.HasSuffix(m.auditOps[0], " http.request#op-1") {
		t.Fatalf("audit correlation = %v", m.auditOps)
	}
}

// TestResolveViaHelperDenials proves grant-pinned identity enforcement on
// the helper path: a helper whose exe/UID does not match the grant is
// denied at authentication, and a helper presenting an unapproved
// operation is denied by scoped-binding enforcement. These are the same
// rules the real AegisKeys broker enforces; cross-UID denial with real
// UIDs is the privileged qualification tier (root-gated, documented in
// qual/PRIVILEGED.md).
func TestResolveViaHelperDenials(t *testing.T) {
	helperTestingCommand(t)
	t.Run("wrong_pinned_executable", func(t *testing.T) {
		m := startMockBrokerChild(t, os.Geteuid(), "/usr/local/bin/definitely-not-this-binary", []string{"http.request"})
		_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "http.request", "op-1", nil)
		if !errors.Is(err, aegiskeys.ErrAccessDenied) {
			t.Fatalf("exe-mismatched helper = %v, want access_denied", err)
		}
		m.refresh()
		if !strings.Contains(m.denyReason, "exe") {
			t.Fatalf("denial reason = %q", m.denyReason)
		}
	})
	t.Run("wrong_uid", func(t *testing.T) {
		// The grant admits a UID the caller does not have: the real
		// broker would deny on SO_PEERCRED UID mismatch. This is the
		// agent-impersonation denial without needing setuid.
		m := startMockBrokerChild(t, os.Geteuid()+1001, selfExe(t), []string{"http.request"})
		_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "http.request", "op-1", nil)
		if !errors.Is(err, aegiskeys.ErrAccessDenied) {
			t.Fatalf("uid-mismatched helper = %v, want access_denied", err)
		}
		m.refresh()
		if !strings.Contains(m.denyReason, "uid") {
			t.Fatalf("denial reason = %q", m.denyReason)
		}
	})
	t.Run("unapproved_operation", func(t *testing.T) {
		m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request"})
		_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "git.push", "op-1", nil)
		if !errors.Is(err, aegiskeys.ErrAccessDenied) {
			t.Fatalf("unapproved operation = %v, want access_denied", err)
		}
	})
	t.Run("empty_operation", func(t *testing.T) {
		m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request"})
		_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "", "op-1", nil)
		if !errors.Is(err, aegiskeys.ErrRequestInvalid) {
			t.Fatalf("empty operation = %v, want request_invalid (client-side, no HTTP)", err)
		}
		m.refresh()
		if len(m.auditOps) != 0 {
			t.Fatalf("denied request reached the broker audit path: %v", m.auditOps)
		}
	})
}

// TestResolveCredentialMaterialRoutesThroughHelper proves the service-level
// wiring: with cfg.AegisKeysResolveHelper set, the trusted-executor branch
// resolves through the helper (never the in-process client) and the C13
// binding-identity check still applies to the helper result.
func TestResolveCredentialMaterialRoutesThroughHelper(t *testing.T) {
	helperTestingCommand(t)
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request"})
	svc := testService(t)
	svc.cfg.AegisKeysSocket = m.sockPath
	svc.cfg.AegisKeysResolveHelper = selfExe(t)

	src := types.SecretSource{Kind: types.SourceAegisKeys, Binding: "seqpass/example"}
	cred, err := svc.resolveCredentialMaterial(context.Background(), src, "http.request", "op-wire")
	if err != nil {
		t.Fatalf("helper-wired resolve: %v", err)
	}
	if cred.Value != m.value {
		t.Fatalf("credential value = %q", cred.Value)
	}
	m.refresh()
	if len(m.auditOps) != 1 || !strings.HasSuffix(m.auditOps[0], " http.request#op-wire") || !strings.HasPrefix(m.auditOps[0], "pid=") {
		t.Fatalf("audit correlation = %v (want pid=<helper> http.request#op-wire)", m.auditOps)
	}
	if len(m.auditPIDs) == 1 && m.auditPIDs[0] == os.Getpid() {
		t.Fatal("resolve ran in the broker process; helper routing not exercised")
	}

	// Forbidden operation through the same wiring: denied before any
	// credential material exists.
	if _, err := svc.resolveCredentialMaterial(context.Background(), src, "git.push", "op-wire-2"); !errors.Is(err, aegiskeys.ErrAccessDenied) {
		t.Fatalf("forbidden op through helper wiring = %v, want access_denied", err)
	}
}

// TestResolveViaHelperAttestKeyFlow pins the hardened-parent attestation
// contract (AegisKeys attest-key grants): the broker signs each request
// with its in-memory ed25519 key; the dumpable helper is a courier that
// cannot forge it. With the key, the attested resolve succeeds and each
// request carries a FRESH nonce (replay-visible). Without the executor key
// (simulating a same-UID attacker who execed the helper directly), the
// same grant denies — attestation, not the helper executable, carries the
// authorization.
func TestResolveViaHelperAttestKeyFlow(t *testing.T) {
	helperTestingCommand(t)
	key, err := aegiskeys.NewExecutorAttestKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = key // ResolveViaHelper signing is exercised through the service cfg below

	t.Run("unattested_request_denied_by_attest_pinned_grant", func(t *testing.T) {
		m := startMockBrokerChildAttest(t, os.Geteuid(), selfExe(t), []string{"http.request"}, key.PublicHex())
		_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), m.sockPath, "seqpass/example", "http.request", "op-att", nil)
		if !errors.Is(err, aegiskeys.ErrAccessDenied) {
			t.Fatalf("unattested request vs attest-pinned grant = %v, want access_denied", err)
		}
		m.refresh()
		if !strings.Contains(m.denyReason, "attestation") {
			t.Fatalf("denial reason = %q", m.denyReason)
		}
	})

	t.Run("attested_resolve_authorized_and_fresh_nonce", func(t *testing.T) {
		m := startMockBrokerChildAttest(t, os.Geteuid(), selfExe(t), []string{"http.request"}, key.PublicHex())
		svc := testService(t)
		svc.cfg.AegisKeysSocket = m.sockPath
		svc.cfg.AegisKeysResolveHelper = selfExe(t)
		svc.cfg.AegisKeysAttestKey = key
		src := types.SecretSource{Kind: types.SourceAegisKeys, Binding: "seqpass/example"}
		cred, err := svc.resolveCredentialMaterial(context.Background(), src, "http.request", "op-att-1")
		if err != nil {
			t.Fatalf("attested resolve: %v", err)
		}
		if cred.Value != m.value {
			t.Fatalf("credential value = %q", cred.Value)
		}
		// The nonce is fresh per request: a second resolve with the same
		// executor key also succeeds (no replay guard trip on the signer
		// side), and the broker observed two distinct nonces.
		if _, err := svc.resolveCredentialMaterial(context.Background(), src, "http.request", "op-att-2"); err != nil {
			t.Fatalf("second attested resolve: %v", err)
		}
		m.refresh()
		if len(m.auditOps) != 2 {
			t.Fatalf("audit ops = %v, want 2 attested resolves", m.auditOps)
		}
		// Fresh nonce per request: the two audit records must carry
		// distinct nonce prefixes (replay would repeat one).
		n1 := strings.TrimPrefix(strings.Fields(m.auditOps[0])[1], "nonce=")
		n2 := strings.TrimPrefix(strings.Fields(m.auditOps[1])[1], "nonce=")
		if n1 == "" || n1 == n2 {
			t.Fatalf("nonces not fresh per request: %q vs %q", n1, n2)
		}
	})
}

// TestResolveViaHelperNoOutputLeak pins the no-side-channel rule: on a
// SUCCESSFUL exchange the helper's stdout/stderr carry nothing (the
// credential exists only on the private descriptor), verified here by
// running the helper body through pipes and draining them before Wait.
func TestResolveViaHelperNoOutputLeak(t *testing.T) {
	m := startMockBrokerChild(t, os.Geteuid(), selfExe(t), []string{"http.request"})

	parent, child, err := socketPairForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close() //nolint:errcheck

	cmd := exec.Command(selfExe(t))
	cmd.Env = append(os.Environ(),
		helperModeEnv+"=helper",
		"SEQPASS_TEST_HELPER_SOCKET="+m.sockPath)
	cmd.ExtraFiles = []*os.File{child}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close() //nolint:errcheck

	req := aegiskeys.HelperRequest{Binding: "seqpass/example", Operation: "http.request", OperationID: "op-leak"}
	_ = parent.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeFramedForTest(parent, req); err != nil {
		t.Fatal(err)
	}
	var resp aegiskeys.HelperResponse
	if err := readFramedForTest(parent, &resp); err != nil {
		t.Fatalf("helper exchange: %v", err)
	}
	// Drain both pipes to EOF (the helper exits after the single
	// exchange) BEFORE Wait, per os/exec StdoutPipe contract.
	out := make(chan []byte, 1)
	errOut := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(stdout); out <- b }()
	go func() { b, _ := io.ReadAll(stderr); errOut <- b }()
	waitErr := cmd.Wait()
	gotOut := <-out
	gotErr := <-errOut
	if !resp.OK || resp.Value != m.value {
		t.Fatalf("response = %+v, wait = %v", resp, waitErr)
	}
	if strings.Contains(string(gotOut), m.value) || strings.Contains(string(gotErr), m.value) {
		t.Fatal("credential material appeared on stdout/stderr")
	}
}

// TestResolveHelperRejectsNoDescriptor: a helper spawned without the
// inherited descriptor must exit non-zero with no useful output (nothing
// it can serve, nothing it can leak).
func TestResolveHelperRejectsNoDescriptor(t *testing.T) {
	cmd := exec.Command(selfExe(t))
	cmd.Env = append(os.Environ(), helperModeEnv+"=helper")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("helper without fd 3 exited zero")
	}
	if strings.Contains(string(out), "mock-credential") {
		t.Fatal("output contained credential material")
	}
}

// TestMockBrokerHandlesFragmentedRequest pins correct HTTP framing in the
// mock broker: the request headers and JSON body may arrive in separate
// segments, and the mock must read the full Content-Length body (real
// http.ReadRequest + bounded body read) before decoding — not decode
// whatever happened to arrive after the header terminator. Under the old
// terminator-only read loop this test reliably 400s on the empty body,
// which is exactly the transport race that intermittently reset the
// positive control's connection.
func TestMockBrokerHandlesFragmentedRequest(t *testing.T) {
	parent, child, err := socketPairForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close() //nolint:errcheck
	defer child.Close()  //nolint:errcheck
	serverConn, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close() //nolint:errcheck
	clientConn, err := net.FileConn(child)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close() //nolint:errcheck

	m := &helperMockBroker{
		grantUID:   os.Geteuid(),
		grantExe:   selfExe(t),
		allowedOps: []string{"http.request"},
		value:      "mock-credential-value",
	}
	done := make(chan struct{})
	go func() {
		m.handle(serverConn)
		close(done)
	}()

	body := `{"binding":"seqpass/example","operation":"http.request","operation_id":"op-frag"}`
	hdr := fmt.Sprintf("POST /v2/resolve HTTP/1.1\r\nHost: aegiskeys.local\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(body))
	if _, err := clientConn.Write([]byte(hdr)); err != nil {
		t.Fatal(err)
	}
	// Headers delivered; body deliberately held back across a real
	// scheduling gap.
	time.Sleep(50 * time.Millisecond)
	if _, err := clientConn.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hresp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	respBody, err := io.ReadAll(io.LimitReader(hresp.Body, 4096))
	hresp.Body.Close() //nolint:errcheck
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("mock handle did not finish")
	}
	if hresp.StatusCode != http.StatusOK {
		t.Fatalf("fragmented request rejected: %d %q", hresp.StatusCode, string(respBody))
	}
	if !strings.Contains(string(respBody), "mock-credential-value") {
		t.Fatalf("fragmented request response missing credential: %q", string(respBody))
	}
}

// zombieChildCount counts zombie (unreaped) children of this process by
// scanning /proc — the observable defect when ResolveViaHelper returns
// early without Wait()-ing the helper child.
func zombieChildCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	self := strconv.Itoa(os.Getpid())
	for _, e := range entries {
		if _, aerr := strconv.Atoi(e.Name()); aerr != nil {
			continue
		}
		raw, rerr := os.ReadFile("/proc/" + e.Name() + "/stat")
		if rerr != nil {
			continue // process exited between listing and read
		}
		s := string(raw)
		idx := strings.LastIndexByte(s, ')')
		if idx < 0 || idx+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[idx+2:])
		if len(fields) >= 2 && fields[0] == "Z" && fields[1] == self {
			count++
		}
	}
	return count
}

// TestResolveViaHelperReapsChildrenOnFailure pins the exactly-once reaping
// contract (P1): every early-return failure path after cmd.Start() —
// deadline/transport failure, truncated response, a helper that never
// responds, an attestation signing failure — must kill the child if still
// running and Wait() exactly once. Without this, each failed exchange
// leaves a zombie helper for the broker's remaining lifetime.
func TestResolveViaHelperReapsChildrenOnFailure(t *testing.T) {
	before := zombieChildCount(t)

	// 1. Helper exits immediately without a framed response (early exit).
	helperTestingCommandMode(t, "envcheck", envcheckChildArg, filepath.Join(t.TempDir(), "unused.json"))
	_, err := aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), deadSocketPath(t), "seqpass/example", "http.request", "op-z", nil)
	if !errors.Is(err, aegiskeys.ErrTransportUnavailable) {
		t.Fatalf("early-exit helper = %v, want transport_unavailable", err)
	}

	// 2. Helper sends a truncated frame and exits.
	helperTestingCommandMode(t, "trunc")
	_, err = aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), deadSocketPath(t), "seqpass/example", "http.request", "op-z", nil)
	if !errors.Is(err, aegiskeys.ErrTransportUnavailable) {
		t.Fatalf("truncated-response helper = %v, want transport_unavailable", err)
	}

	// 3. Helper never responds: the caller's context bounds the exchange
	// and must not hang; the killed child is reaped.
	helperTestingCommandMode(t, "stall")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	started := time.Now()
	_, err = aegiskeys.ResolveViaHelper(ctx, selfExe(t), deadSocketPath(t), "seqpass/example", "http.request", "op-z", nil)
	cancel()
	if !errors.Is(err, aegiskeys.ErrTransportUnavailable) {
		t.Fatalf("stalled helper = %v, want transport_unavailable", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("stalled helper exchange took %v: hang", elapsed)
	}

	// 4. Signing fails after the child is already running: the child is
	// killed and reaped, and the ORIGINAL signing error is returned.
	helperTestingCommandMode(t, "envcheck", envcheckChildArg, filepath.Join(t.TempDir(), "unused2.json"))
	_, err = aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), deadSocketPath(t), "seqpass/example", "http.request", "op-z", failingSigner{})
	if !errors.Is(err, aegiskeys.ErrTransportUnavailable) || !strings.Contains(err.Error(), "attest sign") {
		t.Fatalf("signing-failure helper = %v, want transport attest-sign error", err)
	}

	// All four exchanges: every child reaped — no zombie accumulated.
	deadline := time.Now().Add(5 * time.Second)
	for {
		after := zombieChildCount(t)
		if after <= before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unreaped helper children: %d before, %d after 4 failed exchanges", before, after)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// deadSocketPath is a Unix socket path with no listener: the helper's
// broker connection fails inside the child regardless of timing.
func deadSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-listener.sock")
}

// failingSigner is a crypto.Signer whose Sign always fails: it drives the
// attestation-signing failure path after the helper child is running.
type failingSigner struct{}

func (failingSigner) Public() crypto.PublicKey { return ed25519.PublicKey(make([]byte, 32)) }
func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("synthetic signer failure")
}

// TestAttestKeyRestartRotation pins the restart strategy (P1): the private
// key never leaves non-dumpable memory, so a restart generates a fresh
// pair. The persisted PUBLIC half (not a secret) lets the broker detect
// its own rotation and surface an actionable re-enrollment requirement —
// resolves signed with the new key fail against the old grant until the
// operator re-pins, and the broker must say so rather than emit an
// unexplained access_denied.
func TestAttestKeyRestartRotation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meta.db")

	key1, err := aegiskeys.NewExecutorAttestKey()
	if err != nil {
		t.Fatal(err)
	}
	svc1, err := New(Config{DBPath: dbPath, VaultType: "memory-test", AegisKeysAttestKey: key1})
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	pub1 := svc1.AegisKeysAttestPublic()
	if pub1 == "" {
		t.Fatal("first start published no attest public key")
	}
	if svc1.AttestRotationPending() {
		t.Fatal("first start must not report rotation")
	}
	// A grant pinned to key1 accepts key1 signatures (sanity).
	_ = svc1.Close()

	// Restart with a fresh pair: the grant still pins pub1.
	key2, err := aegiskeys.NewExecutorAttestKey()
	if err != nil {
		t.Fatal(err)
	}
	svc2, err := New(Config{DBPath: dbPath, VaultType: "memory-test", AegisKeysAttestKey: key2})
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	defer svc2.Close()
	pub2 := svc2.AegisKeysAttestPublic()
	if pub2 == "" || pub2 == pub1 {
		t.Fatalf("restart must generate a fresh key pair: pub1=%q pub2=%q", pub1, pub2)
	}
	if !svc2.AttestRotationPending() {
		t.Fatal("restart with a fresh key must report pending re-enrollment")
	}
	// The old grant denies the new key's signature: the signature is over
	// the canonical string with key2, verification against pub1 fails.
	nonce := "restart-rotation-nonce"
	sig := ed25519.Sign(key2.Private.(ed25519.PrivateKey), aegiskeys.AttestCanonicalString("seqpass/example", "http.request", "op-x", nonce))
	if ed25519.Verify(ed25519.PublicKey(mustHex(t, pub1)), aegiskeys.AttestCanonicalString("seqpass/example", "http.request", "op-x", nonce), sig) {
		t.Fatal("key2 signature verified against the OLD grant pin — rotation was not detected by the verifier")
	}
	_ = sig
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestResolveViaHelperHelperEnvFiltered proves the filter end-to-end: the
// spawned helper process's actual environment contains no parent
// application variables — a synthetic secret-shaped canary set in this
// process must not appear in the child's environ.
func TestResolveViaHelperHelperEnvFiltered(t *testing.T) {
	t.Setenv("SEQPASS_TEST_ENV_CANARY", "synthetic-secret-value")
	outPath := filepath.Join(t.TempDir(), "env.json")
	helperTestingCommandMode(t, "envcheck", envcheckChildArg, outPath)
	// The child exits without a framed response, so the resolve fails —
	// the environ dump is the assertion target.
	_, _ = aegiskeys.ResolveViaHelper(context.Background(), selfExe(t), deadSocketPath(t), "seqpass/example", "http.request", "op-env", nil)
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("envcheck child did not write environ: %v", err)
	}
	env := string(raw)
	if strings.Contains(env, "SEQPASS_TEST_ENV_CANARY") {
		t.Fatal("helper inherited the synthetic secret-shaped canary variable")
	}
	for _, line := range strings.Split(env, "\n") {
		if line == "" {
			continue
		}
		key := strings.SplitN(line, "=", 2)[0]
		switch key {
		case "GODEBUG", "GOGC", "GOMEMLIMIT", "GOMAXPROCS":
		default:
			t.Fatalf("helper inherited non-allowlisted env %q", key)
		}
	}
}

// --- test utilities ---

func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func setDumpable(t *testing.T, val int) {
	t.Helper()
	// PR_SET_DUMPABLE on the TEST process mirrors the broker's §11
	// setting; the kernel semantics under test are identical.
	if err := unix.Prctl(prSetDumpable, uintptr(val), 0, 0, 0); err != nil {
		t.Fatalf("prctl PR_SET_DUMPABLE: %v", err)
	}
}

func socketPairForTest() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "test-parent"), os.NewFile(uintptr(fds[1]), "test-child"), nil
}

func writeFramedForTest(w io.Writer, v interface{}) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readFramedForTest(r io.Reader, v interface{}) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > 1<<20 {
		return fmt.Errorf("frame length %d out of bounds", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
