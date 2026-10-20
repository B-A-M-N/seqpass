package ipc

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/intake"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

const (
	maxConns  = 64
	maxFrame  = 1 << 20 // 1 MiB per IPC frame
	ioTimeout = 120 * time.Second
	handlerTO = 30 * time.Second
)

// PrincipalMapper maps OS peer identity -> broker principal. The default maps
// uid to "uid:<n>". Two agents sharing one Linux user share one principal:
// use separate OS identities for stronger per-agent attribution.
type PrincipalMapper func(Peer) string

func DefaultMapper(p Peer) string {
	return fmt.Sprintf("uid:%d", p.UID)
}

// AuthenticatedPrincipal is the broker-verified caller identity.
type AuthenticatedPrincipal struct {
	Peer      Peer
	Principal string
	Role      Role // explicit IPC security domain of this connection
	OnAdmin   bool // connected via the admin socket (kept for admin-only readbacks)
}

// Authorizer decides socket access. Admin rights require explicit UID
// membership: reaching the admin socket alone grants nothing (F01).
type Authorizer interface {
	CanConnectAgent(AuthenticatedPrincipal) bool
	CanConnectIntake(AuthenticatedPrincipal) bool
	CanConnectAdmin(AuthenticatedPrincipal) bool
}

// UIDAuthorizer gates both sockets by explicit UID allowlists (C02).
// Admin rights require membership in AdminUIDs: reaching the admin socket
// alone grants nothing (F01). The agent surface requires membership in
// AgentUIDs: any local process that can reach the socket is NOT sufficient.
// A nil AgentUIDs map means "broker euid only" (fail-closed default); the
// operator opens agent access explicitly via --agent-uid.
type UIDAuthorizer struct {
	AdminUIDs  map[uint32]bool
	AgentUIDs  map[uint32]bool
	IntakeUIDs map[uint32]bool
	// PrincipalAdmin marks intake identities authorized to create
	// trusted host principal bindings. Principal strings mirror the
	// broker's UID mapping (for example "uid:1000").
	PrincipalAdmin map[string]bool
}

// CanAdminPrincipal reports whether the authenticated intake principal is
// explicitly trusted for host-binding administration. Default fail-closed.
func (a *UIDAuthorizer) CanAdminPrincipal(p AuthenticatedPrincipal) bool {
	return a != nil && a.PrincipalAdmin[p.Principal]
}

func (a *UIDAuthorizer) CanConnectAgent(p AuthenticatedPrincipal) bool {
	if p.Principal == "" {
		return false
	}
	if a.AgentUIDs == nil {
		return p.Peer.UID == uint32(os.Geteuid())
	}
	return a.AgentUIDs[p.Peer.UID]
}

func (a *UIDAuthorizer) CanConnectAdmin(p AuthenticatedPrincipal) bool {
	return p.Principal != "" && a.AdminUIDs[p.Peer.UID]
}

// CanConnectIntake gates the human-side surface (QR-02/SP-TUI-04). Agent
// UIDs are never sufficient here unless the operator explicitly lists
// them: intake authorizes value release, so its identities are named
// separately from agent submit rights.
func (a *UIDAuthorizer) CanConnectIntake(p AuthenticatedPrincipal) bool {
	if p.Principal == "" {
		return false
	}
	if a.IntakeUIDs == nil {
		return p.Peer.UID == uint32(os.Geteuid())
	}
	return a.IntakeUIDs[p.Peer.UID]
}

type Server struct {
	svc       *service.Service
	socket    string
	adminSock string
	// AssuranceMode is a validated topology label set by daemon.New.
	// Standalone test/dev servers report best-effort by default.
	AssuranceMode string
	// AssuranceLabel is the honest assurance classification for that
	// topology: "verified" only for a live-verified isolated deployment,
	// otherwise "unverified". It is reported alongside the topology so a
	// caller can never read a best-effort mode as a security guarantee.
	//
	// It is written by the daemon after the live boundary check succeeds and
	// may be revoked later when the boundary drifts, while per-connection
	// handlers read it concurrently. It is therefore guarded rather than
	// exported as a plain field.
	assuranceMu    sync.RWMutex
	assuranceLabel string
	// IntakeSocket, when non-empty, serves the trusted human-side
	// intake domain on its own owner-only socket (QR-02/SP-TUI-04).
	// Set before Start, like AgentGID.
	IntakeSocket string
	// HostSocket, when non-empty, serves the display-only native-host
	// presentation domain (HI-02/HI-03). Empty keeps the domain disabled;
	// Start never creates it implicitly.
	HostSocket string
	mapper     PrincipalMapper
	auth       Authorizer
	listener   net.Listener
	adminLis   net.Listener
	intakeLis  net.Listener
	hostLis    net.Listener
	created    []string          // sockets created by this process (removed on close)
	createdID  map[string]fileID // device+inode at bind time (C09)

	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	wg         sync.WaitGroup
	closed     chan struct{}
	closedOnce sync.Once

	// AgentGID, when non-nil, becomes the group owner of the agent socket
	// (SC-04): directory mode 0710 grants group traverse, so the socket
	// must be explicitly chowned to the agent group — plain Unix bind does
	// not inherit the directory's group without setgid. The admin socket
	// stays owner-only and is never group-assigned. Set before Start.
	AgentGID *uint32
	// IntakeGID, when non-nil, makes the intake socket group-accessible
	// (0660 in a 0710 directory) so a human identity distinct from the
	// broker UID can connect (F04). Peer-credential authorization still
	// applies; the group must never be the agent group. Set before Start.
	IntakeGID *uint32
	// IntakeGroup, when non-empty, is the intake group name used to
	// classify assurance (SP-03): an isolated topology with a separate
	// intake group is classified verified; anything else stays
	// unverified or prohibited based on actual socket topology.
	IntakeGroup string
}

func NewServer(svc *service.Service, socket, adminSock string, mapper PrincipalMapper, auth Authorizer) *Server {
	if mapper == nil {
		mapper = DefaultMapper
	}
	if auth == nil {
		euid := uint32(os.Geteuid())
		auth = &UIDAuthorizer{
			AdminUIDs: map[uint32]bool{euid: true},
			AgentUIDs: map[uint32]bool{euid: true},
		}
	}
	return &Server{
		svc: svc, socket: socket, adminSock: adminSock,
		mapper: mapper, auth: auth,
		conns:     make(map[net.Conn]struct{}),
		closed:    make(chan struct{}),
		createdID: make(map[string]fileID),
	}
}

// SetAssuranceLabel publishes the honest assurance classification for the
// running topology. It is trusted daemon wiring: the label may only read
// "verified" after the live boundary check has passed, and the daemon revokes
// it when that boundary later drifts. Safe to call while handlers are serving.
func (s *Server) SetAssuranceLabel(label string) {
	s.assuranceMu.Lock()
	s.assuranceLabel = label
	s.assuranceMu.Unlock()
}

// AssuranceLabel reports the current classification. An unset label is
// reported as "unverified": absence of evidence is never a guarantee.
func (s *Server) AssuranceLabel() string {
	s.assuranceMu.RLock()
	defer s.assuranceMu.RUnlock()
	if s.assuranceLabel == "" {
		return "unverified"
	}
	return s.assuranceLabel
}

// listenUnix hardens the socket lifecycle (F02/C02/C09):
//   - trusted runtime dir (created with dirMode, must be owned by euid,
//     no symlinks, no group/other write)
//   - existing path: must be a socket owned by euid; live listeners refused;
//     stale sockets removed only after ownership established
//   - refuses to delete non-socket objects; chmod/chown failure is fatal.
//   - agent socket uses mode 0660 + dir 0710 so an approved agent group can
//     traverse/connect; admin socket stays 0600 + dir 0700 (owner only).
func listenUnix(path string, mode, dirMode os.FileMode, gid *uint32) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("empty socket path")
	}
	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	if err != nil {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, err
		}
		// MkdirAll umask may have loosened the leaf; enforce exactly.
		if err := os.Chmod(dir, dirMode); err != nil {
			return nil, fmt.Errorf("socket dir permissions failed: %w", err)
		}
	} else {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("socket dir is a symlink")
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("socket dir is not a directory")
		}
		// Harden existing dirs: no group/other write ever (022). Admin
		// dirs must additionally not be group/other-readable (044);
		// group traverse (0710) is tolerated so agent and admin sockets
		// may share one directory, but production should use a separate
		// 0700 admin directory. The 0600 admin socket + UID allowlist
		// remain the access controls; traversal alone grants nothing.
		if perm := fi.Mode().Perm(); perm&0022 != 0 {
			return nil, fmt.Errorf("socket dir is group/other-writable")
		}
		if mode == 0600 && fi.Mode().Perm()&0044 != 0 {
			return nil, fmt.Errorf("admin socket dir must not be group/other-readable (use 0700)")
		}
	}
	// SC-04: mode 0710 grants traverse to members of the directory's group,
	// so the agent socket directory must itself be group-owned by the agent
	// group; neither MkdirAll nor a pre-created dir guarantees this.
	if gid != nil {
		if err := os.Chown(dir, -1, int(*gid)); err != nil {
			return nil, fmt.Errorf("socket dir group assignment failed: %w", err)
		}
	}
	if st, err := os.Stat(dir); err == nil {
		if sysUID(st) != os.Geteuid() {
			return nil, fmt.Errorf("socket dir not owned by broker user")
		}
		if gid != nil && sysGID(st) != *gid {
			return nil, fmt.Errorf("socket dir group mismatch after chown")
		}
	}
	// Ancestor check (C09): every directory up to / must be owned by the
	// broker user or root, contain no symlink, and not be group-writable
	// or world-writable without the sticky bit. Otherwise a hostile parent
	// could rename or substitute the runtime directory.
	if err := checkAncestors(dir); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to replace symlink at socket path")
		}
		if st.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("refusing to delete non-socket at socket path")
		}
		if sysUID(st) != os.Geteuid() {
			return nil, fmt.Errorf("refusing to replace different-owner socket")
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("live socket already listening at path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("socket permissions failed: %w", err)
	}
	// SC-04: the kernel does not inherit the directory's group for a new
	// socket without setgid, so explicitly assign the agent group and then
	// verify GID + mode (post-condition, not assumption).
	if gid != nil {
		if err := os.Chown(path, -1, int(*gid)); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("socket group assignment failed: %w", err)
		}
		if st, err := os.Stat(path); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("socket group verify failed: %w", err)
		} else if sysGID(st) != *gid {
			_ = l.Close()
			return nil, fmt.Errorf("socket group mismatch after chown")
		} else if st.Mode().Perm() != mode.Perm() {
			_ = l.Close()
			return nil, fmt.Errorf("socket mode mismatch after chown")
		}
	}
	return l, nil
}

// checkAncestors walks from dir to / rejecting untrusted path components.
func checkAncestors(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	cur := abs
	for {
		fi, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("socket ancestor %s is a symlink", cur)
		}
		if !fi.IsDir() {
			return fmt.Errorf("socket ancestor %s is not a directory", cur)
		}
		// Group/other write is safe only under the sticky bit (as in
		// /tmp), where rename/remove is restricted to owners. Without
		// it, a writer could substitute the runtime directory. Note:
		// Go reports the sticky bit as ModeSticky, not in Perm().
		if fi.Mode().Perm()&0022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("socket ancestor %s is group/other-writable without sticky bit", cur)
		}
		if uid := sysUID(fi); uid != os.Geteuid() && uid != 0 {
			return fmt.Errorf("socket ancestor %s not owned by broker or root", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

func (s *Server) Start() error {
	if s.adminSock != "" && s.adminSock == s.socket {
		return fmt.Errorf("agent and admin sockets must differ")
	}
	l, err := listenUnix(s.socket, 0660, 0710, s.AgentGID)
	if err != nil {
		return fmt.Errorf("agent socket: %w", err)
	}
	s.listener = l
	s.created = append(s.created, s.socket)
	if fi, err := os.Stat(s.socket); err == nil {
		s.createdID[s.socket] = statID(fi)
	}
	s.wg.Add(1)
	go s.serve(l, RoleAgent)

	if s.adminSock != "" && s.adminSock != s.socket {
		al, err := listenUnix(s.adminSock, 0600, 0700, nil)
		if err != nil {
			// Do not leave the agent listener running when admin setup
			// fails: signal shutdown, close the agent listener, wait
			// for the serve loop to exit so no half-open broker
			// survives startup failure (C09).
			s.closedOnce.Do(func() { close(s.closed) })
			_ = l.Close()
			s.wg.Wait()
			s.created = nil
			return fmt.Errorf("admin socket: %w", err)
		}
		s.adminLis = al
		s.created = append(s.created, s.adminSock)
		if fi, err := os.Stat(s.adminSock); err == nil {
			s.createdID[s.adminSock] = statID(fi)
		}
		s.wg.Add(1)
		go s.serve(al, RoleAdmin)
	}
	if s.HostSocket != "" && (s.HostSocket == s.socket || s.HostSocket == s.adminSock || s.HostSocket == s.IntakeSocket) {
		_ = l.Close()
		s.closedOnce.Do(func() { close(s.closed) })
		s.created = nil
		return fmt.Errorf("host socket must be separate from agent, admin and intake sockets")
	}
	if s.IntakeSocket != "" && s.IntakeSocket != s.socket && s.IntakeSocket != s.adminSock {
		intakeMode, intakeDirMode := os.FileMode(0600), os.FileMode(0700)
		if s.IntakeGID != nil {
			intakeMode, intakeDirMode = 0660, 0710
		}
		il, err := listenUnix(s.IntakeSocket, intakeMode, intakeDirMode, s.IntakeGID)
		if err != nil {
			s.closedOnce.Do(func() { close(s.closed) })
			_ = l.Close()
			if s.adminLis != nil {
				_ = s.adminLis.Close()
			}
			s.wg.Wait()
			s.created = nil
			return fmt.Errorf("intake socket: %w", err)
		}
		s.intakeLis = il
		s.created = append(s.created, s.IntakeSocket)
		if fi, err := os.Stat(s.IntakeSocket); err == nil {
			s.createdID[s.IntakeSocket] = statID(fi)
		}
		s.wg.Add(1)
		go s.serve(il, RoleIntake)
	}
	if s.HostSocket != "" {
		hl, err := listenUnix(s.HostSocket, 0600, 0700, nil)
		if err != nil {
			s.closedOnce.Do(func() { close(s.closed) })
			_ = l.Close()
			if s.adminLis != nil {
				_ = s.adminLis.Close()
			}
			if s.intakeLis != nil {
				_ = s.intakeLis.Close()
			}
			s.wg.Wait()
			s.created = nil
			return fmt.Errorf("host socket: %w", err)
		}
		s.hostLis = hl
		s.created = append(s.created, s.HostSocket)
		if fi, err := os.Stat(s.HostSocket); err == nil {
			s.createdID[s.HostSocket] = statID(fi)
		}
		s.wg.Add(1)
		go s.serve(hl, RoleHost)
	}
	return nil
}

func (s *Server) serve(l net.Listener, role Role) {
	defer s.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		s.mu.Lock()
		select {
		case <-s.closed:
			// Shutdown raced accept: drop immediately so Close never
			// waits on an untracked connection.
			s.mu.Unlock()
			_ = conn.Close()
			continue
		default:
		}
		if len(s.conns) >= maxConns {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				_ = c.Close()
			}()
			s.handleConn(c, role)
		}(conn)
	}
}

func (s *Server) Close() error {
	s.closedOnce.Do(func() { close(s.closed) })
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.adminLis != nil {
		_ = s.adminLis.Close()
	}
	if s.intakeLis != nil {
		_ = s.intakeLis.Close()
	}
	if s.hostLis != nil {
		_ = s.hostLis.Close()
	}
	// Unblock idle scanners so shutdown cannot wait on silent clients (F09).
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	// Remove only the exact sockets this process bound: the path must still
	// be a broker-owned socket with the same device+inode recorded at bind
	// (C09). A substituted path is left alone.
	for _, p := range s.created {
		st, err := os.Lstat(p)
		if err != nil || st.Mode().Type() != os.ModeSocket || sysUID(st) != os.Geteuid() {
			continue
		}
		want, ok := s.createdID[p]
		if !ok || !want.ok {
			continue
		}
		if got := statID(st); got != want {
			continue
		}
		_ = os.Remove(p)
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn, role Role) {
	peer, err := peerCred(conn)
	if err != nil {
		return // fail closed before any dispatch
	}
	ap := AuthenticatedPrincipal{Peer: peer, Principal: s.mapper(peer), Role: role, OnAdmin: role == RoleAdmin}
	if ap.Principal == "" {
		return
	}
	// Verify peer credentials immediately; reject unknown peers (F01).
	// Each socket admits exactly its domain role — never a union.
	switch role {
	case RoleAdmin:
		if !s.auth.CanConnectAdmin(ap) {
			_ = writeDenied(conn)
			return
		}
	case RoleIntake, RoleHost:
		if !s.auth.CanConnectIntake(ap) {
			_ = writeDenied(conn)
			return
		}
	default:
		if !s.auth.CanConnectAgent(ap) {
			_ = writeDenied(conn)
			return
		}
	}
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), maxFrame)
	w := bufio.NewWriter(conn)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		_ = conn.SetDeadline(time.Now().Add(ioTimeout))
		var req Request
		dec := json.NewDecoder(strings.NewReader(string(sc.Bytes())))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			_ = enc.Encode(Response{ID: "", OK: false, Error: "invalid request"})
			_ = w.Flush()
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), handlerTO)
		resp := s.dispatch(ctx, ap, req, role)
		cancel()
		resp.ID = req.ID
		_ = enc.Encode(resp)
		_ = w.Flush()
	}
}

func writeDenied(conn net.Conn) error {
	w := bufio.NewWriter(conn)
	_ = json.NewEncoder(w).Encode(Response{OK: false, Error: "access denied"})
	return w.Flush()
}

func (s *Server) dispatch(ctx context.Context, ap AuthenticatedPrincipal, req Request, role Role) Response {
	principal := ap.Principal
	// Defense in depth: admin methods require admin authorization even if
	// they arrive on the admin socket (F01).
	if isAdminMethod(req.Method) && !s.auth.CanConnectAdmin(ap) {
		return Response{OK: false, Error: "access denied"}
	}
	allow := AgentAllowlist
	switch role {
	case RoleAdmin:
		allow = AdminAllowlist
	case RoleIntake:
		allow = IntakeAllowlist
	case RoleHost:
		allow = HostAllowlist
	}
	if !allow[req.Method] {
		return Response{OK: false, Error: "access denied"}
	}
	if req.Method == MethodHostBindingCreate {
		if auth, ok := s.auth.(interface {
			CanAdminPrincipal(AuthenticatedPrincipal) bool
		}); !ok || !auth.CanAdminPrincipal(ap) {
			return Response{OK: false, Error: "access denied"}
		}
	}
	_ = ctx
	p := req.Params
	switch req.Method {
	case MethodAttestPublic:
		if key := s.svc.AegisKeysAttestPublic(); key != "" {
			data := map[string]string{"attest_public": key}
			if s.svc.AttestRotationPending() {
				data["attest_rotation"] = "pending"
				data["re_enrollment"] = "attestation key rotated across restart: update the AegisKeys grant attest_key pin to attest_public before resolves succeed"
			}
			return Response{OK: true, Data: data}
		}
		return Response{OK: false, Error: "attest key not configured (no resolve helper)"}
	case MethodHealth:
		mode := s.AssuranceMode
		if mode == "" {
			mode = "best-effort"
		}
		label := s.AssuranceLabel()
		return Response{OK: true, Data: map[string]string{
			"status": "ok", "assurance_mode": mode, "assurance": label,
			"input_mode": s.svc.HostInputMode(), "input_reason": s.svc.HostInputReason(),
		}}
	case MethodCatalog:
		refs, err := s.svc.Catalog(principal)
		if err != nil {
			return Response{OK: false, Error: "internal error"}
		}
		return Response{OK: true, Data: refs}
	case MethodUseSubmit:
		ur := &types.UseRequest{
			SecretRef: strParam(p, "secret_ref"),
			Operation: strParam(p, "operation"),
			Target:    strParam(p, "target"),
		}
		if raw, ok := p["params"].(map[string]interface{}); ok {
			ur.Params = map[string]string{}
			for k, v := range raw {
				if vs, ok := v.(string); ok {
					ur.Params[k] = vs
				}
			}
		}
		id, err := s.svc.SubmitUse(principal, ur)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		st, _ := s.svc.Status(principal, "use", id)
		return Response{OK: true, Data: map[string]string{"op_id": id, "status": st}}
	case MethodTransferSubmit:
		tr := &types.TransferRequest{
			SecretRef:     strParam(p, "secret_ref"),
			DestinationID: strParam(p, "destination_id"),
			PayloadRef:    strParam(p, "payload_ref"),
		}
		id, err := s.svc.SubmitTransfer(principal, tr)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		st, _ := s.svc.Status(principal, "transfer", id)
		return Response{OK: true, Data: map[string]string{"op_id": id, "status": st}}
	case MethodStatus:
		detail, err := s.svc.StatusDetail(principal, strParam(p, "op_type"), strParam(p, "op_id"))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		data := map[string]interface{}{
			"status":            detail.Status,
			"effective_outcome": detail.EffectiveOutcome,
			"next":              detail.NextAction,
		}
		if detail.HasReceipt {
			data["result_type"] = detail.ResultType
			data["result"] = detail.Result
			data["completed_at"] = detail.CompletedAt
		}
		if detail.HasObservation {
			data["verify_state"] = detail.VerifyState
			data["verify_detail"] = detail.VerifyDetail
			data["verify_checked"] = detail.VerifyChecked
		}
		if detail.VerifyUnavailable {
			// P2-8: the store could not be read. The agent must know
			// the absence of verify_state means "unknown", not
			// "nothing contradictory found".
			data["verify_state"] = detail.VerifyState
			data["verify_unavailable"] = true
		}
		return Response{OK: true, Data: data}
	case MethodOpsMine:
		return s.opsMine(principal)
	case MethodOpsPending:
		uses, transfers, err := s.svc.DB().ListPendingOps()
		if err != nil {
			return Response{OK: false, Error: "internal error"}
		}
		return Response{OK: true, Data: map[string]interface{}{"uses": uses, "transfers": transfers}}
	case MethodOpsReady:
		// Ready view (G03): authorized operations awaiting execution.
		// Preauthorized work is visible here even when the auto worker
		// is disabled, so it can never strand silently.
		uses, transfers, err := s.svc.DB().ListAuthorizedOps()
		if err != nil {
			return Response{OK: false, Error: "internal error"}
		}
		return Response{OK: true, Data: map[string]interface{}{"uses": uses, "transfers": transfers}}
	case MethodRecipientStatus:
		res, err := s.svc.RecipientStatus(ctx, principal, strParam(p, "op_id"), role == RoleAdmin)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: res}
	case MethodVerifyOutcome:
		v, err := s.svc.VerifyOutcome(ctx, principal, strParam(p, "op_type"), strParam(p, "op_id"), role == RoleAdmin)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"op_id": v.OpID, "op_type": v.OpType, "state": v.State,
			"detail": v.Detail, "evidence_kind": v.EvidenceKind, "checked": v.Checked,
		}}
	case MethodOpShow:
		detail, err := s.svc.OpEnvelope(strParam(p, "op_type"), strParam(p, "op_id"))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: detail}
	case MethodApproveUse:
		if err := s.svc.ApproveUse(strParam(p, "op_id"), principal, expectRevision(p)); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "authorized"}}
	case MethodRejectUse:
		if err := s.svc.RejectUse(strParam(p, "op_id"), principal); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}
	case MethodApproveTransfer:
		if err := s.svc.ApproveTransfer(strParam(p, "op_id"), principal, expectRevision(p)); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "authorized"}}
	case MethodRejectTransfer:
		if err := s.svc.RejectTransfer(strParam(p, "op_id"), principal); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}
	case MethodExecuteUse:
		res, err := s.svc.ExecuteUse(ctx, strParam(p, "op_id"), principal)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: res}
	case MethodExecuteTransfer:
		res, err := s.svc.ExecuteTransfer(ctx, strParam(p, "op_id"), principal)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: res}
	case MethodPolicyAdd:
		var rules []types.PolicyRule
		if rs, ok := p["rules"].(string); ok && rs != "" {
			dec := json.NewDecoder(strings.NewReader(rs))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&rules); err != nil {
				return Response{OK: false, Error: "invalid rules"}
			}
		}
		pol := &types.Policy{Name: strParam(p, "name"), Rules: rules, Enabled: true, Revision: 1}
		if pol.Name == "" || len(rules) == 0 {
			return Response{OK: false, Error: "missing name or rules"}
		}
		if err := s.svc.DB().CreatePolicy(pol); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"id": pol.ID}}
	case MethodPolicySet:
		enabled, _ := p["enabled"].(bool)
		if err := s.svc.DB().SetPolicyEnabled(strParam(p, "id"), enabled); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}
	case MethodDestUpdate:
		// Re-pinning endpoint and/or recipient identity in one atomic
		// mutation (C05). Identity params are optional here; when present
		// they replace the pins. Endpoint-only changes keep identity.
		if _, hasUID := p["expected_uid"]; hasUID {
			uid, ok := uintParam(p, "expected_uid")
			if !ok {
				return Response{OK: false, Error: "invalid expected_uid"}
			}
			var gid *uint32
			if g, ok := uintParam(p, "expected_gid"); ok {
				gid = &g
			}
			u := uid
			if strParam(p, "endpoint") == "" {
				return Response{OK: false, Error: "missing endpoint"}
			}
			if err := s.svc.DB().UpdateDestinationRecipient(strParam(p, "id"), strParam(p, "endpoint"), &u, gid, principal); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true}
		}
		if err := s.svc.DB().UpdateDestinationEndpoint(strParam(p, "id"), strParam(p, "endpoint"), principal); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}
	case MethodSecretAdd:
		sr := &types.SecretReference{
			Name:    strParam(p, "name"),
			Owner:   principal,
			Binding: strParam(p, "binding"),
		}
		sr.Description = strParam(p, "description")
		if sr.Name == "" {
			return Response{OK: false, Error: "missing name"}
		}
		if err := s.svc.AddSecretRef(sr); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"id": sr.ID}}
	case MethodSecretStage:
		// Bounded development intake (SC-08): admin socket only (allowlist),
		// payload as base64, staged by the service with dev-mode and
		// size enforcement. Never on the agent surface.
		raw, _ := p["payload_b64"].(string)
		if len(raw) > 4*(64*1024+2)/3+8 {
			return Response{OK: false, Error: "payload too large"}
		}
		payload, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return Response{OK: false, Error: "payload not valid base64"}
		}
		if err := s.svc.StageEphemeral(strParam(p, "ref_id"), payload); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}
	case MethodDestAdd:
		d := &types.Destination{
			Name:       strParam(p, "name"),
			Type:       strParam(p, "type"),
			Endpoint:   strParam(p, "endpoint"),
			SourceRepo: strParam(p, "source_repo"),
		}
		if d.Name == "" || d.Endpoint == "" || d.Type == "" {
			return Response{OK: false, Error: "missing fields"}
		}
		switch d.Type {
		case "recipient-socket":
			// C05: recipient identity pins. expected_uid is required;
			// expected_gid is optional. Numeric params arrive as float64.
			if uid, ok := uintParam(p, "expected_uid"); ok {
				u := uid
				d.ExpectedUID = &u
			}
			if gid, ok := uintParam(p, "expected_gid"); ok {
				g := gid
				d.ExpectedGID = &g
			}
			if d.ExpectedUID == nil {
				return Response{OK: false, Error: "expected_uid is required for recipient-socket"}
			}
		case secureops.DestTypeHTTPPinned, secureops.DestTypeProcessPinned, secureops.DestTypeGitPinned:
			// Pinned operation profiles carry no identity pin; their
			// security is the strict endpoint grammar, which
			// AddDestination enforces at the broker boundary.
		default:
			return Response{OK: false, Error: "unsupported destination type"}
		}
		if err := s.svc.AddDestination(d); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"id": d.ID}}
	case MethodRelayRequest:
		// F03: the agent-facing surface creates single-use relays only.
		// Broader consumption (reusable/bounded) requires an explicit
		// trusted-user choice via the intake request path — it is never
		// silently selected by an agent IPC parameter.
		reqID, err := s.svc.RelayRequest(principal,
			strParam(p, "destination_id"), strParam(p, "data_kind"), strParam(p, "purpose"),
			ttlParam(p), "single_dispatch", 1)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		// SP-03: when a known host session is available (agent passes
		// session_id + session_token), atomically create the relay and
		// bind it to the session so the native host inbox discovers it.
		if sid := strParam(p, "session_id"); sid != "" {
			tok := strParam(p, "session_token")
			sess, authErr := s.svc.HostSessionAuth(sid, tok)
			if authErr != nil {
				return Response{OK: false, Error: "host session invalid"}
			}
			if sess.AgentPrincipal != principal {
				return Response{OK: false, Error: "relay and host session bind to different agents"}
			}
			if err := s.svc.BindRelayHost(principal, reqID, sess); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"request_id": reqID, "status": "awaiting_user",
			"next_action": "protected_input",
		}}
	case MethodRelayStatus:
		st, err := s.svc.RelayStatus(principal, strParam(p, "request_id"))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		// SP-02/HI-01/HI-06: return the broker-configured assurance facts,
		// never a caller-controlled topology assertion. The agent remains
		// a control-plane consumer and cannot claim host-native isolation.
		if rm := st; rm != nil {
			rm["input_mode"] = harness.SecureInputMode(s.svc.HostInputMode())
			rm["input_assurance"] = s.svc.HostInputAssurance()
			rm["input_protected"] = s.svc.HostInputAssurance() != string(intake.AssuranceUnverified)
			rm["input_reason"] = s.svc.HostInputReason()
		}
		return Response{OK: true, Data: st}
	case MethodRelayCancel:
		if err := s.svc.RelayCancel(principal, strParam(p, "request_id"), role != RoleAgent); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "cancelled"}}
	case MethodIntakeInspect:
		v, err := s.svc.RelayInspect(principal, strParam(p, "request_id"), 50)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: v}
	case MethodIntakeFulfill:
		raw, err := b64Param(p, "payload")
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		expectedRevision := uint64(uintParamOr(p, "request_revision"))
		opID, err := s.svc.RelayFulfill(principal, strParam(p, "request_id"), expectedRevision, raw)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"request_id": strParam(p, "request_id"), "op_id": opID, "status": "authorized",
			"next": "Authorized: the trusted worker delivers; poll relay.status for the outcome",
		}}
	case MethodIntakeReject:
		if err := s.svc.RelayReject(principal, strParam(p, "request_id"), uint64(uintParamOr(p, "request_revision"))); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "rejected"}}
	case MethodIntakeCancel:
		if err := s.svc.RelayCancel(principal, strParam(p, "request_id"), true); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "cancelled"}}
	case MethodHostRegister:
		// Registration is trusted-side only. HumanPrincipal arrives from
		// the same authenticated IPC connection that would otherwise use
		// intake; the broker rejects the agent-supplied aliases.
		caps := harness.HostCapabilities{
			Presentation:            strParam(p, "presentation"),
			InputTransport:          strParam(p, "input_transport"),
			CredentialFormViaMCP:    false,
			SupportsResume:          strParam(p, "supports_resume") == "true",
			SupportsCancelPrompt:    strParam(p, "supports_cancel_prompt") == "true",
			SupportsMultiplePending: strParam(p, "supports_multiple_pending") == "true",
		}
		reg := harness.HostRegistration{
			HostKind:       harness.HostSessionKind(strParam(p, "host_kind")),
			ThreadID:       strParam(p, "thread_id"),
			HostVersion:    strParam(p, "host_version"),
			AdapterVersion: strParam(p, "adapter_version"),
			Topology:       s.AssuranceMode,
			SecurityConfig: harness.BrokerSecurityConfig(s.AssuranceMode, s.IntakeGroup != ""),
			Credentials:    caps,
		}
		if ttl, ok := uintParam(p, "ttl_seconds"); ok {
			reg.TTLOfSession = time.Duration(ttl) * time.Second
		}
		// S1: resolve the authorized agent principal from the broker's
		// trusted human/host-kind binding. Never bind both principals to
		// the authenticated intake identity.
		resolved, bindErr := s.svc.DB().ResolveHostPrincipalBinding(principal, string(reg.HostKind), time.Now())
		if bindErr != nil || resolved == nil {
			return Response{OK: false, Error: "host is not authorized for this agent principal"}
		}
		session, token, err := s.svc.RegisterHostSession(resolved.AgentPrincipal, principal, reg)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{"session": session, "token": token}}
	case MethodHostBindingCreate:
		// SP-02: the admin host-binding RPC is only reachable through the
		// admin socket with an explicitly authorized administrative identity.
		// The auth.CanAdminPrincipal check at the top of dispatch already
		// gated this. Route to the host-binding handler.
		return s.dispatchHostBindingCreate(p)
	case MethodHostEvent, MethodHostPending, MethodHostNotice, MethodHostStatus, MethodHostReview, MethodHostCancelPrompt:
		var sess *types.HostSession
		if sid := strParam(p, "session_id"); sid != "" {
			tok := strParam(p, "session_token")
			authSession, authErr := s.svc.HostSessionAuth(sid, tok)
			if authErr != nil {
				return Response{OK: false, Error: "host session invalid"}
			}
			sess = authSession
		} else {
			return Response{OK: false, Error: "missing host session"}
		}
		if req.Method == MethodHostPending {
			limit := int(uintParamOr(p, "limit"))
			records, err := s.svc.ListPendingRelaysForHostSession(sess, limit)
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			notices := make([]*harness.ProtectedInputNotice, 0, len(records))
			for _, r := range records {
				n, err := s.svc.HostRelayNotice(principal, r.ID, sess)
				if err != nil {
					return Response{OK: false, Error: err.Error()}
				}
				notices = append(notices, n)
			}
			return Response{OK: true, Data: notices}
		}

		if req.Method == MethodHostEvent {
			// SP-04: the host socket authenticates a trusted human. The
			// service derives the agent principal from the broker-issued
			// session, never from a caller-supplied string.
			sequence := uint64(uintParamOr(p, "sequence"))
			ev, err := s.svc.HostRelayEvent(sess.AgentPrincipal, strParam(p, "request_id"), sess, sequence)
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true, Data: ev}
		}
		if req.Method == MethodHostStatus {
			// SP-04: derive agent principal from the trusted session.
			st, err := s.svc.HostRelayStatus(sess.AgentPrincipal, strParam(p, "request_id"), sess)
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true, Data: st}
		}
		if req.Method == MethodHostNotice {
			// SP-04: HostRelayNotice takes the human principal for review
			// validation, but the service derives the agent from the session.
			notice, err := s.svc.HostRelayNotice(sess.HumanPrincipal, strParam(p, "request_id"), sess)
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true, Data: notice}
		}
		if req.Method == MethodHostCancelPrompt {
			// SP-04: check the exact relay-session association before
			// calling cancellation. The agent principal is derived from
			// the trusted session, never from the caller's connection.
			if err := s.requireRelayHostSession(sess.AgentPrincipal, strParam(p, "request_id"), sess); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			cancelled, err := s.svc.RelayCancelPrompt(sess.AgentPrincipal, strParam(p, "request_id"))
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true, Data: map[string]interface{}{
				"request_id": strParam(p, "request_id"), "prompt_cancelled": cancelled,
			}}
		}
		review, err := s.svc.HostRelayReview(sess.HumanPrincipal, strParam(p, "request_id"), sess)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: review}
	case MethodIntakeRequest:
		// F13: trusted user-initiated creation-plus-fulfillment that
		// operates without agent IPC privileges. The trusted caller
		// may explicitly choose a broader consumption policy.
		payload, err := b64Param(p, "payload")
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		cons := strParam(p, "consumption")
		if cons == "" {
			cons = "single_dispatch"
		}
		reqID, opID, err := s.svc.RelayUserInitWithConsumption(principal,
			strParam(p, "destination_id"), strParam(p, "data_kind"), strParam(p, "purpose"),
			ttlParam(p), cons, uintParamOr(p, "max_deliveries"), payload)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"request_id": reqID, "op_id": opID, "status": "authorized",
		}}
	case MethodIntakeCredentialSave:
		// P0-3: trusted-intake credential persistence. The value arrives
		// as base64 (same envelope discipline as intake.fulfill) and
		// crosses onward ONLY through the trusted helper crossing; it is
		// never persisted in SeqPass, never logged, never echoed back.
		raw, err := b64Param(p, "value_b64")
		if err != nil {
			return Response{OK: false, Error: "value_b64: " + err.Error()}
		}
		if len(raw) > aegiskeys.MaxProvisionValueLen {
			return Response{OK: false, Error: "value too large"}
		}
		var ops []string
		if opsRaw, ok := p["operations"].([]interface{}); ok {
			for _, o := range opsRaw {
				if os, ok := o.(string); ok {
					ops = append(ops, os)
				}
			}
		}
		pReq := aegiskeys.ProvisionRequest{
			RequestID:   strParam(p, "request_id"),
			Value:       string(raw),
			Service:     strParam(p, "service"),
			Label:       strParam(p, "label"),
			Kind:        strParam(p, "kind"),
			Binding:     strParam(p, "binding"),
			Operations:  ops,
			Description: strParam(p, "description"),
			EnvVarHint:  strParam(p, "env_var_hint"),
		}
		if pReq.RequestID == "" {
			// The caller may supply a durable request ID for its own
			// retry bookkeeping; otherwise the broker generates one and
			// returns it (the reconciliation anchor for every retry).
			pReq.RequestID = "prov-" + newRequestID()
		}
		report, ref, err := s.svc.ProvisionCredential(context.Background(), principal, strParam(p, "mode"), pReq)
		if err != nil {
			// The durable reference (if created) carries the honest
			// reconcile state; report it alongside the error.
			out := map[string]interface{}{}
			if ref != nil {
				out["ref_id"] = ref.ID
				out["reconcile_status"] = ref.ReconcileStatus
				out["request_id"] = pReq.RequestID
			}
			return Response{OK: false, Error: err.Error(), Data: out}
		}
		return Response{OK: true, Data: provisionReportData(report, ref, pReq.RequestID)}
	case MethodIntakeProvisionStatus:
		report, ref, err := s.svc.ProvisionStatusReport(context.Background(), principal, strParam(p, "request_id"))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: provisionReportData(report, ref, strParam(p, "request_id"))}
	default:
		return Response{OK: false, Error: "unknown method"}
	}
}

// requireRelayHostSession checks the exact relay-to-host-session binding
// before any host-domain transition. SP-04: the service enforces that the
// session's agent and human principals match the persisted association.
// If the binding already exists and matches, this is a no-op — never
// a "already bound" error.
func (s *Server) requireRelayHostSession(agent, relayID string, sess *types.HostSession) error {
	existing, err := s.svc.DB().GetRelayHostSession(relayID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.SessionID != sess.ID || existing.AgentPrincipal != agent ||
			existing.HumanPrincipal != sess.HumanPrincipal || existing.HostKind != sess.HostKind {
			return fmt.Errorf("relay and host session bind to different agents")
		}
		return nil // already correctly bound
	}
	return s.svc.BindRelayHost(agent, relayID, sess)
}

func isAdminMethod(m string) bool {
	return len(m) > 6 && m[:6] == "admin."
}

func (s *Server) opsMine(principal string) Response {
	uses, transfers, err := s.svc.DB().ListPendingOps()
	if err != nil {
		return Response{OK: false, Error: "internal error"}
	}
	var mu []*types.UseRequest
	var mt []*types.TransferRequest
	for _, u := range uses {
		if u.RequestedBy == principal {
			mu = append(mu, u)
		}
	}
	for _, t := range transfers {
		if t.RequestedBy == principal {
			mt = append(mt, t)
		}
	}
	return Response{OK: true, Data: map[string]interface{}{"uses": mu, "transfers": mt}}
}
