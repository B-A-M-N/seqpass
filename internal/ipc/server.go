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

	"github.com/secretbridge/secretbridge/internal/intake"
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
	// IntakeSocket, when non-empty, serves the trusted human-side
	// intake domain on its own owner-only socket (QR-02/SP-TUI-04).
	// Set before Start, like AgentGID.
	IntakeSocket string
	mapper       PrincipalMapper
	auth         Authorizer
	listener     net.Listener
	adminLis     net.Listener
	intakeLis    net.Listener
	created      []string          // sockets created by this process (removed on close)
	createdID    map[string]fileID // device+inode at bind time (C09)

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
	case RoleIntake:
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
	}
	if !allow[req.Method] {
		return Response{OK: false, Error: "access denied"}
	}
	_ = ctx
	p := req.Params
	switch req.Method {
	case MethodHealth:
		mode := s.AssuranceMode
		if mode == "" {
			mode = "best-effort"
		}
		return Response{OK: true, Data: map[string]string{
			"status": "ok", "assurance_mode": mode,
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
			Name:     strParam(p, "name"),
			Type:     strParam(p, "type"),
			Endpoint: strParam(p, "endpoint"),
		}
		if d.Name == "" || d.Endpoint == "" || d.Type == "" {
			return Response{OK: false, Error: "missing fields"}
		}
		if d.Type != "recipient-socket" {
			return Response{OK: false, Error: "unsupported destination type"}
		}
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
		return Response{OK: true, Data: map[string]interface{}{
			"request_id": reqID, "status": "awaiting_user",
			"next": "Fulfill through the trusted intake (relay fulfill) before expiry",
		}}
	case MethodRelayStatus:
		st, err := s.svc.RelayStatus(principal, strParam(p, "request_id"))
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		// SP-02/SP-03: attach the broker-verified secure-input notice so
		// any harness adapter can render it without the agent fabricating
		// security claims. The assurance is derived from actual topology,
		// never from agent arguments.
		mode := "best-effort"
		if s.AssuranceMode != "" {
			mode = s.AssuranceMode
		}
		assurance := intake.Classify(mode, false, false)
		if rm := st; rm != nil {
			rm["input_mode"] = assurance.Mode
			rm["input_assurance"] = assurance.Assurance
			rm["input_protected"] = assurance.Protected
			rm["input_reason"] = assurance.Reason
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
		opID, err := s.svc.RelayFulfill(principal, strParam(p, "request_id"), raw)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"request_id": strParam(p, "request_id"), "op_id": opID, "status": "authorized",
			"next": "Authorized: the trusted worker delivers; poll relay.status for the outcome",
		}}
	case MethodIntakeReject:
		if err := s.svc.RelayReject(principal, strParam(p, "request_id")); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "rejected"}}
	case MethodIntakeCancel:
		if err := s.svc.RelayCancel(principal, strParam(p, "request_id"), true); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]string{"status": "cancelled"}}
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
	default:
		return Response{OK: false, Error: "unknown method"}
	}
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
