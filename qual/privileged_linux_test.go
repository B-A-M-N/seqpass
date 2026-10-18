//go:build linux

package qual

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/testruntime"
)

type privilegedIdentity struct {
	uid    uint32
	gid    uint32
	groups []uint32
}

type boundaryProbe struct {
	EffectiveUID       uint32            `json:"effective_uid"`
	EffectiveGID       uint32            `json:"effective_gid"`
	Groups             []uint32          `json:"supplementary_gids"`
	AssuranceMode      string            `json:"assurance_mode,omitempty"`
	HealthOK           bool              `json:"health_ok"`
	AdminMethodDenied  bool              `json:"admin_method_denied"`
	AegisSocketConnect bool              `json:"aegis_socket_connect,omitempty"`
	SocketDenied       map[string]string `json:"socket_denial,omitempty"`
	FileUnreadable     map[string]string `json:"file_denial,omitempty"`
	Errors             []string          `json:"errors,omitempty"`
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *synchronizedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b.Bytes()...)
}

func (b *synchronizedBuffer) Redact(value, replacement []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw := b.b.Bytes()
	found := bytes.Contains(raw, value)
	if found {
		redacted := bytes.ReplaceAll(raw, value, replacement)
		b.b.Reset()
		_, _ = b.b.Write(redacted)
	}
	return found
}

// runPrivilegedBoundary runs only after the explicit opt-in and root checks.
// It returns ready=false for missing lab prerequisites; actual assertion
// failures are recorded as failures and do not get relabeled as blocked.
func runPrivilegedBoundary(t *testing.T, h *harness) (ready bool, blocked string) {
	t.Helper()
	serviceUID, err := parseUIDEnv("SEQPASS_QUAL_SERVICE_UID")
	if err != nil {
		return false, err.Error()
	}
	agentUID, err := parseUIDEnv("SEQPASS_QUAL_AGENT_UID")
	if err != nil {
		return false, err.Error()
	}
	groupName := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AGENT_GROUP"))
	if groupName == "" {
		return false, "missing SEQPASS_QUAL_AGENT_GROUP (dedicated agent socket group)"
	}
	agentGroup, err := user.LookupGroup(groupName)
	if err != nil {
		return false, "cannot resolve SEQPASS_QUAL_AGENT_GROUP: " + err.Error()
	}
	agentGID64, err := strconv.ParseUint(agentGroup.Gid, 10, 32)
	if err != nil {
		return false, "agent socket group has an invalid GID"
	}
	agentGID := uint32(agentGID64)
	aegisSocket := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_SOCKET"))
	vaultPath := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_VAULT"))
	metadataPath := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_METADATA"))
	aegisRevision := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_REV"))
	if aegisRevision != "" && !isFullSourceRevision(aegisRevision) {
		return false, "SEQPASS_QUAL_AEGISKEYS_REV must be the full 40-character AegisKeys Git revision"
	}
	var missing []string
	if aegisSocket == "" {
		missing = append(missing, "SEQPASS_QUAL_AEGISKEYS_SOCKET")
	}
	if vaultPath == "" {
		missing = append(missing, "SEQPASS_QUAL_AEGISKEYS_VAULT")
	}
	if metadataPath == "" {
		missing = append(missing, "SEQPASS_QUAL_AEGISKEYS_METADATA")
	}
	if aegisRevision == "" {
		missing = append(missing, "SEQPASS_QUAL_AEGISKEYS_REV (deployed source revision)")
	}
	if len(missing) != 0 {
		return false, "missing " + strings.Join(missing, ", ")
	}
	if serviceUID == 0 || serviceUID == agentUID || agentUID == 0 {
		return false, "service and agent UIDs must be distinct non-root identities"
	}
	serviceUser, err := user.LookupId(strconv.FormatUint(uint64(serviceUID), 10))
	if err != nil {
		return false, "cannot resolve service UID: " + err.Error()
	}
	agentUser, err := user.LookupId(strconv.FormatUint(uint64(agentUID), 10))
	if err != nil {
		return false, "cannot resolve agent UID: " + err.Error()
	}
	serviceIdentity, err := identityFor(serviceUser)
	if err != nil {
		return false, "cannot load service groups: " + err.Error()
	}
	agentIdentity, err := identityFor(agentUser)
	if err != nil {
		return false, "cannot load agent groups: " + err.Error()
	}
	if !containsGID(agentIdentity.groups, agentGID) {
		return false, fmt.Sprintf("agent UID %d is not a member of socket group %s (GID %d)", agentUID, groupName, agentGID)
	}
	artifactDir := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_ARTIFACT_DIR"))
	if artifactDir == "" {
		return false, "missing SEQPASS_QUAL_ARTIFACT_DIR (live qualification evidence must be retained)"
	}
	if err := requireProtectedArtifactDir(artifactDir, uint32(os.Geteuid())); err != nil {
		return false, "qualification artifact directory is not private: " + err.Error()
	}
	if agentUID == serviceUID {
		return false, "agent UID must differ from the broker service UID"
	}
	if err := requireLiveSocket(aegisSocket); err != nil {
		return false, "AegisKeys broker socket is not live: " + err.Error()
	}
	aegisPeer, err := fingerprintUnixPeer(aegisSocket)
	if err != nil {
		return false, "cannot fingerprint live AegisKeys socket peer: " + err.Error()
	}
	for name, path := range map[string]string{"AegisKeys vault": vaultPath, "AegisKeys metadata": metadataPath} {
		if err := requireExistingPrivateTarget(path); err != nil {
			return false, fmt.Sprintf("%s prerequisite failed: %v", name, err)
		}
	}

	root, err := testruntime.Dir(testruntime.NamedFunc("privileged-isolated-qual"))
	if err != nil {
		h.recordTier("privileged-runtime", tierSystem, "create a disposable private qualification tree", "temporary root is created", err.Error(), false)
		return true, ""
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0711); err != nil {
		h.recordTier("privileged-runtime", tierSystem, "allow configured service and agent to traverse only the disposable root", "root mode 0711", err.Error(), false)
		return true, ""
	}
	if err := os.Chown(root, 0, 0); err != nil {
		h.recordTier("privileged-runtime", tierSystem, "make the disposable path root-owned", "root UID/GID own the traversal directory", err.Error(), false)
		return true, ""
	}

	stateDir := filepath.Join(root, "state")
	agentDir := filepath.Join(root, "agent")
	adminDir := filepath.Join(root, "admin")
	intakeDir := filepath.Join(root, "intake")
	for _, dir := range []struct {
		path string
		uid  uint32
		gid  uint32
		mode os.FileMode
	}{
		{stateDir, serviceUID, serviceIdentity.gid, 0700},
		{agentDir, serviceUID, agentGID, 0710},
		{adminDir, serviceUID, serviceIdentity.gid, 0700},
		{intakeDir, serviceUID, serviceIdentity.gid, 0700},
	} {
		if err := os.Mkdir(dir.path, 0700); err != nil {
			h.recordTier("privileged-runtime", tierSystem, "create disjoint broker runtime directories", "all dirs created with isolated ownership", err.Error(), false)
			return true, ""
		}
		if err := os.Chown(dir.path, int(dir.uid), int(dir.gid)); err != nil {
			h.recordTier("privileged-runtime", tierSystem, "assign runtime directory ownership", "service owner and intended group", err.Error(), false)
			return true, ""
		}
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			h.recordTier("privileged-runtime", tierSystem, "assign runtime directory permissions", fmt.Sprintf("mode %o", dir.mode), err.Error(), false)
			return true, ""
		}
	}

	bin := buildBinary(t, root)
	h.bin = bin
	if err := os.Chmod(bin, 0755); err != nil {
		h.recordTier("privileged-build", tierSystem, "make broker executable available to its service UID", "binary mode 0755", err.Error(), false)
		return true, ""
	}
	probeBin, err := buildBoundaryProbe(t, root)
	if err != nil {
		h.recordTier("privileged-probe-build", tierSystem, "build a stdlib-only external UID probe", "probe builds without project-private test hooks", err.Error(), false)
		return true, ""
	}

	h.agent = filepath.Join(agentDir, "agent.sock")
	h.admin = filepath.Join(adminDir, "admin.sock")
	intakeSocket := filepath.Join(intakeDir, "intake.sock")
	dbPath := filepath.Join(stateDir, "seqpass.db")
	h.uid = strconv.FormatUint(uint64(agentUID), 10)
	h.topology = map[string]string{
		"assurance_mode":             "isolated",
		"service_uid":                strconv.FormatUint(uint64(serviceUID), 10),
		"agent_uid":                  h.uid,
		"service_gid":                strconv.FormatUint(uint64(serviceIdentity.gid), 10),
		"agent_socket_group":         groupName,
		"agent_socket_gid":           strconv.FormatUint(uint64(agentGID), 10),
		"agent_socket":               h.agent,
		"admin_socket":               h.admin,
		"intake_socket":              intakeSocket,
		"aegiskeys_socket":           aegisSocket,
		"aegiskeys_vault":            vaultPath,
		"aegiskeys_metadata":         metadataPath,
		"seqpass_db":                 dbPath,
		"artifact_directory":         artifactDir,
		"service_supplementary_gids": strings.Trim(strings.ReplaceAll(fmt.Sprint(serviceIdentity.groups), " ", ","), "[]"),
		"agent_supplementary_gids":   strings.Trim(strings.ReplaceAll(fmt.Sprint(agentIdentity.groups), " ", ","), "[]"),
		"aegiskeys_source_revision":  aegisRevision,
	}
	for key, value := range aegisPeer {
		h.topology[key] = value
	}
	for key, path := range map[string]string{"aegiskeys_socket": aegisSocket, "aegiskeys_vault": vaultPath, "aegiskeys_metadata": metadataPath} {
		h.topology[key+"_owner_mode"] = ownershipMode(path)
	}
	peerRevision := aegisPeer["aegiskeys_peer_vcs_revision"]
	h.recordTier("aegiskeys-listener-identity", tierSystem,
		"identify the actual process accepting the AegisKeys Unix socket", "peer UID, executable digest, and available build identity are recorded",
		fmt.Sprintf("pid=%s uid=%s sha256=%s vcs_revision=%s", aegisPeer["aegiskeys_peer_pid"], aegisPeer["aegiskeys_peer_uid"], aegisPeer["aegiskeys_peer_binary_sha256"], peerRevision),
		aegisPeer["aegiskeys_peer_pid"] != "" && aegisPeer["aegiskeys_peer_binary_sha256"] != "")
	if peerRevision == "" {
		h.recordNotExercised("aegiskeys-source-revision-match", tierSystem,
			"live AegisKeys VCS revision matches the declared deployment revision",
			"the listener executable does not expose vcs.revision build metadata")
	} else {
		revisionMatches := isFullSourceRevision(peerRevision) && peerRevision == aegisRevision
		h.recordTier("aegiskeys-source-revision-match", tierSystem,
			"compare the live listener build revision with the declared deployment revision",
			"embedded and declared revisions match",
			fmt.Sprintf("embedded=%s declared=%s match=%t", peerRevision, aegisRevision, revisionMatches), revisionMatches)
	}

	serviceProbe := runCredentialed(t, probeBin, serviceIdentity, serviceUser, []string{
		"service", strconv.FormatUint(uint64(serviceUID), 10), aegisSocket,
	})
	var svcResult boundaryProbe
	serviceOK := decodeProbe(serviceProbe, &svcResult) == nil && svcResult.EffectiveUID == serviceUID && svcResult.AegisSocketConnect
	h.recordTier("service-can-reach-aegiskeys-socket", tierSystem,
		"broker service identity has access to its configured AegisKeys broker", "service UID connects to live AegisKeys socket",
		fmt.Sprintf("uid=%d gid=%d groups=%v connected=%t", svcResult.EffectiveUID, svcResult.EffectiveGID, svcResult.Groups, svcResult.AegisSocketConnect), serviceOK)

	args := []string{
		"broker", "--vault", "aegiskeys", "--db", dbPath,
		"--socket", h.agent, "--admin-socket", h.admin, "--intake-socket", intakeSocket,
		"--assurance", "isolated",
		"--agent-uid", strconv.FormatUint(uint64(agentUID), 10),
		"--admin-uid", strconv.FormatUint(uint64(serviceUID), 10),
		"--intake-uid", strconv.FormatUint(uint64(serviceUID), 10),
		"--socket-group", groupName,
		"--aegiskeys-socket", aegisSocket,
	}
	if aegisDir := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_DIR")); aegisDir != "" {
		args = append(args, "--aegiskeys-dir", aegisDir)
	}
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(serviceIdentity)}
	cmd.Env = identityEnvironment(serviceUser, nil)
	var brokerLog synchronizedBuffer
	cmd.Stdout = &brokerLog
	cmd.Stderr = &brokerLog
	oldMask := syscall.Umask(0077)
	startErr := cmd.Start()
	syscall.Umask(oldMask)
	if startErr != nil {
		h.recordTier("isolated-broker-start", tierSystem, "launch the real broker as the dedicated service UID", "broker starts in isolated mode", startErr.Error(), false)
		return true, ""
	}
	brokerDone := make(chan struct{})
	var brokerErr error
	go func() { brokerErr = cmd.Wait(); close(brokerDone) }()
	brokerStopped := false
	t.Cleanup(func() {
		if brokerStopped {
			return
		}
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-brokerDone:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-brokerDone
		}
	})

	live := waitForSockets([]string{h.agent, h.admin, intakeSocket}, 10*time.Second)
	if !live {
		select {
		case <-brokerDone:
			h.recordTier("isolated-broker-start", tierSystem, "launch the real broker as the dedicated service UID", "all three isolated sockets become live", fmt.Sprintf("broker exited: %v log=%s", brokerErr, trimOutput(brokerLog.Bytes())), false)
		default:
			h.recordTier("isolated-broker-start", tierSystem, "launch the real broker as the dedicated service UID", "all three isolated sockets become live", "socket startup timed out; log="+trimOutput(brokerLog.Bytes()), false)
		}
		return true, ""
	}

	layoutOK, layoutObserved := verifySocketLayout(h.agent, h.admin, intakeSocket, serviceUID, serviceIdentity.gid, agentGID, root, stateDir, agentDir, adminDir, intakeDir)
	h.recordTier("isolated-socket-layout", tierSystem,
		"independently inspect live socket and state ownership/modes", "agent socket is service-owned/group-accessible; admin/intake/state are private",
		layoutObserved, layoutOK)
	dbOK, dbObserved := verifyPrivateFile(dbPath, serviceUID)
	h.topology["seqpass_db_owner_mode"] = ownershipMode(dbPath)
	h.recordTier("isolated-seqpass-database-private", tierSystem,
		"independently inspect the broker database file after initialization", "service-owned regular file mode 0600",
		dbObserved, dbOK)
	for name, path := range map[string]string{"admin": h.admin, "intake": intakeSocket, "AegisKeys": aegisSocket} {
		err := requireLiveSocket(path)
		h.recordTier("protected-socket-live-"+strings.ToLower(name), tierSystem,
			"prove denied socket paths name live listeners before the agent denial check", "root observer can connect to listener",
			fmt.Sprintf("%s", resultText(err)), err == nil)
	}

	probeArgs := []string{
		"agent", strconv.FormatUint(uint64(agentUID), 10), h.agent, h.admin, intakeSocket,
		aegisSocket, vaultPath, metadataPath, dbPath,
	}
	probeOutput := runCredentialed(t, probeBin, agentIdentity, agentUser, probeArgs)
	var agentResult boundaryProbe
	parseErr := decodeProbe(probeOutput, &agentResult)
	if parseErr != nil {
		h.recordTier("agent-boundary-probe", tierSystem, "run independent probe under the dedicated agent UID", "probe returns structured observations", parseErr.Error()+" output="+trimOutput(probeOutput), false)
	} else {
		h.recordTier("agent-health-over-allowed-socket", tierSystem,
			"agent reaches the real SeqPass agent socket", "health response declares isolated assurance",
			fmt.Sprintf("uid=%d gid=%d groups=%v health=%t assurance=%s", agentResult.EffectiveUID, agentResult.EffectiveGID, agentResult.Groups, agentResult.HealthOK, agentResult.AssuranceMode),
			agentResult.EffectiveUID == agentUID && containsGID(agentResult.Groups, agentGID) && agentResult.HealthOK && agentResult.AssuranceMode == "isolated")
		h.recordTier("agent-admin-method-denied", tierSystem,
			"agent socket rejects a privileged method even on its allowed endpoint", "admin method returns access denied",
			fmt.Sprintf("denied=%t", agentResult.AdminMethodDenied), agentResult.AdminMethodDenied)
		for _, name := range []string{"admin", "intake", "aegiskeys"} {
			errText := agentResult.SocketDenied[name]
			denied := permissionDenied(errText)
			h.recordTier("agent-cannot-connect-"+name+"-socket", tierSystem,
				"agent UID cannot connect directly to a live trusted socket", "kernel denies socket connection with EACCES or EPERM",
				fmt.Sprintf("denied=%t error=%s", denied, errText), denied)
		}
		for _, name := range []string{"aegiskeys_vault", "aegiskeys_metadata", "seqpass_db"} {
			errText := agentResult.FileUnreadable[name]
			denied := permissionDenied(errText)
			h.recordTier("agent-cannot-read-"+name, tierSystem,
				"agent UID cannot read protected credential or broker state", "kernel denies file open with EACCES or EPERM",
				fmt.Sprintf("unreadable=%t error=%s", denied, errText), denied)
		}
	}
	relayCaseStart := len(h.cases)
	relayMarker := qualifyPrivilegedRelay(t, h, root, probeBin, serviceIdentity, agentIdentity, serviceUser, agentUser, stateDir, intakeSocket)
	_ = cmd.Process.Signal(syscall.SIGINT)
	cleanShutdown := false
	select {
	case <-brokerDone:
		cleanShutdown = brokerErr == nil
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-brokerDone
	}
	brokerStopped = true
	h.recordTier("isolated-broker-clean-shutdown", tierSystem,
		"stop the isolated broker after access checks and wait for worker/database cleanup",
		"broker exits cleanly on SIGINT", fmt.Sprintf("exit_error=%v", brokerErr), cleanShutdown)
	if len(relayMarker) != 0 {
		brokerLogLeaked := brokerLog.Redact(relayMarker, []byte("[REDACTED-QUALIFICATION-VALUE]"))
		encoded := []byte(base64.StdEncoding.EncodeToString(relayMarker))
		brokerLogLeaked = brokerLog.Redact(encoded, []byte("[REDACTED-QUALIFICATION-VALUE]")) || brokerLogLeaked
		clear(encoded)
		if !brokerLogLeaked {
			h.recordTier("broker-log-nondisclosure", tierSystem, "inspect real broker stdout/stderr after trusted fulfillment and shutdown", "broker logs omit the synthetic value", "credential absent", true)
		} else {
			h.recordTier("broker-log-nondisclosure", tierSystem, "inspect real broker stdout/stderr after trusted fulfillment and shutdown", "broker logs omit the synthetic value", "credential found and redacted in broker output", false)
		}
		clear(relayMarker)
	} else {
		h.recordNotExercised("broker-log-nondisclosure", tierSystem,
			"broker logs omit the synthetic value", "protected relay did not reach synthetic payload creation")
	}
	recordProtectedRelayAggregate(h, h.cases[relayCaseStart:])
	brokerLogName := fmt.Sprintf("qual-broker-%d.log", time.Now().UnixNano())
	if err := writeProtectedArtifact(artifactDir, brokerLogName, brokerLog.Bytes()); err != nil {
		h.recordTier("privileged-log-retention", tierSystem, "retain broker output with restricted permissions", "mode-0600 log is retained in the protected evidence directory", err.Error(), false)
	} else {
		h.topology["broker_log"] = brokerLogName
	}
	return true, ""
}

func parseUIDEnv(name string) (uint32, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, fmt.Errorf("missing %s", name)
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a numeric UID", name)
	}
	return uint32(n), nil
}

func identityFor(u *user.User) (privilegedIdentity, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return privilegedIdentity{}, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return privilegedIdentity{}, err
	}
	groupStrings, err := u.GroupIds()
	if err != nil {
		return privilegedIdentity{}, err
	}
	groups := make([]uint32, 0, len(groupStrings))
	for _, item := range groupStrings {
		g, err := strconv.ParseUint(item, 10, 32)
		if err != nil {
			return privilegedIdentity{}, err
		}
		groups = append(groups, uint32(g))
	}
	return privilegedIdentity{uid: uint32(uid), gid: uint32(gid), groups: groups}, nil
}

func credentialFor(id privilegedIdentity) *syscall.Credential {
	return &syscall.Credential{Uid: id.uid, Gid: id.gid, Groups: id.groups}
}

func containsGID(gids []uint32, wanted uint32) bool {
	for _, gid := range gids {
		if gid == wanted {
			return true
		}
	}
	return false
}

func requireLiveSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path is not a Unix socket")
	}
	conn, err := net.DialTimeout("unix", path, 1500*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
}

func requireExistingPrivateTarget(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink target refused")
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return fmt.Errorf("target must be a regular file or directory")
	}
	return nil
}

func requireProtectedArtifactDir(path string, owner uint32) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path must be a real directory, not a symlink")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != owner {
		return fmt.Errorf("directory must be owned by test UID %d", owner)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("group/other permissions must be absent (want 0700 or tighter)")
	}
	if info.Mode().Perm()&0300 != 0300 {
		return fmt.Errorf("owner must have read/write/traverse access to write retained evidence")
	}
	return nil
}

func writeProtectedArtifact(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func ownershipMode(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "unavailable"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("mode=%04o", info.Mode().Perm())
	}
	return fmt.Sprintf("uid=%d,gid=%d,mode=%04o", st.Uid, st.Gid, info.Mode().Perm())
}

func waitForSockets(paths []string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ready := true
		for _, path := range paths {
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
				ready = false
				break
			}
		}
		if ready {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func verifySocketLayout(agent, admin, intake string, serviceUID, serviceGID, agentGID uint32, root, stateDir, agentDir, adminDir, intakeDir string) (bool, string) {
	checks := []struct {
		path string
		uid  uint32
		gid  uint32
		mode os.FileMode
	}{
		{agent, serviceUID, agentGID, 0660},
		{admin, serviceUID, serviceGID, 0600},
		{intake, serviceUID, serviceGID, 0600},
	}
	var observed []string
	ok := true
	for _, c := range checks {
		info, err := os.Lstat(c.path)
		if err != nil {
			observed = append(observed, filepath.Base(c.path)+": stat error")
			ok = false
			continue
		}
		st, valid := info.Sys().(*syscall.Stat_t)
		if !valid || info.Mode()&os.ModeSocket == 0 {
			observed = append(observed, filepath.Base(c.path)+": not a socket")
			ok = false
			continue
		}
		entryOK := st.Uid == c.uid && uint32(st.Gid) == c.gid && info.Mode().Perm() == c.mode
		observed = append(observed, fmt.Sprintf("%s uid=%d gid=%d mode=%04o ok=%t", filepath.Base(c.path), st.Uid, st.Gid, info.Mode().Perm(), entryOK))
		ok = ok && entryOK
	}
	for _, c := range []struct {
		path string
		uid  uint32
		gid  uint32
		mode os.FileMode
	}{{root, 0, 0, 0711}, {stateDir, serviceUID, serviceGID, 0700}, {agentDir, serviceUID, agentGID, 0710}, {adminDir, serviceUID, serviceGID, 0700}, {intakeDir, serviceUID, serviceGID, 0700}} {
		info, err := os.Stat(c.path)
		if err != nil {
			observed = append(observed, filepath.Base(c.path)+": stat error")
			ok = false
			continue
		}
		st, valid := info.Sys().(*syscall.Stat_t)
		entryOK := valid && st.Uid == c.uid && uint32(st.Gid) == c.gid && info.Mode().Perm() == c.mode
		observed = append(observed, fmt.Sprintf("%s uid=%d gid=%d mode=%04o ok=%t", filepath.Base(c.path), st.Uid, st.Gid, info.Mode().Perm(), entryOK))
		ok = ok && entryOK
	}
	return ok, strings.Join(observed, "; ")
}

func verifyPrivateFile(path string, owner uint32) (bool, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, "stat failed: " + err.Error()
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return false, "database is not a regular file"
	}
	private := info.Mode().Perm() == 0600 && st.Uid == owner
	return private, fmt.Sprintf("uid=%d gid=%d mode=%04o private=%t", st.Uid, st.Gid, info.Mode().Perm(), private)
}

func fingerprintUnixPeer(path string) (map[string]string, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		peer, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if controlErr != nil {
		return nil, controlErr
	}
	procExe := fmt.Sprintf("/proc/%d/exe", peer.Pid)
	exePath, _ := os.Readlink(procExe)
	f, err := os.Open(procExe)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		_ = f.Close()
		return nil, err
	}
	_ = f.Close()
	info := map[string]string{
		"aegiskeys_peer_pid":           strconv.Itoa(int(peer.Pid)),
		"aegiskeys_peer_uid":           strconv.FormatUint(uint64(peer.Uid), 10),
		"aegiskeys_peer_gid":           strconv.FormatUint(uint64(peer.Gid), 10),
		"aegiskeys_peer_executable":    exePath,
		"aegiskeys_peer_binary_sha256": hex.EncodeToString(hash.Sum(nil)),
		"aegiskeys_peer_vcs_revision":  "",
		"aegiskeys_peer_build_version": "",
		"aegiskeys_peer_build_module":  "",
	}
	if build, err := buildinfo.ReadFile(procExe); err == nil {
		info["aegiskeys_peer_build_version"] = build.GoVersion
		info["aegiskeys_peer_build_module"] = build.Path
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" {
				info["aegiskeys_peer_vcs_revision"] = setting.Value
			}
		}
	}
	return info, nil
}

func buildBoundaryProbe(t *testing.T, dir string) (string, error) {
	t.Helper()
	bin := filepath.Join(dir, "boundary-probe")
	cmd := exec.Command("go", "build", "-o", bin, "./privileged_probe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build boundary probe: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Chmod(bin, 0755); err != nil {
		return "", err
	}
	return bin, nil
}

func TestQualBoundaryProbeBuilds(t *testing.T) {
	if _, err := buildBoundaryProbe(t, t.TempDir()); err != nil {
		t.Fatalf("build isolated boundary probe: %v", err)
	}
}

func TestPrivilegedProbeIPCRoundTrip(t *testing.T) {
	// Sandboxed environments may expose /home as nobody:nogroup even when
	// the test runtime directory itself is correctly owned. The broker
	// refuses such ancestors by design; skip these socket tests there.
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	probe, err := buildBoundaryProbe(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "probe.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type observedRequest struct {
		method string
		params map[string]interface{}
		err    error
	}
	observed := make(chan observedRequest, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			observed <- observedRequest{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var request struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			observed <- observedRequest{err: err}
			return
		}
		observed <- observedRequest{method: request.Method, params: request.Params}
		_ = json.NewEncoder(conn).Encode(map[string]interface{}{
			"id": "qual-trusted", "ok": true, "data": map[string]interface{}{"accepted": true},
		})
	}()

	cmd := exec.Command(probe, "ipc", socket, "qual.echo")
	cmd.Stdin = strings.NewReader(`{"sample":"fixture"}`)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = identityEnvironment(current, nil)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("IPC probe failed: %v (%s)", err, trimOutput(output))
	}
	var response map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(output), &response); err != nil {
		t.Fatalf("decode IPC probe response: %v", err)
	}
	if response["ok"] != true {
		t.Fatalf("probe response not accepted: %v", response)
	}
	select {
	case got := <-observed:
		if got.err != nil || got.method != "qual.echo" || got.params["sample"] != "fixture" {
			t.Fatalf("request mismatch: %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe probe request")
	}
}

func permissionDenied(err string) bool {
	return err == "EACCES" || err == "EPERM"
}

func runCredentialed(t *testing.T, bin string, id privilegedIdentity, u *user.User, args []string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(id)}
	cmd.Env = identityEnvironment(u, nil)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		t.Logf("credentialed probe uid=%d exited: %v (%s)", id.uid, err, trimOutput(stderr.Bytes()))
	}
	if stderr.Len() != 0 {
		t.Logf("credentialed probe uid=%d stderr: %s", id.uid, trimOutput(stderr.Bytes()))
	}
	return stdout.Bytes()
}

func decodeProbe(raw []byte, dst *boundaryProbe) error {
	if len(raw) == 0 {
		return fmt.Errorf("probe produced no output")
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), dst); err != nil {
		return fmt.Errorf("invalid probe JSON: %w", err)
	}
	return nil
}

func trimOutput(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if len(text) > 1200 {
		return text[:1200] + "..."
	}
	return text
}

func containsValue(haystack, value []byte) bool {
	if len(value) == 0 {
		return false
	}
	return bytes.Contains(haystack, value) || bytes.Contains(haystack, []byte(base64.StdEncoding.EncodeToString(value)))
}

func qualifyPrivilegedRelay(
	t *testing.T,
	h *harness,
	root, probeBin string,
	serviceIdentity, agentIdentity privilegedIdentity,
	serviceUser, agentUser *user.User,
	stateDir, intakeSocket string,
) (marker []byte) {
	t.Helper()
	recipientDir := filepath.Join(root, "qual-recipient")
	if err := os.Mkdir(recipientDir, 0700); err != nil {
		h.recordTier("protected-relay-setup", tierSystem, "prepare an independent local recipient", "recipient socket and store are private to the qualification runtime", err.Error(), false)
		return
	}
	recipient := startRecipient(t, recipientDir, "recipient.sock")
	t.Cleanup(func() { _ = recipient.lis.Close() })
	if err := os.Chmod(recipientDir, 0711); err != nil {
		h.recordTier("protected-relay-setup", tierSystem, "make the root-owned fixture path traversable by the broker", "root-owned directory is not group/other writable", err.Error(), false)
		return
	}
	if err := os.Chmod(recipient.sock, 0666); err != nil {
		h.recordTier("protected-relay-setup", tierSystem, "allow the broker UID to connect to the pinned fixture recipient", "socket is reachable only through a root-owned non-writable directory", err.Error(), false)
		return
	}

	destResponse, err := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.dest_add", map[string]interface{}{
		"name": "privileged-qualification-recipient", "type": "recipient-socket",
		"endpoint": recipient.sock, "expected_uid": float64(0),
	})
	destinationID := responseString(destResponse, "id")
	if err != nil || destinationID == "" {
		h.recordTier("protected-relay-setup", tierSystem, "register a pinned local recipient through the trusted admin socket", "service UID receives a destination ID", fmt.Sprint(err), false)
		return
	}

	agentCmd := exec.Command(h.bin, "mcp", "--socket", h.agent)
	agentCmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(agentIdentity)}
	agentCmd.Env = identityEnvironment(agentUser, map[string]string{"SEQ_PASS_SOCKET": h.agent})
	agentIn, err := agentCmd.StdinPipe()
	if err != nil {
		h.recordTier("protected-relay-setup", tierSystem, "start real MCP stdio adapter under the agent UID", "pipes are available", err.Error(), false)
		return
	}
	agentOut, err := agentCmd.StdoutPipe()
	if err != nil {
		_ = agentIn.Close()
		h.recordTier("protected-relay-setup", tierSystem, "start real MCP stdio adapter under the agent UID", "stdout is observable by an independent harness", err.Error(), false)
		return
	}
	var agentErr bytes.Buffer
	agentCmd.Stderr = &agentErr
	if err := agentCmd.Start(); err != nil {
		_ = agentIn.Close()
		h.recordTier("protected-relay-setup", tierSystem, "start real MCP stdio adapter under the agent UID", "process runs under the configured agent identity", err.Error(), false)
		return
	}
	agentStopped := false
	t.Cleanup(func() {
		if !agentStopped {
			_ = agentIn.Close()
			_ = agentCmd.Process.Kill()
			_ = agentCmd.Wait()
		}
	})
	reader := bufio.NewReader(agentOut)
	var transcript bytes.Buffer
	var requestTrace bytes.Buffer
	initReply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05", "capabilities": map[string]interface{}{},
		"clientInfo": map[string]interface{}{"name": "seqpass-privileged-qual", "version": "1"},
	})
	if err == nil {
		if _, ok := initReply["result"]; !ok {
			err = fmt.Errorf("MCP initialize has no result")
		}
	}
	if err == nil {
		err = writeMCPNotification(agentIn, "notifications/initialized")
	}
	if err != nil {
		h.recordTier("protected-relay-mcp-start", tierSystem, "initialize the real MCP adapter under the agent UID", "MCP handshake completes", err.Error(), false)
		return
	}
	requestReply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 2, "tools/call", map[string]interface{}{
		"name": "relay_request", "arguments": map[string]interface{}{
			"destination_id": destinationID, "data_kind": "api_key", "purpose": "isolated process qualification",
		},
	})
	requestText, textErr := mcpToolText(requestReply)
	var requestData map[string]interface{}
	if textErr == nil {
		textErr = json.Unmarshal([]byte(requestText), &requestData)
	}
	requestID, _ := requestData["request_id"].(string)
	nextStep, _ := requestData["next_step"].(string)
	requestShapeOK := len(requestData) == 3 && requestData["state"] == "awaiting_user" &&
		strings.Contains(nextStep, "seqpass relay fulfill "+requestID)
	if err != nil || textErr != nil || requestID == "" || !requestShapeOK {
		h.recordTier("protected-relay-mcp-request", tierSystem, "request operator input through the untrusted MCP process", "agent receives only an opaque request ID", fmt.Sprintf("mcp=%v parse=%v", err, textErr), false)
		return
	}
	h.recordTier("protected-relay-mcp-request", tierSystem,
		"request operator input through the untrusted MCP process", "agent sees only an opaque request ID and trusted-terminal next step",
		"opaque request ID, awaiting_user state, trusted-terminal instruction", true)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		h.recordTier("protected-relay-secret-fixture", tierSystem, "generate a unique synthetic payload for process observation", "random marker is available only to the trusted harness", err.Error(), false)
		return
	}
	marker = []byte("SEQPASS-QUAL-SECRET-" + hex.EncodeToString(secret))
	clear(secret)
	markerEncoded := []byte(base64.StdEncoding.EncodeToString(marker))
	defer clear(markerEncoded)
	digest := sha256.Sum256(marker)
	h.topology["relay_secret_sha256"] = hex.EncodeToString(digest[:])
	payloadPath := filepath.Join(stateDir, "qual-relay-payload")
	payloadFile, err := os.OpenFile(payloadPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = payloadFile.Write(marker)
	}
	if err == nil {
		err = payloadFile.Sync()
	}
	if payloadFile != nil {
		if closeErr := payloadFile.Close(); err == nil {
			err = closeErr
		}
	}
	if err == nil {
		err = os.Chown(payloadPath, int(serviceIdentity.uid), int(serviceIdentity.gid))
	}
	if err == nil {
		err = os.Chmod(payloadPath, 0600)
	}
	if err != nil {
		h.recordTier("protected-relay-secret-fixture", tierSystem, "stage a synthetic value in service-owned protected storage", "mode-0600 file is readable by the trusted service and denied to the agent", err.Error(), false)
		return
	}
	defer os.Remove(payloadPath)
	payload, err := os.ReadFile(payloadPath)
	if err != nil || !bytes.Equal(payload, marker) {
		clear(payload)
		h.recordTier("protected-relay-secret-fixture", tierSystem, "read the synthetic value from the trusted-only fixture file", "trusted observer reads the exact generated value", fmt.Sprint(err), false)
		return
	}
	defer clear(payload)

	probeArgs := []string{
		"agent", strconv.FormatUint(uint64(agentIdentity.uid), 10), h.agent, h.admin, intakeSocket,
		strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_SOCKET")),
		strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_VAULT")),
		strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_METADATA")),
		filepath.Join(stateDir, "seqpass.db"), payloadPath,
	}
	probeOutput := runCredentialed(t, probeBin, agentIdentity, agentUser, probeArgs)
	var agentProbe boundaryProbe
	probeErr := decodeProbe(probeOutput, &agentProbe)
	payloadDenied := probeErr == nil && permissionDenied(agentProbe.FileUnreadable["trusted_payload"])
	h.recordTier("agent-cannot-read-relay-payload", tierSystem,
		"verify the agent UID cannot open the trusted operator's synthetic payload file", "kernel denies the payload path with EACCES or EPERM",
		fmt.Sprintf("denied=%t error=%s", payloadDenied, agentProbe.FileUnreadable["trusted_payload"]), payloadDenied)

	encoded, _ := json.Marshal(map[string]interface{}{
		"request_id": requestID, "payload": base64.StdEncoding.EncodeToString(payload),
	})
	fulfillInput := append(bytes.Clone(encoded), '\n')
	clear(encoded)
	fulfillResponse, err := runCredentialedInput(t, probeBin, serviceIdentity, serviceUser, []string{"ipc", intakeSocket, "intake.fulfill"}, fulfillInput)
	var fulfill map[string]interface{}
	if err == nil {
		err = json.Unmarshal(bytes.TrimSpace(fulfillResponse), &fulfill)
	}
	if err != nil || fulfill["ok"] != true {
		h.recordTier("trusted-intake-fulfillment", tierSystem, "fulfill the request from a trusted service UID through the intake socket", "broker accepts the value without returning it to the agent", fmt.Sprintf("helper_error=%t response_contains_payload=%t", err != nil, containsValue(fulfillResponse, marker)), false)
		return
	}
	h.recordTier("trusted-intake-fulfillment", tierSystem,
		"fulfill the request from a trusted service UID through the intake socket", "broker authorizes the request without returning the value",
		fmt.Sprintf("authorized=%t response_contains_payload=%t", fulfill["ok"] == true, containsValue(fulfillResponse, marker)), fulfill["ok"] == true && !containsValue(fulfillResponse, marker))

	status := ""
	var statusErr error
	for i := 0; i < 100; i++ {
		reply, callErr := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 3+i, "tools/call", map[string]interface{}{
			"name": "relay_status", "arguments": map[string]interface{}{"request_id": requestID},
		})
		if callErr != nil {
			statusErr = callErr
			break
		}
		body, parseErr := mcpToolText(reply)
		var statusData map[string]interface{}
		if parseErr == nil {
			parseErr = json.Unmarshal([]byte(body), &statusData)
		}
		if parseErr != nil {
			statusErr = parseErr
			break
		}
		status, _ = statusData["status"].(string)
		if status == "delivered" || status == "uncertain" || status == "failed" || status == "expired" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	received := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := recipient.snapshot()
		for _, payload := range got {
			if bytes.Equal(payload, marker) {
				received = true
			}
		}
		if received {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if statusErr == nil {
		h.recordTier("protected-relay-recipient-acceptance", tierSystem,
			"observe the recipient's independently persisted bytes and the agent's relay status", "recipient persists exact synthetic value and MCP status is delivered",
			fmt.Sprintf("recipient_received=%t agent_status=%s", received, status), received && status == "delivered")
	} else {
		h.recordTier("protected-relay-recipient-acceptance", tierSystem,
			"observe the recipient's independently persisted bytes and the agent's relay status", "recipient persists exact synthetic value and MCP status is delivered",
			fmt.Sprintf("recipient_received=%t agent_status=%s status_error=%v", received, status, statusErr), false)
	}

	cmdline, cmdlineErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", agentCmd.Process.Pid))
	env, envErr := os.ReadFile(fmt.Sprintf("/proc/%d/environ", agentCmd.Process.Pid))
	mcpInputClean := !containsValue(requestTrace.Bytes(), marker)
	streamClean := !containsValue(transcript.Bytes(), marker)
	if cmdlineErr != nil || envErr != nil {
		h.recordBlocked("agent-process-metadata-observation", tierSystem, "inspect the live MCP child's argv and environment", fmt.Sprintf("cmdline=%v environ=%v", cmdlineErr, envErr))
	} else {
		processMetadataClean := !containsValue(cmdline, marker) && !containsValue(env, marker)
		h.recordTier("agent-process-metadata-nondisclosure", tierSystem,
			"inspect the live MCP child's argv and environment", "process metadata omits the synthetic value",
			fmt.Sprintf("credential_absent=%t", processMetadataClean), processMetadataClean)
	}
	if err := os.Remove(payloadPath); err != nil {
		t.Logf("remove synthetic qualification payload: %v", err)
	}
	memoryContains, memoryErr := processMemoryContains(agentCmd.Process.Pid, marker)
	if memoryErr == nil {
		memoryContainsEncoded, encodedErr := processMemoryContains(agentCmd.Process.Pid, markerEncoded)
		if encodedErr != nil {
			memoryErr = encodedErr
		} else {
			memoryContains = memoryContains || memoryContainsEncoded
		}
	}
	if memoryErr != nil {
		h.recordBlocked("agent-process-memory-observation", tierSystem, "independently scan readable agent process mappings for the synthetic value", memoryErr.Error())
	} else {
		h.recordTier("agent-process-memory-excludes-payload", tierSystem,
			"independently scan readable agent process mappings after trusted fulfillment", "the unique synthetic value is absent from agent-readable memory",
			fmt.Sprintf("contains_payload=%t", memoryContains), !memoryContains)
	}
	probeClean := !containsValue(probeOutput, marker)
	h.recordTier("agent-mcp-message-nondisclosure", tierSystem,
		"inspect every MCP request/response through delivered status and the independent probe", "MCP input/output and the probe contain no synthetic value",
		fmt.Sprintf("mcp_input_clean=%t mcp_output_clean=%t independent_probe_clean=%t", mcpInputClean, streamClean, probeClean), mcpInputClean && streamClean && probeClean)
	if dbBytes, readErr := os.ReadFile(filepath.Join(stateDir, "seqpass.db")); readErr == nil {
		walBytes, _ := os.ReadFile(filepath.Join(stateDir, "seqpass.db-wal"))
		dbClean := !containsValue(dbBytes, marker) && !containsValue(walBytes, marker)
		h.recordTier("broker-receipt-nondisclosure", tierSystem, "inspect durable SeqPass metadata and WAL after relay completion", "receipt and metadata omit the synthetic value", fmt.Sprintf("credential_absent=%t", dbClean), dbClean)
	} else {
		h.recordTier("broker-receipt-nondisclosure", tierSystem, "inspect durable SeqPass metadata and WAL after relay completion", "receipt and metadata omit the synthetic value", readErr.Error(), false)
	}
	_ = agentIn.Close()
	if err := agentCmd.Wait(); err != nil {
		h.recordTier("agent-mcp-clean-exit", tierSystem, "close the agent MCP process after the observation window", "process exits without error", err.Error(), false)
	} else {
		h.recordTier("agent-mcp-clean-exit", tierSystem, "close the agent MCP process after the observation window", "process exits without error", "clean exit", true)
	}
	agentStopped = true
	if containsValue(agentErr.Bytes(), marker) {
		h.recordTier("agent-mcp-stderr-nondisclosure", tierSystem, "inspect captured agent process stderr", "stderr omits the synthetic value", "credential found in stderr", false)
	} else {
		h.recordTier("agent-mcp-stderr-nondisclosure", tierSystem, "inspect captured agent process stderr", "stderr omits the synthetic value", "credential absent", true)
	}
	return marker
}

func identityEnvironment(u *user.User, extra map[string]string) []string {
	values := map[string]string{"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
	if u != nil {
		values["HOME"], values["USER"], values["LOGNAME"] = u.HomeDir, u.Username, u.Username
	}
	for k, v := range extra {
		values[k] = v
	}
	env := make([]string, 0, len(values))
	for k, v := range values {
		env = append(env, k+"="+v)
	}
	return env
}

func runCredentialedInput(t *testing.T, bin string, id privilegedIdentity, u *user.User, args []string, input []byte) ([]byte, error) {
	t.Helper()
	defer clear(input)
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(id)}
	cmd.Env = identityEnvironment(u, nil)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if _, err := stdin.Write(input); err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return stdout.Bytes(), err
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return stdout.Bytes(), err
	}
	if err := cmd.Wait(); err != nil {
		return stdout.Bytes(), fmt.Errorf("trusted helper exited: %w (%s)", err, trimOutput(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

func callTrustedIPC(t *testing.T, probeBin string, id privilegedIdentity, u *user.User, socket, method string, params map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	output, err := runCredentialedInput(t, probeBin, id, u, []string{"ipc", socket, method}, append(raw, '\n'))
	if err != nil {
		return nil, err
	}
	var response map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(output), &response); err != nil {
		return nil, err
	}
	if response["ok"] != true {
		return response, fmt.Errorf("trusted IPC request rejected")
	}
	return response, nil
}

func responseString(response map[string]interface{}, key string) string {
	data, _ := response["data"].(map[string]interface{})
	value, _ := data[key].(string)
	return value
}

func sendMCPCall(stdin io.Writer, reader *bufio.Reader, requestTrace, transcript *bytes.Buffer, id int, method string, params map[string]interface{}) (map[string]interface{}, error) {
	message, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	message = append(message, '\n')
	requestTrace.Write(message)
	if _, err := stdin.Write(message); err != nil {
		return nil, err
	}
	type result struct {
		line []byte
		err  error
	}
	read := make(chan result, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		read <- result{line: line, err: err}
	}()
	select {
	case got := <-read:
		if got.err != nil {
			return nil, got.err
		}
		transcript.Write(got.line)
		var reply map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(got.line), &reply); err != nil {
			return nil, err
		}
		return reply, nil
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("MCP response timed out")
	}
}

func writeMCPNotification(w io.Writer, method string) error {
	raw, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

func mcpToolText(reply map[string]interface{}) (string, error) {
	result, _ := reply["result"].(map[string]interface{})
	if result == nil || result["isError"] == true {
		return "", fmt.Errorf("MCP tool returned an error")
	}
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		return "", fmt.Errorf("MCP tool returned no content")
	}
	first, _ := content[0].(map[string]interface{})
	text, _ := first["text"].(string)
	if text == "" {
		return "", fmt.Errorf("MCP tool returned no text")
	}
	return text, nil
}

func processMemoryContains(pid int, needle []byte) (bool, error) {
	if len(needle) == 0 {
		return false, fmt.Errorf("empty memory-scan marker")
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false, err
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return false, err
	}
	defer mem.Close()
	buf := make([]byte, 64*1024)
	carry := make([]byte, 0, len(needle))
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[1], "r") {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, e1 := strconv.ParseUint(bounds[0], 16, 64)
		end, e2 := strconv.ParseUint(bounds[1], 16, 64)
		if e1 != nil || e2 != nil || end <= start {
			continue
		}
		carry = carry[:0]
		for address := start; address < end; {
			want := uint64(len(buf))
			if end-address < want {
				want = end - address
			}
			n, readErr := mem.ReadAt(buf[:int(want)], int64(address))
			if readErr != nil && n == 0 {
				return false, fmt.Errorf("read agent memory mapping: %w", readErr)
			}
			window := append(carry, buf[:n]...)
			if bytes.Contains(window, needle) {
				return true, nil
			}
			keep := len(needle) - 1
			if keep > len(window) {
				keep = len(window)
			}
			carry = append(carry[:0], window[len(window)-keep:]...)
			address += uint64(n)
			if readErr != nil && n < int(want) {
				return false, fmt.Errorf("read agent memory mapping: %w", readErr)
			}
		}
	}
	return false, nil
}

func resultText(err error) string {
	if err == nil {
		return "connected"
	}
	return err.Error()
}
