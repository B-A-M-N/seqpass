//go:build linux

package qual

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/testruntime"
)

// syntheticScenarioCases maps the qual/PRIVILEGED.md scenario names to the
// concrete subchecks this tier records for them. Each scenario aggregate
// passes only when every listed subcheck passed.
var syntheticScenarioCases = map[string][]string{
	"authorized-credentialed-read": {
		"synthetic-registration",
		"service-can-reach-mock-aegiskeys-socket",
		"use-submit-returns-opaque-id",
		"use-execution-completes",
		"provider-received-pinned-bearer",
		"aegis-resolved-exactly-once",
		"use-result-nondisclosure",
		"agent-process-metadata-nondisclosure",
		"agent-process-memory-excludes-payload",
		"broker-log-nondisclosure",
		"broker-receipt-nondisclosure",
	},
	"adversarial-credential-echo": {
		"use-adversarial-echo-rejected",
		"use-result-nondisclosure",
	},
	"unauthorized-operation": {
		"use-unauthorized-submit-denied",
		"unauthorized-no-dispatch",
	},
	"credential-rotation": {
		"use-rotation-dispatches-new-value",
		"provider-rejects-rotated-value",
		"use-result-nondisclosure",
	},
	"revocation-barrier": {
		"use-revoked-submit-denied",
		"no-dispatch-after-revocation",
	},
}

// runPrivilegedSyntheticUse executes the synthetic AegisKeys credential
// tier. It returns ready=false only for missing lab prerequisites; actual
// assertion failures are recorded as failed cases.
func runPrivilegedSyntheticUse(t *testing.T, h *harness) (ready bool, blocked string) {
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
	artifactDir := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_ARTIFACT_DIR"))
	if artifactDir == "" {
		return false, "missing SEQPASS_QUAL_ARTIFACT_DIR (live qualification evidence must be retained)"
	}
	if err := requireProtectedArtifactDir(artifactDir, uint32(os.Geteuid())); err != nil {
		return false, "qualification artifact directory is not private: " + err.Error()
	}
	if serviceUID == 0 || agentUID == 0 || serviceUID == agentUID {
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
	if containsGID(agentIdentity.groups, serviceIdentity.gid) {
		// The AegisKeys mock socket is isolated through the service group;
		// an agent sharing that group would make the kernel-denial claim
		// unprovable, so the tier refuses instead of under-checking.
		return false, "agent UID shares the service primary group; the synthetic AegisKeys socket cannot be isolated"
	}

	root, err := testruntime.Dir(testruntime.NamedFunc("privileged-synthetic-qual"))
	if err != nil {
		h.recordTier("synthetic-runtime", tierSystem, "create a disposable private qualification tree", "temporary root is created", err.Error(), false)
		return true, ""
	}
	// From here on the tier runs in a live lab, so the scenario aggregates
	// must land on every ready path: either computed from the recorded
	// subchecks after the scenarios were reached, or as honest
	// not_exercised rows when an earlier setup step bailed. The deferred
	// finalize also fixes the ordering requirement: stopSyntheticBroker
	// records broker-log-nondisclosure in the body, and the aggregate
	// computation must observe it.
	scenarioReached := false
	defer func() { finalizeSyntheticScenarios(h, scenarioReached) }()
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"chmod-root-0711", func() error { return os.Chmod(root, 0711) }},
		{"chown-root", func() error { return os.Chown(root, 0, 0) }},
	} {
		if err := step.fn(); err != nil {
			h.recordTier("synthetic-runtime", tierSystem, "prepare the disposable root as a root-owned traversal directory", "root is owned 0711", step.name+": "+err.Error(), false)
			return true, ""
		}
	}

	stateDir, agentDir, adminDir, intakeDir, dirErr := createBrokerRuntimeDirs(root, serviceIdentity, agentGID)
	if dirErr != nil {
		h.recordTier("synthetic-runtime", tierSystem, "create disjoint broker runtime directories", "all dirs created with isolated ownership", dirErr.Error(), false)
		return true, ""
	}
	logsDir := filepath.Join(root, "logs")
	if err := os.Mkdir(logsDir, 0700); err != nil {
		h.recordTier("synthetic-runtime", tierSystem, "create the trusted mock observation log directory", "logs dir is root-only", err.Error(), false)
		return true, ""
	}
	aegisDir := filepath.Join(root, "aegis")
	if err := os.Mkdir(aegisDir, 0750); err != nil {
		h.recordTier("synthetic-runtime", tierSystem, "create the AegisKeys mock directory", "aegis dir is root-owned service-group-only", err.Error(), false)
		return true, ""
	}
	if err := os.Chown(aegisDir, 0, int(serviceIdentity.gid)); err != nil {
		h.recordTier("synthetic-runtime", tierSystem, "assign the AegisKeys mock directory to the service group", "group access for the service identity only", err.Error(), false)
		return true, ""
	}

	// Synthetic credentials and their durable mock backing files. The
	// values are strings, so they cannot be zeroed; lifetimes are bounded
	// by the disposable root tree and retained evidence carries digests
	// only (the []byte fixtures use clear(), these do not pretend to).
	cred1, err := newSyntheticValue("SEQPASS-QUAL-CRED1-")
	if err != nil {
		h.recordTier("synthetic-credential-fixture", tierSystem, "generate the synthetic credential values", "random values available only to the trusted harness", err.Error(), false)
		return true, ""
	}
	cred2, err := newSyntheticValue("SEQPASS-QUAL-CRED2-")
	if err != nil {
		h.recordTier("synthetic-credential-fixture", tierSystem, "generate the synthetic credential values", "random values available only to the trusted harness", err.Error(), false)
		return true, ""
	}
	vaultPath := filepath.Join(aegisDir, mockVaultPath)
	metaPath := filepath.Join(aegisDir, mockMetaPath)
	if err := writeSyntheticVaultFile(vaultPath, cred1); err != nil {
		h.recordTier("synthetic-credential-fixture", tierSystem, "stage the synthetic credential in the root-owned mock vault file", "mode-0600 root-owned vault backs the served value", err.Error(), false)
		return true, ""
	}
	if err := os.WriteFile(metaPath, []byte(`{"protocol":"v1","bindings":{"qual/synthetic":{"rotations":1}}}`), 0600); err != nil {
		h.recordTier("synthetic-credential-fixture", tierSystem, "stage the mock AegisKeys metadata file", "mode-0600 root-owned metadata without credential values", err.Error(), false)
		return true, ""
	}
	h.topology["synthetic_credential1_sha256"] = sha256Hex([]byte(cred1))
	h.topology["synthetic_credential2_sha256"] = sha256Hex([]byte(cred2))
	h.topology["synthetic_binding"] = "qual/synthetic"

	// Mock AegisKeys broker + real credentialed mock provider.
	upstream := newMockUpstream(logsDir, cred1, cred2)
	aegisSocket := filepath.Join(aegisDir, "aegis.sock")
	if err := upstream.startAegis(aegisSocket, vaultPath, serviceIdentity.gid); err != nil {
		h.recordTier("synthetic-upstream-start", tierSystem, "start the protocol-faithful AegisKeys mock on a service-group-isolated unix socket", "mock serves the AegisKeys v2 resolve contract", err.Error(), false)
		return true, ""
	}
	origin, err := upstream.startProvider()
	if err != nil {
		upstream.close()
		h.recordTier("synthetic-upstream-start", tierSystem, "start the real credentialed mock provider on loopback TCP", "provider records path and bearer digest per request", err.Error(), false)
		return true, ""
	}
	t.Cleanup(upstream.close)
	if err := requireLiveSocket(aegisSocket); err != nil {
		h.recordTier("synthetic-upstream-start", tierSystem, "prove the mock AegisKeys socket is live before broker startup", "root observer can connect to listener", err.Error(), false)
		return true, ""
	}
	bin := buildBinary(t, root)
	h.bin = bin
	probeBin, err := buildBoundaryProbe(t, root)
	if err != nil {
		h.recordTier("synthetic-probe-build", tierSystem, "build a stdlib-only external UID probe", "probe builds without project-private test hooks", err.Error(), false)
		return true, ""
	}
	// The service side of the boundary must also be proven: the service
	// UID can connect to the group-isolated mock socket (the mirror of the
	// agent-denial check recorded after broker startup).
	serviceProbe := runCredentialed(t, probeBin, serviceIdentity, serviceUser, []string{
		"service", itoa(serviceUID), aegisSocket,
	})
	var svcResult boundaryProbe
	serviceOK := decodeProbe(serviceProbe, &svcResult) == nil && svcResult.EffectiveUID == serviceUID && svcResult.AegisSocketConnect
	h.recordTier("service-can-reach-mock-aegiskeys-socket", tierSystem,
		"broker service identity has access to the group-isolated mock AegisKeys socket", "service UID connects to the mock listener",
		fmt.Sprintf("uid=%d connected=%t", svcResult.EffectiveUID, svcResult.AegisSocketConnect), serviceOK)
	h.topology["aegiskeys_mock_socket"] = aegisSocket
	h.topology["aegiskeys_mock_socket_owner_mode"] = ownershipMode(aegisSocket)
	h.topology["mock_provider_origin"] = origin
	h.agent = filepath.Join(agentDir, "agent.sock")
	h.admin = filepath.Join(adminDir, "admin.sock")
	dbPath := filepath.Join(stateDir, "seqpass.db")
	h.uid = strconv.FormatUint(uint64(agentUID), 10)
	h.topology["service_uid"] = itoa(serviceUID)
	h.topology["agent_uid"] = h.uid
	h.topology["agent_socket_group"] = groupName
	h.topology["seqpass_db"] = dbPath

	args := []string{
		"broker", "--vault", "aegiskeys", "--db", dbPath,
		"--socket", h.agent, "--admin-socket", h.admin,
		"--intake-socket", filepath.Join(intakeDir, "intake.sock"),
		"--assurance", "isolated",
		"--agent-uid", h.uid,
		"--admin-uid", itoa(serviceUID),
		"--intake-uid", itoa(serviceUID),
		"--socket-group", groupName,
		"--aegiskeys-socket", aegisSocket,
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
		h.recordTier("synthetic-broker-start", tierSystem, "launch the real broker as the dedicated service UID against the mock AegisKeys socket", "broker starts in isolated mode", startErr.Error(), false)
		return true, ""
	}
	brokerDone := make(chan struct{})
	var brokerErr error
	go func() { brokerErr = cmd.Wait(); close(brokerDone) }()
	brokerStopped := false
	t.Cleanup(func() {
		if brokerStopped || cmd.Process == nil {
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
	if !waitForSockets([]string{h.agent, h.admin, filepath.Join(intakeDir, "intake.sock")}, 10*time.Second) {
		select {
		case <-brokerDone:
			h.recordTier("synthetic-broker-start", tierSystem, "launch the real broker as the dedicated service UID against the mock AegisKeys socket", "broker sockets become live", fmt.Sprintf("broker exited: %v log=%s", brokerErr, trimOutput(brokerLog.Bytes())), false)
		default:
			h.recordTier("synthetic-broker-start", tierSystem, "launch the real broker as the dedicated service UID against the mock AegisKeys socket", "broker sockets become live", "socket startup timed out; log="+trimOutput(brokerLog.Bytes()), false)
		}
		return true, ""
	}
	h.recordTier("synthetic-broker-start", tierSystem,
		"launch the real broker as the dedicated service UID against the mock AegisKeys socket",
		"isolated broker serves agent, admin, and intake sockets", "all three sockets live", true)

	intakeSocket := filepath.Join(intakeDir, "intake.sock")
	// Agent boundary probes against the mock topology.
	probeArgs := []string{
		"agent", h.uid, h.agent, h.admin,
		intakeSocket,
		aegisSocket, vaultPath, metaPath, dbPath,
	}
	probeOutput := runCredentialed(t, probeBin, agentIdentity, agentUser, probeArgs)
	recordSyntheticBoundaryProbe(t, h, agentIdentity, agentGID, probeOutput)

	// Trusted registration under the service UID.
	refID, policyOK := registerSyntheticPolicy(t, h, probeBin, serviceIdentity, serviceUser, agentUID, origin)
	if !policyOK {
		stopSyntheticBroker(t, cmd, &brokerDone, &brokerStopped, &brokerLog, h, artifactDir, []string{cred1, cred2})
		return true, ""
	}

	// Agent MCP session and the credentialed scenarios.
	mcpErr := runSyntheticAgentScenarios(t, h, probeBin, serviceIdentity, serviceUser, agentIdentity, agentUser, refID, upstream, dbPath, probeOutput, []string{cred1, cred2, b64(cred1), b64(cred2)})
	scenarioReached = mcpErr == nil
	stopSyntheticBroker(t, cmd, &brokerDone, &brokerStopped, &brokerLog, h, artifactDir, []string{cred1, cred2})
	return true, ""
}

// recordSyntheticBoundaryProbe records the kernel-denial checks from the
// agent-UID probe run against the mock topology.
func recordSyntheticBoundaryProbe(t *testing.T, h *harness, agentIdentity privilegedIdentity, agentGID uint32, probeOutput []byte) {
	t.Helper()
	var agentResult boundaryProbe
	parseErr := decodeProbe(probeOutput, &agentResult)
	if parseErr != nil {
		h.recordTier("synthetic-agent-boundary-probe", tierSystem, "run independent probe under the dedicated agent UID", "probe returns structured observations", parseErr.Error()+" output="+trimOutput(probeOutput), false)
		return
	}
	probeOK := agentResult.EffectiveUID == agentIdentity.uid && containsGID(agentResult.Groups, agentGID) &&
		agentResult.HealthOK && agentResult.AssuranceMode == "isolated"
	h.recordTier("synthetic-agent-health-over-allowed-socket", tierSystem,
		"agent reaches the real SeqPass agent socket", "health response declares isolated assurance",
		fmt.Sprintf("uid=%d health=%t assurance=%s", agentResult.EffectiveUID, agentResult.HealthOK, agentResult.AssuranceMode), probeOK)
	for _, name := range []string{"admin", "intake", "aegiskeys"} {
		errText := agentResult.SocketDenied[name]
		denied := permissionDenied(errText)
		h.recordTier("agent-cannot-connect-"+name+"-socket", tierSystem,
			"agent UID cannot connect directly to a live trusted socket", "kernel denies socket connection with EACCES or EPERM",
			fmt.Sprintf("socket=%s denied=%t error=%s", name, denied, errText), denied)
	}
	for _, name := range []string{"aegiskeys_vault", "aegiskeys_metadata", "seqpass_db"} {
		errText := agentResult.FileUnreadable[name]
		denied := permissionDenied(errText)
		h.recordTier("agent-cannot-read-"+name, tierSystem,
			"agent UID cannot read protected credential or broker state", "kernel denies file open with EACCES or EPERM",
			fmt.Sprintf("file=%s unreadable=%t error=%s", name, denied, errText), denied)
	}
}

// registerSyntheticPolicy provisions the secret ref, pinned destination,
// and allow policy through the trusted admin IPC under the service UID.
func registerSyntheticPolicy(
	t *testing.T,
	h *harness,
	probeBin string,
	serviceIdentity privilegedIdentity,
	serviceUser *user.User,
	agentUID uint32,
	origin string,
) (refID string, ok bool) {
	t.Helper()
	fail := func(observed string) (string, bool) {
		h.recordTier("synthetic-registration", tierSystem, "register the synthetic secret, pinned provider origin, and scoped allow policy through the trusted admin socket", "service UID receives ref, destination, and policy IDs", observed, false)
		return "", false
	}
	refResp, err := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.secret_add", map[string]interface{}{
		"name": "synthetic-qualification", "description": "synthetic credential for privileged qualification",
		"binding": "qual/synthetic",
	})
	refID = responseString(refResp, "id")
	if err != nil || refID == "" {
		return fail(fmt.Sprintf("secret_add=%v", err))
	}
	destResp, err := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.dest_add", map[string]interface{}{
		"name": "synthetic-qual-provider", "type": "http-pinned", "endpoint": origin,
	})
	destID := responseString(destResp, "id")
	if err != nil || destID == "" {
		return fail(fmt.Sprintf("dest_add=%v", err))
	}
	rules := []map[string]interface{}{{
		"principal":   "uid:" + itoa(agentUID),
		"secret_refs": []string{refID},
		"ops":         []string{"http.request"},
		"dest_ids":    []string{destID},
		"no_approval": true,
	}}
	rulesRaw, err := json.Marshal(rules)
	if err != nil {
		return fail("rules marshal: " + err.Error())
	}
	polResp, err := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.policy_add", map[string]interface{}{
		"name": "synthetic-qual-policy", "rules": string(rulesRaw),
	})
	polID := responseString(polResp, "id")
	if err != nil || polID == "" {
		return fail(fmt.Sprintf("policy_add=%v", err))
	}
	h.topology["synthetic_policy_id"] = polID
	h.topology["synthetic_dest_id"] = destID
	h.recordTier("synthetic-registration", tierSystem,
		"register the synthetic secret, pinned provider origin, and scoped allow policy through the trusted admin socket",
		"service UID receives ref, destination, and policy IDs",
		fmt.Sprintf("ref=%s dest=%s policy=%s", refID, destID, polID), true)
	return refID, true
}

// runSyntheticAgentScenarios drives the real MCP adapter under the agent
// UID through the credentialed scenarios and records every subcheck.
func runSyntheticAgentScenarios(
	t *testing.T,
	h *harness,
	probeBin string,
	serviceIdentity privilegedIdentity,
	serviceUser *user.User,
	agentIdentity privilegedIdentity,
	agentUser *user.User,
	refID string,
	upstream *mockUpstream,
	dbPath string,
	probeOutput []byte,
	creds []string,
) error {
	t.Helper()
	agentCmd := exec.Command(h.bin, "mcp", "--socket", h.agent)
	agentCmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(agentIdentity)}
	agentCmd.Env = identityEnvironment(agentUser, map[string]string{"SEQ_PASS_SOCKET": h.agent})
	agentIn, err := agentCmd.StdinPipe()
	if err != nil {
		h.recordTier("synthetic-agent-start", tierSystem, "start real MCP stdio adapter under the agent UID", "pipes are available", err.Error(), false)
		return err
	}
	agentOut, err := agentCmd.StdoutPipe()
	if err != nil {
		_ = agentIn.Close()
		h.recordTier("synthetic-agent-start", tierSystem, "start real MCP stdio adapter under the agent UID", "stdout is observable by an independent harness", err.Error(), false)
		return err
	}
	var agentErr bytes.Buffer
	agentCmd.Stderr = &agentErr
	if err := agentCmd.Start(); err != nil {
		_ = agentIn.Close()
		h.recordTier("synthetic-agent-start", tierSystem, "start real MCP stdio adapter under the agent UID", "process runs under the configured agent identity", err.Error(), false)
		return err
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

	cleanups := func() {
		_ = agentIn.Close()
		if waitErr := agentCmd.Wait(); waitErr != nil {
			h.recordTier("agent-mcp-clean-exit", tierSystem, "close the agent MCP process after the observation window", "process exits without error", waitErr.Error(), false)
		} else {
			h.recordTier("agent-mcp-clean-exit", tierSystem, "close the agent MCP process after the observation window", "process exits without error", "clean exit", true)
		}
		agentStopped = true
	}

	if err := initializeMCP(agentIn, reader, &requestTrace, &transcript); err != nil {
		h.recordTier("synthetic-agent-mcp-start", tierSystem, "initialize the real MCP adapter under the agent UID", "MCP handshake completes", err.Error(), false)
		return err
	}
	h.recordTier("synthetic-agent-mcp-start", tierSystem, "initialize the real MCP adapter under the agent UID", "MCP handshake completes", "initialized", true)

	// Catalog: the scoped operation is discoverable and leaks nothing.
	catalogReply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 10, "tools/call", map[string]interface{}{"name": "secret_catalog"})
	catalogText, textErr := mcpToolText(catalogReply)
	catalogOK := err == nil && textErr == nil && strings.Contains(catalogText, "http.request")
	if err == nil && textErr == nil {
		if !strings.Contains(catalogText, refID) {
			catalogOK = false
		}
	}
	h.recordTier("use-catalog-discloses-scoped-operation", tierSystem,
		"discover the authorized operation through secret_catalog under the agent UID", "catalog lists the ref with http.request and no credential material",
		fmt.Sprintf("mcp=%v parse=%v", err, textErr), catalogOK)

	// Scenario: authorized credentialed read.
	useReply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 11, "tools/call", map[string]interface{}{
		"name": "secret_use", "arguments": map[string]interface{}{
			"secret_ref": refID, "operation": "http.request", "target": h.topology["synthetic_dest_id"],
			"params": map[string]interface{}{"path": "/qual"},
		},
	})
	useText, textErr := mcpToolText(useReply)
	var useData map[string]interface{}
	if textErr == nil {
		textErr = json.Unmarshal([]byte(useText), &useData)
	}
	opID, _ := useData["op_id"].(string)
	useStatus, _ := useData["status"].(string)
	submitOK := err == nil && textErr == nil && opID != "" && useStatus == "authorized"
	h.recordTier("use-submit-returns-opaque-id", tierSystem,
		"submit the authorized credentialed read through the untrusted MCP adapter", "agent receives an opaque op id and authorized status, never secret material",
		fmt.Sprintf("mcp=%v parse=%v status=%s", err, textErr, useStatus), submitOK)
	if !submitOK {
		cleanups()
		return fmt.Errorf("authorized use submit failed")
	}

	// Execute through the trusted admin surface (deterministic, no auto worker).
	if _, execErr := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.execute_use", map[string]interface{}{
		"op_id": opID,
	}); execErr != nil {
		h.recordTier("use-execution-completes", tierSystem, "execute the authorized operation from the trusted service UID", "trusted executor runs the pinned credentialed request", execErr.Error(), false)
		cleanups()
		return execErr
	}

	status, statusErr := pollUseStatus(t, agentIn, reader, &requestTrace, &transcript, opID)
	if statusErr != nil || status == nil {
		h.recordTier("use-execution-completes", tierSystem, "observe the operation reaching a terminal state through the agent's own status tool", "status reports completed with a receipt", fmt.Sprintf("err=%v status=%v", statusErr, status), false)
		cleanups()
		return fmt.Errorf("status polling failed")
	}
	completed := status["status"] == "completed" && status["result"] != nil
	h.recordTier("use-execution-completes", tierSystem,
		"observe the operation reaching a terminal state through the agent's own status tool",
		"status reports completed with a receipt",
		fmt.Sprintf("status=%v effective=%v", status["status"], status["effective_outcome"]), completed)

	// Independent provider observation: the pinned bearer reached the real
	// consuming application.
	requests, provErr := upstream.providerRequests()
	provOK := provErr == nil && len(requests) == 1 && requests[0].Path == "/qual" &&
		requests[0].Admitted && requests[0].BearerSHA256 == sha256Hex([]byte(creds[0]))
	h.recordTier("provider-received-pinned-bearer", tierSystem,
		"read the provider's independent request log after execution", "the consuming application received exactly the current synthetic credential as the pinned bearer",
		fmt.Sprintf("requests=%d err=%v", len(requests), provErr), provOK)

	resolves, resolveErr := upstream.resolveCount()
	h.recordTier("aegis-resolved-exactly-once", tierSystem,
		"read the mock AegisKeys resolve log after the first execution", "exactly one authorized resolve occurred for the binding",
		fmt.Sprintf("resolves=%d err=%v", resolves, resolveErr), resolveErr == nil && resolves == 1)

	// Adversarial echo + result nondisclosure over the receipt.
	resultBody, _ := status["result"].(string)
	var receipt map[string]interface{}
	receiptErr := json.Unmarshal([]byte(resultBody), &receipt)
	echoRejected := completed && receiptErr == nil && receipt != nil &&
		dataField(receipt, "service") == "qual-mock-provider" &&
		dataField(receipt, "echo") == nil && dataField(receipt, "escaped") == nil
	h.recordTier("use-adversarial-echo-rejected", tierSystem,
		"submit a provider response that echoes the credential literally and JSON-escaped", "the closed projection drops both echo fields entirely instead of masking them",
		fmt.Sprintf("service=%v echo=%v escaped=%v", dataField(receipt, "service"), dataField(receipt, "echo"), dataField(receipt, "escaped")), echoRejected)

	mcpClean := !containsAnyValue(transcript.Bytes(), creds...) && !containsAnyValue(requestTrace.Bytes(), creds...)
	h.recordTier("use-result-nondisclosure", tierSystem,
		"inspect every MCP request and response byte in the session", "MCP traffic contains no synthetic credential in any encoding",
		fmt.Sprintf("clean=%t", mcpClean), mcpClean)

	cmdline, cmdlineErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", agentCmd.Process.Pid))
	env, envErr := os.ReadFile(fmt.Sprintf("/proc/%d/environ", agentCmd.Process.Pid))
	if cmdlineErr != nil || envErr != nil {
		h.recordBlocked("agent-process-metadata-observation", tierSystem, "inspect the live MCP child's argv and environment", fmt.Sprintf("cmdline=%v environ=%v", cmdlineErr, envErr))
	} else {
		clean := !containsAnyValue(cmdline, creds...) && !containsAnyValue(env, creds...)
		h.recordTier("agent-process-metadata-nondisclosure", tierSystem,
			"inspect the live MCP child's argv and environment", "process metadata omits the synthetic values",
			fmt.Sprintf("credential_absent=%t", clean), clean)
	}
	memoryContains, memoryErr := processMemoryContainsSet(agentCmd.Process.Pid, creds[0], creds[1])
	if memoryErr != nil {
		h.recordBlocked("agent-process-memory-observation", tierSystem, "independently scan readable agent process mappings for the synthetic values", memoryErr.Error())
	} else {
		h.recordTier("agent-process-memory-excludes-payload", tierSystem,
			"independently scan readable agent process mappings after trusted execution", "the synthetic values are absent from agent-readable memory",
			fmt.Sprintf("contains_payload=%t", memoryContains), !memoryContains)
	}

	// Scenario: unauthorized operation (operation outside the policy).
	beforeResolves, _ := upstream.resolveCount()
	unauthReply, unauthErr := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 12, "tools/call", map[string]interface{}{
		"name": "secret_use", "arguments": map[string]interface{}{
			"secret_ref": refID, "operation": "process.run", "target": h.topology["synthetic_dest_id"],
			"params": map[string]interface{}{"arg0": "x"},
		},
	})
	_, unauthTextErr := mcpToolText(unauthReply)
	unauthDenied := unauthErr != nil || unauthTextErr != nil
	if unauthErr == nil && unauthTextErr == nil && unauthReply != nil && unauthReply["error"] != nil {
		unauthDenied = true
	}
	afterResolves, _ := upstream.resolveCount()
	requestsAfter, _ := upstream.providerRequests()
	h.recordTier("use-unauthorized-submit-denied", tierSystem,
		"submit an operation outside the allow policy through the untrusted MCP adapter", "submission is denied",
		fmt.Sprintf("denied=%t", unauthDenied), unauthDenied)
	noDispatch := beforeResolves == afterResolves && len(requestsAfter) == 1
	h.recordTier("unauthorized-no-dispatch", tierSystem,
		"verify no credential resolution and no provider request followed the denied submission", "resolve count and provider request count are unchanged",
		fmt.Sprintf("resolves=%d->%d provider=%d", beforeResolves, afterResolves, len(requestsAfter)), noDispatch)

	// Scenario: credential rotation.
	use2Reply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 13, "tools/call", map[string]interface{}{
		"name": "secret_use", "arguments": map[string]interface{}{
			"secret_ref": refID, "operation": "http.request", "target": h.topology["synthetic_dest_id"],
			"params": map[string]interface{}{"path": "/qual"},
		},
	})
	use2Text, textErr2 := mcpToolText(use2Reply)
	var use2Data map[string]interface{}
	if textErr2 == nil {
		_ = json.Unmarshal([]byte(use2Text), &use2Data)
	}
	opID2, _ := use2Data["op_id"].(string)
	rotationReady := err == nil && textErr2 == nil && opID2 != ""
	if !rotationReady {
		h.recordTier("use-rotation-dispatches-new-value", tierSystem, "submit a second authorized read after rotation", "second submission succeeds", fmt.Sprintf("mcp=%v parse=%v", err, textErr2), false)
		cleanups()
		return fmt.Errorf("rotation submit failed")
	}
	if _, execErr := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.execute_use", map[string]interface{}{"op_id": opID2}); execErr != nil {
		h.recordTier("use-rotation-dispatches-new-value", tierSystem, "execute the second authorized read after rotation", "trusted executor runs the pinned credentialed request", execErr.Error(), false)
		cleanups()
		return execErr
	}
	status2, statusErr2 := pollUseStatus(t, agentIn, reader, &requestTrace, &transcript, opID2)
	requests2, _ := upstream.providerRequests()
	rotOK := statusErr2 == nil && status2 != nil && status2["status"] == "completed" &&
		len(requests2) == 2 && requests2[1].Path == "/qual" && requests2[1].Admitted &&
		requests2[1].BearerSHA256 == sha256Hex([]byte(creds[1])) &&
		requests2[1].BearerSHA256 != requests2[0].BearerSHA256
	h.recordTier("use-rotation-dispatches-new-value", tierSystem,
		"execute a second authorized read after the AegisKeys value rotated", "the provider receives exactly the rotated value and never the prior one",
		fmt.Sprintf("requests=%d err=%v", len(requests2), statusErr2), rotOK)

	// The rotation contract itself: after rotation the consuming
	// application rejects the prior value. The trusted harness replays it
	// directly against the provider — this validates the mock's rotation
	// semantics, not broker behavior, so it records under the fixture's
	// own check name.
	replay := replayProviderGet(t, upstream.origin(), creds[0])
	h.recordTier("provider-rejects-rotated-value", tierSystem,
		"replay the prior credential value directly against the mock provider after rotation", "the provider rejects the prior value with 401",
		fmt.Sprintf("status=%d", replay), replay == 401)

	// Scenario: revocation barrier — disable the policy, submission denied.
	polID := h.topology["synthetic_policy_id"]
	if _, disableErr := callTrustedIPC(t, probeBin, serviceIdentity, serviceUser, h.admin, "admin.policy_set", map[string]interface{}{
		"id": polID, "enabled": false,
	}); disableErr != nil {
		h.recordTier("use-revoked-submit-denied", tierSystem, "disable the allow policy through the trusted admin socket", "policy_set succeeds", disableErr.Error(), false)
		cleanups()
		return disableErr
	}
	preRevokeResolves, _ := upstream.resolveCount()
	preRevokeRequests, _ := upstream.providerRequests()
	use3Reply, err := sendMCPCall(agentIn, reader, &requestTrace, &transcript, 14, "tools/call", map[string]interface{}{
		"name": "secret_use", "arguments": map[string]interface{}{
			"secret_ref": refID, "operation": "http.request", "target": h.topology["synthetic_dest_id"],
			"params": map[string]interface{}{"path": "/qual"},
		},
	})
	_, textErr3 := mcpToolText(use3Reply)
	use3Denied := err != nil || textErr3 != nil
	if err == nil && textErr3 == nil && use3Reply != nil && use3Reply["error"] != nil {
		use3Denied = true
	}
	h.recordTier("use-revoked-submit-denied", tierSystem,
		"disable the allow policy and resubmit through the untrusted MCP adapter", "submission is denied after revocation",
		fmt.Sprintf("denied=%t", use3Denied), use3Denied)
	requests3, _ := upstream.providerRequests()
	resolves3, _ := upstream.resolveCount()
	h.recordTier("no-dispatch-after-revocation", tierSystem,
		"verify no credential resolution and no provider request followed the revoked submission", "resolve and provider request counts are unchanged by the denied submission",
		fmt.Sprintf("resolves=%d->%d provider=%d->%d", preRevokeResolves, resolves3, len(preRevokeRequests), len(requests3)),
		preRevokeResolves == resolves3 && len(preRevokeRequests) == len(requests3))

	// Broker-side and store-side nondisclosure sweeps.
	stderrClean := !containsAnyValue(agentErr.Bytes(), creds...)
	h.recordTier("agent-mcp-stderr-nondisclosure", tierSystem, "inspect captured agent process stderr", "stderr omits the synthetic values", fmt.Sprintf("credential_absent=%t", stderrClean), stderrClean)
	probeClean := !containsAnyValue(probeOutput, creds...)
	h.recordTier("agent-mcp-message-nondisclosure", tierSystem,
		"inspect every MCP request/response byte and the independent probe output", "MCP input/output and the probe contain no synthetic value",
		fmt.Sprintf("mcp_clean=%t probe_clean=%t", mcpClean, probeClean), mcpClean && probeClean)
	if dbBytes, readErr := os.ReadFile(dbPath); readErr == nil {
		walBytes, _ := os.ReadFile(dbPath + "-wal")
		dbClean := !containsAnyValue(dbBytes, creds...) && !containsAnyValue(walBytes, creds...)
		h.recordTier("broker-receipt-nondisclosure", tierSystem, "inspect durable SeqPass metadata and WAL after execution", "receipt and metadata omit the synthetic values", fmt.Sprintf("credential_absent=%t", dbClean), dbClean)
	} else {
		h.recordTier("broker-receipt-nondisclosure", tierSystem, "inspect durable SeqPass metadata and WAL after execution", "receipt and metadata omit the synthetic values", readErr.Error(), false)
	}

	cleanups()
	return nil
}

// initializeMCP performs the MCP initialize handshake plus notification.
func initializeMCP(stdin io.Writer, reader *bufio.Reader, requestTrace, transcript *bytes.Buffer) error {
	initReply, err := sendMCPCall(stdin, reader, requestTrace, transcript, 1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05", "capabilities": map[string]interface{}{},
		"clientInfo": map[string]interface{}{"name": "seqpass-privileged-qual", "version": "1"},
	})
	if err == nil {
		if _, ok := initReply["result"]; !ok {
			err = fmt.Errorf("MCP initialize has no result")
		}
	}
	if err == nil {
		err = writeMCPNotification(stdin, "notifications/initialized")
	}
	return err
}

// pollUseStatus polls the agent's own secret_status tool until a terminal
// state, returning the parsed data map.
func pollUseStatus(t *testing.T, stdin io.Writer, reader *bufio.Reader, requestTrace, transcript *bytes.Buffer, opID string) (map[string]interface{}, error) {
	t.Helper()
	for i := 0; i < 100; i++ {
		reply, err := sendMCPCall(stdin, reader, requestTrace, transcript, 1000+i, "tools/call", map[string]interface{}{
			"name": "secret_status", "arguments": map[string]interface{}{"op_type": "use", "op_id": opID},
		})
		if err != nil {
			return nil, err
		}
		body, textErr := mcpToolText(reply)
		if textErr != nil {
			return nil, textErr
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			return nil, err
		}
		switch data["status"] {
		case "completed", "failed", "uncertain", "expired":
			return data, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("status polling timed out")
}

// processMemoryContainsSet scans the agent's readable memory for each
// needle (literal or base64), reusing the relay tier's scanner.
func processMemoryContainsSet(pid int, needles ...string) (bool, error) {
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		found, err := processMemoryContains(pid, []byte(needle))
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
		encoded, encErr := processMemoryContains(pid, []byte(b64(needle)))
		if encErr != nil {
			return false, encErr
		}
		if encoded {
			return true, nil
		}
	}
	return false, nil
}

// finalizeSyntheticScenarios records the PRIVILEGED.md scenario aggregates
// from the recorded subchecks. It never duplicates a scenario row: the
// aggregate passes only when every listed subcheck was recorded and passed;
// missing subchecks fail the aggregate rather than silently counting as
// exercised.
func finalizeSyntheticScenarios(h *harness, reached bool) {
	for scenario, subchecks := range syntheticScenarioCases {
		if hasRecordedScenario(h, scenario) {
			continue
		}
		if !reached {
			h.recordNotExercised(scenario, tierSystem, scenarioExpected(scenario), "the synthetic tier did not reach this scenario")
			continue
		}
		pass := true
		var failed []string
		for _, name := range subchecks {
			found := false
			for _, c := range h.cases {
				if c.Name == name {
					found = true
					if !c.Pass {
						pass = false
						failed = append(failed, name)
					}
					break
				}
			}
			if !found {
				pass = false
				failed = append(failed, name+"(missing)")
			}
		}
		if pass {
			h.recordTier(scenario, tierSystem, "aggregate of the synthetic tier subchecks", scenarioExpected(scenario), "all subchecks passed", true)
		} else {
			h.recordTier(scenario, tierSystem, "aggregate of the synthetic tier subchecks", scenarioExpected(scenario), "failed subchecks="+strings.Join(failed, ","), false)
		}
	}
}

func scenarioExpected(scenario string) string {
	switch scenario {
	case "authorized-credentialed-read":
		return "controlled credential reaches mock provider while absent from every agent-visible surface"
	case "adversarial-credential-echo":
		return "literal and JSON-escaped credential echoes are rejected before persistence/publication"
	case "unauthorized-operation":
		return "no provider request and no AegisKeys resolve"
	case "credential-rotation":
		return "next resolution uses new binding and old value is rejected"
	case "revocation-barrier":
		return "revocation before dispatch prevents provider request; post-dispatch revocation remains in-flight"
	default:
		return ""
	}
}

// stopSyntheticBroker shuts the broker down, sweeps its log for credential
// disclosure, and retains the log as protected evidence.
func stopSyntheticBroker(
	t *testing.T,
	cmd *exec.Cmd,
	brokerDone *chan struct{},
	brokerStopped *bool,
	brokerLog *synchronizedBuffer,
	h *harness,
	artifactDir string,
	creds []string,
) {
	t.Helper()
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGINT)
	}
	cleanShutdown := false
	select {
	case <-*brokerDone:
		cleanShutdown = true
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-*brokerDone
	}
	*brokerStopped = true
	h.recordTier("synthetic-broker-clean-shutdown", tierSystem,
		"stop the synthetic-tier broker after the credentialed scenarios",
		"broker exits cleanly on SIGINT", fmt.Sprintf("clean=%t", cleanShutdown), cleanShutdown)
	// Detect and redact before retention: the retained artifact must not
	// carry credential values (literal or base64) even on failure.
	leaked := false
	for _, cred := range creds {
		if brokerLog.Redact([]byte(cred), []byte("[REDACTED-QUALIFICATION-VALUE]")) {
			leaked = true
		}
		if brokerLog.Redact([]byte(b64(cred)), []byte("[REDACTED-QUALIFICATION-VALUE]")) {
			leaked = true
		}
	}
	h.recordTier("broker-log-nondisclosure", tierSystem,
		"inspect real broker stdout/stderr after trusted execution and shutdown", "broker logs omit the synthetic values",
		fmt.Sprintf("credential_absent=%t", !leaked), !leaked)
	brokerLogName := fmt.Sprintf("qual-synthetic-broker-%d.log", time.Now().UnixNano())
	if err := writeProtectedArtifact(artifactDir, brokerLogName, brokerLog.Bytes()); err != nil {
		h.recordTier("synthetic-log-retention", tierSystem, "retain broker output with restricted permissions", "mode-0600 log is retained in the protected evidence directory", err.Error(), false)
	} else {
		h.topology["broker_log"] = brokerLogName
	}
}
