//go:build linux

package qual

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
)

// TestQualPrivilegedCapsuleBoundary qualifies the agent-courier boundary with
// three distinct OS identities and homes created inside a disposable container.
// It never changes ownership or permissions on an existing user home.
func TestQualPrivilegedCapsuleBoundary(t *testing.T) {
	if os.Getenv("SEQPASS_QUAL_CAPSULE") != "1" {
		t.Skip("set SEQPASS_QUAL_CAPSULE=1 in a disposable Linux multi-UID environment")
	}
	h := &harness{t: t, dir: t.TempDir(), uid: "capsule-boundary", topology: map[string]string{}}
	defer func() {
		if t.Failed() {
			h.cases = append(h.cases, caseResult{Name: "capsule-qualification-run", Tier: tierSystem, Intent: "complete the three-identity sealed-capsule qualification", Expected: "test exits successfully", Observed: "test failed before every qualification case completed", Status: "failed"})
		}
		writeManifest(t, h, "sealed-capsule-synthetic")
	}()
	if os.Geteuid() != 0 {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "issuer, courier, and recipient execute as distinct OS identities", "test needs root to launch configured UIDs")
		t.Skip("capsule boundary qualification needs root")
	}
	artifactDir := strings.TrimSpace(os.Getenv("SEQPASS_QUAL_ARTIFACT_DIR"))
	if artifactDir == "" {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "retain protected evidence for the exact three-UID run", "missing SEQPASS_QUAL_ARTIFACT_DIR")
		t.Skip("capsule boundary qualification requires retained evidence")
	}
	if err := requireProtectedArtifactDir(artifactDir, uint32(os.Geteuid())); err != nil {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "retain protected evidence for the exact three-UID run", err.Error())
		t.Skip("capsule boundary evidence directory is not private")
	}
	serviceUID, serviceUser, serviceIdentity := capsuleIdentity(t, "SEQPASS_QUAL_SERVICE_UID", h)
	agentUID, agentUser, agentIdentity := capsuleIdentity(t, "SEQPASS_QUAL_AGENT_UID", h)
	recipientUID, recipientUser, recipientIdentity := capsuleIdentity(t, "SEQPASS_QUAL_RECIPIENT_UID", h)
	if serviceUID == 0 || agentUID == 0 || recipientUID == 0 || serviceUID == agentUID || serviceUID == recipientUID || agentUID == recipientUID {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "issuer, courier, and recipient execute as distinct non-root identities", "configured UIDs are missing, root, or overlap")
		t.Skip("capsule qualification requires three distinct non-root UIDs")
	}
	h.topology["service_uid"] = strconv.FormatUint(uint64(serviceUID), 10)
	h.topology["agent_uid"] = strconv.FormatUint(uint64(agentUID), 10)
	h.topology["recipient_uid"] = strconv.FormatUint(uint64(recipientUID), 10)
	h.recordTier("capsule-three-identity-boundary", tierSystem, "issuer, courier, and recipient execute as distinct OS identities", "all three UIDs are distinct and non-root", fmt.Sprintf("issuer=%d agent=%d recipient=%d", serviceUID, agentUID, recipientUID), true)

	homeRoot := filepath.Clean(strings.TrimSpace(os.Getenv("SEQPASS_QUAL_CAPSULE_HOME_ROOT")))
	if !filepath.IsAbs(homeRoot) || !strings.HasPrefix(homeRoot, "/tmp/") {
		h.recordBlocked("capsule-disposable-recipient-home", tierSystem, "recipient registration uses a disposable home", "SEQPASS_QUAL_CAPSULE_HOME_ROOT must name an isolated /tmp directory")
		t.Skip("capsule qualification requires a disposable recipient home")
	}
	if err := requireDisposableHome(recipientUser.HomeDir, homeRoot, recipientUID); err != nil {
		h.recordBlocked("capsule-disposable-recipient-home", tierSystem, "recipient registration uses a disposable home", err.Error())
		t.Skip("recipient passwd home is not isolated")
	}
	h.topology["recipient_home"] = recipientUser.HomeDir

	root, err := os.MkdirTemp("/tmp", "seqpass-capsule-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	serviceDir := filepath.Join(root, "issuer")
	agentDir := filepath.Join(root, "courier")
	if err := mkdirOwned(serviceDir, serviceIdentity, 0700); err != nil {
		t.Fatal(err)
	}
	if err := mkdirOwned(agentDir, agentIdentity, 0700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(recipientUser.HomeDir, ".local", "share", "seqpass-capsule-qual")
	privatePath := filepath.Join(keyDir, "recipient.hpke.json")
	publicPath := filepath.Join(keyDir, "recipient.hpke.pub")
	receiptPrivatePath := filepath.Join(keyDir, "recipient.receipt.seed")
	receiptPublicPath := filepath.Join(keyDir, "recipient.receipt.pub")
	seqpassBin := buildBinary(t, root)
	h.bin = seqpassBin
	if _, err := runCapsuleAs(seqpassBin, recipientIdentity, recipientUser, []string{
		"recipient", "keys", "generate", "--private-key", privatePath, "--public-key", publicPath,
		"--receipt-private-key", receiptPrivatePath, "--receipt-public-key", receiptPublicPath,
	}, nil); err != nil {
		t.Fatalf("recipient key generation failed: %v", err)
	}

	issuerSeed := filepath.Join(serviceDir, "issuer.seed")
	issuerPublic := filepath.Join(serviceDir, "issuer.pub")
	if _, err := runCapsuleAs(seqpassBin, serviceIdentity, serviceUser, []string{"admin", "handoff-issuer-keygen", "--private-seed", issuerSeed, "--public-key", issuerPublic}, nil); err != nil {
		t.Fatalf("issuer key generation failed: %v", err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil || len(publicBytes) != 32 {
		t.Fatal("recipient public key unavailable")
	}
	servicePublic := filepath.Join(serviceDir, "recipient.hpke.pub")
	if err := os.WriteFile(servicePublic, publicBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(servicePublic, int(serviceUID), int(serviceIdentity.gid)); err != nil {
		t.Fatal(err)
	}
	issuerBytes, err := os.ReadFile(issuerPublic)
	if err != nil || len(issuerBytes) != 32 {
		t.Fatal("issuer public key unavailable")
	}
	issuerCopy := filepath.Join(keyDir, "issuer.pub")
	if err := os.WriteFile(issuerCopy, issuerBytes, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(issuerCopy, int(recipientUID), int(recipientIdentity.gid)); err != nil {
		t.Fatal(err)
	}

	destinationID := fmt.Sprintf("qual-opencode-%d", time.Now().UnixNano())
	receiptDir := filepath.Join(keyDir, "receipts")
	if err := mkdirOwned(receiptDir, recipientIdentity, 0700); err != nil {
		t.Fatal(err)
	}
	brokerSocket := filepath.Join(root, "receipt.sock")
	receipts, stopReceipt, err := startCapsuleReceiptSink(brokerSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopReceipt)
	registerArgs := []string{
		"recipient", "capsule", "register", "--destination-id", destinationID, "--destination-revision", "1",
		"--recipient-key-id", "qual-recipient-r1", "--recipient-private-key", privatePath,
		"--receipt-key-id", "qual-receipt-r1", "--receipt-private-key", receiptPrivatePath, "--receipt-public-key", receiptPublicPath,
		"--issuer-key-id", "qual-issuer-r1", "--issuer-public-key", issuerCopy,
		"--target-id", "opencode:qual:api_key", "--app", "opencode", "--account", "qual", "--slot", "api_key",
		"--update-method", "opencode-auth-json-v1", "--source-ref", "qual/synthetic", "--source-revision", "1",
		"--broker-socket", brokerSocket,
	}
	if _, err := runCapsuleAs(seqpassBin, recipientIdentity, recipientUser, registerArgs, nil); err != nil {
		t.Fatalf("recipient trust registration failed: %v", err)
	}
	issuerHelper := filepath.Join(root, "capsule-issuer")
	buildHelper := exec.Command("go", "build", "-buildvcs=false", "-o", issuerHelper, "./qual/capsule_issuer")
	buildHelper.Dir = ".."
	if output, err := buildHelper.CombinedOutput(); err != nil {
		h.recordTier("capsule-issuer-helper-build", tierSystem, "build the test-only signed-capsule issuer", "helper builds from the actual SeqPass repository", trimOutput(output), false)
		t.Fatalf("capsule issuer helper build failed: %v: %s", err, trimOutput(output))
	}
	if err := os.Chown(issuerHelper, int(serviceUID), int(serviceIdentity.gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(issuerHelper, 0755); err != nil {
		t.Fatal(err)
	}

	const synthetic = "SEQPASS-QUAL-SEALED-CAPSULE-SYNTHETIC-7a5d"
	makeCapsule := func(extra ...string) ([]byte, error) {
		args := []string{"--issuer-seed", issuerSeed, "--issuer-key-id", "qual-issuer-r1", "--recipient-public-key", servicePublic,
			"--recipient-key-id", "qual-recipient-r1", "--destination-id", destinationID, "--destination-revision", "1"}
		args = append(args, extra...)
		return runCapsuleAs(issuerHelper, serviceIdentity, serviceUser, args, []byte(synthetic))
	}
	var receiptSequence atomic.Uint64
	importCapsule := func(encoded []byte, extra ...string) ([]byte, error) {
		receiptPath := filepath.Join(receiptDir, fmt.Sprintf("receipt-%d.json", receiptSequence.Add(1)))
		args := append([]string{"recipient", "capsule", "import", "--receipt-output", receiptPath}, extra...)
		return runCapsuleAs(seqpassBin, recipientIdentity, recipientUser, args, encoded)
	}

	validEnvelope, err := makeCapsule()
	if err != nil {
		t.Fatalf("issuer capsule creation failed: %v", err)
	}
	agentCopy := filepath.Join(agentDir, "handoff.capsule")
	if err := os.WriteFile(agentCopy, validEnvelope, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agentCopy, int(agentUID), int(agentIdentity.gid)); err != nil {
		t.Fatal(err)
	}
	observedCapsule, err := runCapsuleAs("/bin/cat", agentIdentity, agentUser, []string{agentCopy}, nil)
	packageOpaque := err == nil && !bytes.Contains(observedCapsule, []byte(synthetic))
	h.recordTier("capsule-agent-package-nondisclosure", tierSystem, "agent inspects the complete signed capsule bytes", "no synthetic plaintext is recoverable from the package", fmt.Sprintf("read=%t plaintext_absent=%t", err == nil, !bytes.Contains(observedCapsule, []byte(synthetic))), packageOpaque)
	privateDenied := capsuleReadDenied(privatePath, agentIdentity, agentUser)
	h.recordTier("capsule-agent-private-key-denial", tierSystem, "agent attempts to read the recipient-only HPKE private key", "kernel denies the untrusted agent UID", "private key read denied", privateDenied)
	issuerDenied := capsuleReadDenied(issuerSeed, agentIdentity, agentUser)
	h.recordTier("capsule-agent-issuer-key-denial", tierSystem, "agent attempts to read the issuer signing seed", "kernel denies the untrusted agent UID", "issuer seed read denied", issuerDenied)
	h.topology["capsule_sha256"] = sha256Hex(validEnvelope)
	h.topology["synthetic_credential_sha256"] = sha256Hex([]byte(synthetic))

	tampered := append([]byte(nil), validEnvelope...)
	tampered[len(tampered)-1] ^= 1
	_, tamperErr := importCapsule(tampered)
	h.recordTier("capsule-ciphertext-tamper-rejected", tierSystem, "recipient processes an agent-modified capsule", "signature or HPKE authentication fails before application write", resultText(tamperErr), tamperErr != nil)
	wrongDestination, wrongDestErr := makeCapsule("--destination-id", "unregistered-destination")
	if wrongDestErr == nil {
		_, wrongDestErr = importCapsule(wrongDestination)
	}
	h.recordTier("capsule-wrong-destination-rejected", tierSystem, "recipient receives a valid issuer capsule addressed to another logical destination", "no local registration matches the signed destination", resultText(wrongDestErr), wrongDestErr != nil)
	wrongTarget, wrongTargetErr := makeCapsule("--account", "attacker")
	if wrongTargetErr != nil {
		t.Fatalf("issuer could not create wrong-target negative control: %v", wrongTargetErr)
	}
	_, wrongTargetErr = importCapsule(wrongTarget)
	h.recordTier("capsule-wrong-target-rejected", tierSystem, "issuer-signed capsule names a target different from recipient registration", "recipient rejects before application write", resultText(wrongTargetErr), wrongTargetErr != nil)
	staleKey, staleKeyErr := makeCapsule("--recipient-key-id", "qual-recipient-r0")
	if staleKeyErr != nil {
		t.Fatalf("issuer could not create retired-key negative control: %v", staleKeyErr)
	}
	_, staleKeyErr = importCapsule(staleKey)
	h.recordTier("capsule-retired-recipient-key-rejected", tierSystem, "recipient receives a capsule for a retired key identity", "recipient-local current key ID rejects the stale capsule", resultText(staleKeyErr), staleKeyErr != nil)
	staleRevision, staleRevisionErr := makeCapsule("--destination-revision", "2")
	if staleRevisionErr != nil {
		t.Fatalf("issuer could not create stale-revision negative control: %v", staleRevisionErr)
	}
	_, staleRevisionErr = importCapsule(staleRevision)
	h.recordTier("capsule-stale-destination-revision-rejected", tierSystem, "recipient receives a capsule for a prior destination revision", "recipient-local revision rejects the stale capsule", resultText(staleRevisionErr), staleRevisionErr != nil)
	expired, expiredErr := makeCapsule("--age", "10m")
	if expiredErr != nil {
		t.Fatalf("issuer could not create expired negative control: %v", expiredErr)
	}
	_, expiredErr = importCapsule(expired)
	h.recordTier("capsule-expiry-rejected", tierSystem, "recipient receives an already expired signed capsule", "recipient rejects before application write", resultText(expiredErr), expiredErr != nil)
	_, attackerTrustErr := importCapsule(validEnvelope, "--issuer-key-id", "attacker-key")
	h.recordTier("capsule-agent-cannot-substitute-trust-flags", tierSystem, "courier attempts to override recipient trust through import arguments", "recipient import accepts no trust or target flags", resultText(attackerTrustErr), attackerTrustErr != nil)

	appPath := filepath.Join(recipientUser.HomeDir, ".local", "share", "opencode", "auth.json")
	if _, err := os.Stat(appPath); !os.IsNotExist(err) {
		h.recordTier("capsule-negative-controls-no-write", tierSystem, "inspect application state after invalid capsules", "invalid packages made no application write", "application auth file absent", false)
	} else {
		h.recordTier("capsule-negative-controls-no-write", tierSystem, "inspect application state after invalid capsules", "invalid packages made no application write", "application auth file absent", true)
	}
	if _, err := runCapsuleAs("/bin/mkdir", recipientIdentity, recipientUser, []string{"-p", filepath.Dir(appPath)}, nil); err != nil {
		t.Fatalf("could not prepare recipient app state directory: %v", err)
	}
	watcher, watch, err := watchCapsuleAppDir(filepath.Dir(appPath))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(watcher)
	var outputs [2][]byte
	var errs [2]error
	var wg sync.WaitGroup
	for i := range outputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outputs[i], errs[i] = importCapsule(validEnvelope)
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent identical capsule imports failed: first=%v second=%v", errs[0], errs[1])
	}
	writeCount, watchErr := countCapsuleAppWrites(watcher, watch, filepath.Base(appPath))
	content, readErr := os.ReadFile(appPath)
	installed := readErr == nil && bytes.Contains(content, []byte(synthetic))
	h.recordTier("capsule-concurrent-single-apply", tierSystem, "two recipient processes import the same capsule concurrently", "journal claim permits at most one application write and both receive idempotent completion", fmt.Sprintf("writes=%d receipts=%d", writeCount, receipts.Load()), watchErr == nil && writeCount == 1 && errs[0] == nil && errs[1] == nil)
	h.recordTier("capsule-recipient-install-readback", tierSystem, "inspect the recipient-owned OpenCode auth store", "only the registered recipient account contains the synthetic credential", fmt.Sprintf("installed=%t", installed), installed)
	h.recordTier("capsule-recipient-receipts", tierSystem, "inspect the recipient-authenticated completion sink", "both successful duplicate deliveries return receipts", fmt.Sprintf("receipts=%d", receipts.Load()), receipts.Load() == 2)
}

func capsuleIdentity(t *testing.T, variable string, h *harness) (uint32, *user.User, privilegedIdentity) {
	t.Helper()
	uid, err := parseUIDEnv(variable)
	if err != nil {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "resolve configured issuer, courier, and recipient accounts", err.Error())
		t.Skip("capsule identity configuration incomplete")
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "resolve configured issuer, courier, and recipient accounts", err.Error())
		t.Skip("capsule identity account unavailable")
	}
	id, err := identityFor(u)
	if err != nil {
		h.recordBlocked("capsule-three-identity-boundary", tierSystem, "resolve supplementary groups for each identity", err.Error())
		t.Skip("capsule identity groups unavailable")
	}
	return uid, u, id
}

func requireDisposableHome(home, root string, uid uint32) error {
	rel, err := filepath.Rel(root, home)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("recipient home must be beneath the disposable home root")
	}
	info, err := os.Stat(home)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("recipient home must already be owned by the recipient and not writable by others")
	}
	return nil
}

func mkdirOwned(path string, identity privilegedIdentity, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, int(identity.uid), int(identity.gid)); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func runCapsuleAs(binary string, identity privilegedIdentity, u *user.User, args []string, input []byte) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(identity)}
	cmd.Env = identityEnvironment(u, nil)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("process failed: %w (%s)", err, trimOutput(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

func capsuleReadDenied(path string, identity privilegedIdentity, u *user.User) bool {
	cmd := exec.Command("/bin/cat", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(identity)}
	cmd.Env = identityEnvironment(u, nil)
	return cmd.Run() != nil
}

func startCapsuleReceiptSink(path string) (*atomic.Int64, func(), error) {
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0666); err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	var count atomic.Int64
	var closed atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				if !scanner.Scan() {
					return
				}
				var req ipc.Request
				if json.Unmarshal(scanner.Bytes(), &req) != nil || req.Method != ipc.MethodHandoffComplete {
					return
				}
				count.Add(1)
				_ = json.NewEncoder(conn).Encode(ipc.Response{ID: req.ID, OK: true, Data: map[string]string{"status": "recorded"}})
			}(conn)
		}
	}()
	stop := func() {
		if closed.CompareAndSwap(false, true) {
			_ = listener.Close()
			wg.Wait()
		}
	}
	return &count, stop, nil
}

func watchCapsuleAppDir(dir string) (int, int, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return -1, -1, err
	}
	watch, err := syscall.InotifyAddWatch(fd, dir, syscall.IN_MOVED_TO)
	if err != nil {
		_ = syscall.Close(fd)
		return -1, -1, err
	}
	return fd, watch, nil
}

func countCapsuleAppWrites(fd, watch int, filename string) (int, error) {
	_ = watch
	if err := syscall.SetNonblock(fd, true); err != nil {
		return 0, err
	}
	buf := make([]byte, 4096)
	count := 0
	for {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		for offset := 0; offset+syscall.SizeofInotifyEvent <= n; {
			nameLen := int(binary.LittleEndian.Uint32(buf[offset+12 : offset+16]))
			nameStart := offset + syscall.SizeofInotifyEvent
			nameEnd := nameStart + nameLen
			if nameEnd > n {
				return count, fmt.Errorf("truncated inotify event")
			}
			mask := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
			name := strings.TrimRight(string(buf[nameStart:nameEnd]), "\x00")
			if mask&syscall.IN_MOVED_TO != 0 && name == filename {
				count++
			}
			offset = nameEnd
		}
	}
}
