// Package qual is the independent black-box qualification harness (SC-15).
//
// It treats the broker as an opaque system under test: it builds the real
// binary, launches the real broker as a child process, drives only the
// public surfaces (operator CLI, agent IPC, MCP stdio), and observes results
// from outside the implementation — recipient-side bytes, agent-visible
// receipts, and process behavior under failure injection.
//
// What it proves per run is recorded in a qualification manifest (JSON).
// What it cannot prove in an unprivileged test environment (true multi-UID
// isolation, real AegisKeys grants) is listed as residual risk, not assumed.
package qual

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/testruntime"
)

// Qualification tiers (CV-05): every case declares which slice of the
// system it exercises, so a green run cannot be mistaken for full native
// coverage when only one tier ran.
const (
	tierIPC    = "ipc-integration"
	tierMCP    = "mcp-surface"
	tierCLI    = "operator-cli"
	tierPost   = "external-postcondition"
	tierSystem = "cross-broker-system"
)

// manifest records everything needed to interpret one qualification run:
// source, executable, topology, intent, expected vs observed postconditions,
// and unresolved contradictions. When SEQPASS_QUAL_ARTIFACT_DIR is set the
// manifest is retained there as durable assurance evidence (CV-06);
// otherwise it lives in the test temp dir like before.
type manifest struct {
	Suite        string            `json:"suite"`
	SourceRev    string            `json:"source_rev"`
	AegisKeysRev string            `json:"aegiskeys_source_rev,omitempty"`
	BinaryHash   string            `json:"binary_sha256"`
	UID          uint32            `json:"uid"`
	GID          uint32            `json:"gid"`
	Agent        string            `json:"agent_principal"`
	Env          envFingerprint    `json:"environment"`
	Protocols    map[string]string `json:"protocol_versions"`
	VaultMode    string            `json:"vault_mode"`
	Topology     map[string]string `json:"topology,omitempty"`
	Cases        []caseResult      `json:"cases"`
	Residual     []string          `json:"residual_risks"`
	Contradicts  []string          `json:"unresolved_contradictions"`
}

type envFingerprint struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	Kernel    string `json:"kernel,omitempty"`
}

type caseResult struct {
	Name     string `json:"name"`
	Tier     string `json:"tier"`
	Intent   string `json:"intent"`
	Expected string `json:"expected_postcondition"`
	Observed string `json:"observed_postcondition"`
	Status   string `json:"status"` // passed | failed | blocked | not_exercised
	Pass     bool   `json:"pass"`
}

type harness struct {
	t        *testing.T
	dir      string
	bin      string
	broker   *exec.Cmd
	agent    string
	admin    string
	uid      string
	cases    []caseResult
	topology map[string]string
}

func (h *harness) record(name, intent, expected, observed string, pass bool) {
	h.recordTier(name, tierIPC, intent, expected, observed, pass)
}

// recordTier files a case under its qualification tier with an explicit
// status (CV-05/CV-06): passed, failed, blocked (environmental
// prerequisite missing — never counted as passing), or not_exercised.
func (h *harness) recordTier(name, tier, intent, expected, observed string, pass bool) {
	status := "passed"
	if !pass {
		status = "failed"
	}
	h.cases = append(h.cases, caseResult{
		Name: name, Tier: tier, Intent: intent,
		Expected: expected, Observed: observed, Status: status, Pass: pass,
	})
	if !pass {
		h.t.Errorf("QUAL FAIL %s [%s]: intent=%s expected=%s observed=%s", name, tier, intent, expected, observed)
	} else {
		h.t.Logf("QUAL PASS %s [%s]: %s", name, tier, observed)
	}
}

// recordBlocked files an environmental exclusion as blocked, not passing
// (CV-06/CV-09): a qualification that cannot run here must not read as
// green evidence for that claim.
func (h *harness) recordBlocked(name, tier, intent, missing string) {
	h.cases = append(h.cases, caseResult{
		Name: name, Tier: tier, Intent: intent,
		Expected: "environment supports this qualification", Observed: "blocked: " + missing,
		Status: "blocked",
	})
	h.t.Logf("QUAL BLOCKED %s [%s]: %s", name, tier, missing)
}

// recordNotExercised preserves required acceptance scenarios in the evidence
// record without implying that a narrower qualification covered them.
func (h *harness) recordNotExercised(name, tier, expected, reason string) {
	h.cases = append(h.cases, caseResult{
		Name: name, Tier: tier, Intent: "required audit acceptance scenario",
		Expected: expected, Observed: "not exercised: " + reason,
		Status: "not_exercised",
	})
	h.t.Logf("QUAL NOT EXERCISED %s [%s]: %s", name, tier, reason)
}

func buildBinary(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "seqpass")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/seqpass")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build broker: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(bin)
	sum := sha256.Sum256(raw)
	t.Logf("qual binary sha256: %s", hex.EncodeToString(sum[:]))
	return bin
}

func startBroker(t *testing.T, h *harness) {
	t.Helper()
	dir, err := testruntime.Dir(t)
	if err != nil {
		testruntime.Skip(t, err)
		return
	}
	_ = dir
	db := filepath.Join(h.dir, "qual.db")
	h.agent = filepath.Join(h.dir, "agent.sock")
	h.admin = filepath.Join(h.dir, "admin.sock")
	uid := fmt.Sprintf("%d", os.Geteuid())
	h.broker = exec.Command(h.bin, "broker",
		"--vault", "memory-test", "--dev",
		"--db", db,
		"--socket", h.agent, "--admin-socket", h.admin,
		"--agent-uid", uid, "--admin-uid", uid,
	)
	h.broker.Stdout = os.Stderr
	h.broker.Stderr = os.Stderr
	if err := h.broker.Start(); err != nil {
		t.Fatalf("start broker: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(h.agent); err == nil {
			if _, err := os.Stat(h.admin); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			_ = h.broker.Process.Kill()
			t.Fatal("broker sockets never appeared")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func adminCall(t *testing.T, h *harness, method string, params map[string]interface{}) interface{} {
	t.Helper()
	cli, err := ipc.Dial(h.admin)
	if err != nil {
		t.Fatalf("dial admin: %v", err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	data, err := cli.CallCtx(ctx, method, params)
	if err != nil {
		t.Fatalf("admin %s: %v", method, err)
	}
	return data
}

func agentCall(t *testing.T, h *harness, method string, params map[string]interface{}) (interface{}, error) {
	t.Helper()
	cli, err := ipc.Dial(h.agent)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return cli.CallCtx(ctx, method, params)
}

func strField(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

// recipient is an external v1 receiver with a durable file-backed store
// (CV-04): payloads persist under store/<op_id>.<digest> via atomic
// rename + fsync, so bytes survive a recipient restart. It independently
// recomputes SHA-256 over the received payload (never trusting the
// incoming digest), rejects unknown envelope versions and inconsistent
// duplicates, and only then acknowledges. dropAck simulates
// post-persistence ack loss. A storage-purpose receiver's terminal state
// is durably_accepted; it never claims applied (CV-10).
type recipient struct {
	t       *testing.T
	sock    string
	lis     net.Listener
	mu      sync.Mutex
	got     map[string][]byte // in-memory mirror for fast assertions
	counts  map[string]int
	dropAck bool
	store   string
}

func startRecipient(t *testing.T, dir, name string) *recipient {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "store-"+name)
	if err := os.MkdirAll(store, 0700); err != nil {
		t.Fatal(err)
	}
	r := &recipient{t: t, sock: filepath.Join(dir, name), got: map[string][]byte{}, counts: map[string]int{}, store: store}
	r.reloadStore()
	l, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	r.lis = l
	go r.serve()
	return r
}

// reloadStore rebuilds the in-memory mirror from the durable store, so a
// restarted recipient answers from disk, not from lost process memory.
func (r *recipient) reloadStore() {
	entries, _ := os.ReadDir(r.store)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".payload") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".payload")
		i := strings.LastIndex(base, ".")
		if i < 0 {
			continue
		}
		opID, digest := base[:i], base[i+1:]
		raw, err := os.ReadFile(filepath.Join(r.store, e.Name()))
		if err != nil {
			continue
		}
		r.got[opID+"/"+digest] = raw
	}
}

// storeFile maps (op_id, digest) to a store path. Op IDs and digests are
// broker-generated hex/ID strings; any path separator is rejected rather
// than sanitized into a traversal.
func (r *recipient) storeFile(opID, digest string) (string, bool) {
	if opID == "" || digest == "" {
		return "", false
	}
	if strings.ContainsAny(opID, "/\\") || strings.ContainsAny(digest, "/\\") {
		return "", false
	}
	return filepath.Join(r.store, opID+"."+digest+".payload"), true
}

// snapshot copies the persisted store under lock for race-clean assertions.
func (r *recipient) snapshot() (map[string][]byte, map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	got := make(map[string][]byte, len(r.got))
	for k, v := range r.got {
		got[k] = v
	}
	counts := make(map[string]int, len(r.counts))
	for k, v := range r.counts {
		counts[k] = v
	}
	return got, counts
}

func (r *recipient) serve() {
	for {
		c, err := r.lis.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

func (r *recipient) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var lb [4]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n == 0 || n > 2<<20 {
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	var probe struct {
		V    uint32 `json:"v"`
		Kind string `json:"kind"`
	}
	if json.Unmarshal(buf, &probe) != nil || probe.V != 1 {
		return // unknown envelope version: no ack, no state change
	}
	if probe.Kind == "lookup" {
		r.serveLookup(c, buf)
		return
	}
	r.serveDeliver(c, buf)
}

// serveDeliver validates, durably persists, then acks (CV-04). The digest
// is recomputed over the received bytes — the incoming digest is a claim,
// not a fact. Inconsistent duplicates (same op, different payload) are
// rejected; exact duplicates are acked idempotently without rewrite.
func (r *recipient) serveDeliver(c net.Conn, buf []byte) {
	var env struct {
		V       uint32 `json:"v"`
		OpID    string `json:"op_id"`
		Digest  string `json:"digest"`
		Payload string `json:"payload"`
	}
	if json.Unmarshal(buf, &env) != nil || env.V != 1 {
		return
	}
	deny := func(reason string) {
		raw, _ := json.Marshal(map[string]interface{}{
			"accepted": false, "op_id": env.OpID, "digest": env.Digest, "error": reason,
		})
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}
	sum := sha256.Sum256([]byte(env.Payload))
	if hex.EncodeToString(sum[:]) != env.Digest {
		deny("digest mismatch: payload does not hash to claimed digest")
		return
	}
	path, ok := r.storeFile(env.OpID, env.Digest)
	if !ok {
		deny("invalid operation identity")
		return
	}
	key := env.OpID + "/" + env.Digest
	// One serialized acceptance transition per operation (P1): the
	// mutex is held from duplicate comparison through durable
	// persistence to publication. Two concurrent conflicting deliveries
	// cannot both observe "no prior payload" — the loser sees the
	// winner's record and is rejected as an inconsistent duplicate.
	// File I/O under the lock is deliberate for this test-only
	// receiver; a real receiver would use a per-operation lock or a
	// transactional store.
	r.mu.Lock()
	defer r.mu.Unlock()
	// Inconsistent duplicate: this op already persisted OTHER bytes.
	for k := range r.got {
		if strings.HasPrefix(k, env.OpID+"/") && k != key {
			deny("inconsistent duplicate: operation already accepted different payload")
			return
		}
	}
	r.counts[key]++
	if _, have := r.got[key]; !have {
		// Atomic durable write: temp file + fsync + close-checked +
		// rename + dir fsync. Any durability failure denies instead
		// of acking a payload that might not survive.
		if !r.persistLocked(key, path, env.Payload, deny) {
			return
		}
	}

	if r.dropAck {
		return // bytes durable, ack lost: broker must report uncertain
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"accepted": true, "op_id": env.OpID, "digest": env.Digest, "bytes": len(env.Payload),
	})
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
	_, _ = c.Write(lb[:])
	_, _ = c.Write(raw)
}

// persistLocked writes one payload atomically and publishes it to the
// mirror. Caller holds r.mu. False means durability failed and deny()
// was already sent — never ack a possibly-lost payload.
func (r *recipient) persistLocked(key, path, payload string, deny func(string)) bool {
	tmp, err := os.CreateTemp(r.store, "tmp-*.payload")
	if err != nil {
		deny("storage unavailable")
		return false
	}
	tmpName := tmp.Name()
	fail := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		deny("storage unavailable")
	}
	if _, err := tmp.Write([]byte(payload)); err != nil {
		fail()
		return false
	}
	if err := tmp.Sync(); err != nil {
		fail()
		return false
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		deny("storage unavailable")
		return false
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		deny("storage unavailable")
		return false
	}
	if dfd, err := os.Open(r.store); err != nil {
		deny("storage unavailable")
		return false
	} else {
		syncErr := dfd.Sync()
		cerr := dfd.Close()
		if syncErr != nil || cerr != nil {
			deny("storage unavailable")
			return false
		}
	}
	r.got[key] = []byte(payload)
	return true
}

// serveLookup answers the recipient-status readback (CV-10) from durable
// state: durably_accepted when the exact (op, digest) is on disk, unknown
// otherwise. A storage-purpose receiver never claims applied.
func (r *recipient) serveLookup(c net.Conn, buf []byte) {
	var q struct {
		V      uint32 `json:"v"`
		Kind   string `json:"kind"`
		OpID   string `json:"op_id"`
		Digest string `json:"digest"`
	}
	if json.Unmarshal(buf, &q) != nil || q.V != 1 || q.Kind != "lookup" {
		return
	}
	reply := func(status, digest string, n int) {
		raw, _ := json.Marshal(map[string]interface{}{
			"op_id": q.OpID, "digest": digest, "status": status, "bytes": n,
		})
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(raw)))
		_, _ = c.Write(lb[:])
		_, _ = c.Write(raw)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if q.Digest != "" {
		if p, ok := r.got[q.OpID+"/"+q.Digest]; ok {
			reply("durably_accepted", q.Digest, len(p))
			return
		}
		reply("unknown", q.Digest, 0)
		return
	}
	for k, p := range r.got {
		if strings.HasPrefix(k, q.OpID+"/") {
			reply("durably_accepted", strings.TrimPrefix(k, q.OpID+"/"), len(p))
			return
		}
	}
	reply("unknown", "", 0)
}

// readback returns the exact durable bytes for (op_id, digest), or false.
// It reads through to disk so a restarted recipient proves survival.
func (r *recipient) readback(opID, digest string) ([]byte, bool) {
	path, ok := r.storeFile(opID, digest)
	if !ok {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// restart closes the listener, drops all process memory, and re-listens
// on the same socket with the same store (CV-04 validation). Anything
// the recipient still knows afterwards came from disk.
func (r *recipient) restart(t *testing.T) {
	t.Helper()
	_ = r.lis.Close()
	_ = os.Remove(r.sock)
	r.mu.Lock()
	r.got = map[string][]byte{}
	r.counts = map[string]int{}
	r.mu.Unlock()
	r.reloadStore()
	l, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatalf("recipient restart listen: %v", err)
	}
	r.lis = l
	go r.serve()
}

// TestQualFullCycle proves one complete blind-transfer workflow from intent
// to durable external outcome through public surfaces only: operator stages
// a synthetic secret, the agent requests a transfer seeing only an op ID,
// the operator approves and executes, and the external recipient holds the
// exact bytes while the agent-visible receipt holds none of them.
func TestQualFullCycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid())}
	h.bin = buildBinary(t, dir)
	startBroker(t, h)
	defer func() {
		_ = h.broker.Process.Signal(os.Interrupt)
		_ = h.broker.Wait()
	}()

	secret := "QUAL-SYNTHETIC-" + t.Name()
	// Operator: register unbound ref + stage payload via trusted intake.
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "qual-cert"})
	refID := strField(refData.(map[string]interface{}), "id")
	payloadFile := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payloadFile, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	adminCall(t, h, ipc.MethodSecretStage, map[string]interface{}{
		"ref_id": refID, "payload_b64": base64.StdEncoding.EncodeToString([]byte(secret)),
	})
	h.record("trusted-intake", "operator stages synthetic payload without agent visibility",
		"staged", "staged ref "+refID, refID != "")

	// Operator: register recipient + policy for this principal.
	rcptDir := filepath.Join(dir, "rcpt")
	if err := os.Mkdir(rcptDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := startRecipient(t, rcptDir, "r.sock")
	defer r.lis.Close()
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "qual-r", "type": "recipient-socket",
		"endpoint": r.sock, "expected_uid": float64(os.Geteuid()),
	})
	destID := strField(destData.(map[string]interface{}), "id")
	polData := adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "qual-pol",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":[%q],"resources":["*"]}]`, h.uid, refID, destID),
	})
	_ = polData

	// Agent: submit sees only an opaque op ID.
	subData, err := agentCall(t, h, ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": refID, "destination_id": destID,
	})
	if err != nil {
		t.Fatalf("agent submit: %v", err)
	}
	opID := strField(subData.(map[string]interface{}), "op_id")
	h.record("agent-submit", "agent coordinates transfer without plaintext",
		"opaque op id, no secret bytes", "op_id="+opID, opID != "" && !strings.Contains(fmt.Sprint(subData), secret))

	// Operator: approve exact reviewed revision, then execute.
	showData := adminCall(t, h, ipc.MethodOpShow, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	rev := int(showData.(map[string]interface{})["revision"].(float64))
	adminCall(t, h, ipc.MethodApproveTransfer, map[string]interface{}{"op_id": opID, "expect_revision": float64(rev)})
	adminCall(t, h, ipc.MethodExecuteTransfer, map[string]interface{}{"op_id": opID})

	// Agent: completed status + receipt without secret bytes.
	stData, err := agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil {
		t.Fatalf("agent status: %v", err)
	}
	stMap := stData.(map[string]interface{})
	status := strField(stMap, "status")
	receipt := fmt.Sprint(stMap["result"])
	h.record("agent-receipt", "agent learns outcome, never plaintext",
		"completed + receipt free of secret", "status="+status, status == "completed" && !strings.Contains(receipt, secret))

	// External postcondition: recipient holds EXACT bytes under (op,dgest).
	got, counts := r.snapshot()
	found := false
	for k, payload := range got {
		if strings.HasPrefix(k, opID+"/") && string(payload) == secret {
			found = true
			h.recordTier("recipient-outcome", tierPost, "intended external effect occurred",
				"recipient persists exact bytes", "key="+k, counts[k] == 1)
		}
	}
	if !found {
		h.recordTier("recipient-outcome", tierPost, "intended external effect occurred",
			"recipient persists exact bytes", fmt.Sprintf("recipient store: %d keys", len(got)), false)
	}

	// Negative control: unknown operation denied on the agent surface.
	if _, err := agentCall(t, h, ipc.MethodUseSubmit, map[string]interface{}{
		"secret_ref": refID, "operation": "shell.exec", "target": "",
	}); err == nil {
		h.record("deny-unknown-op", "unauthorized alternatives rejected",
			"denial", "shell.exec accepted", false)
	} else {
		h.record("deny-unknown-op", "unauthorized alternatives rejected",
			"denial", "denied: "+err.Error(), true)
	}

	writeManifest(t, h, "memory-test")
}

// TestQualUncertainAck proves ack loss is reported honestly: the recipient
// persists the bytes but the ack never arrives, so the broker must report
// uncertain — never false completion, never blind retry.
func TestQualUncertainAck(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid())}
	h.bin = buildBinary(t, dir)
	startBroker(t, h)
	defer func() {
		_ = h.broker.Process.Signal(os.Interrupt)
		_ = h.broker.Wait()
	}()

	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "qual-u"})
	refID := strField(refData.(map[string]interface{}), "id")
	adminCall(t, h, ipc.MethodSecretStage, map[string]interface{}{
		"ref_id": refID, "payload_b64": base64.StdEncoding.EncodeToString([]byte("U-PAYLOAD")),
	})
	rcptDir := filepath.Join(dir, "rcpt")
	if err := os.Mkdir(rcptDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := startRecipient(t, rcptDir, "r.sock")
	r.dropAck = true
	defer r.lis.Close()
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "qual-ur", "type": "recipient-socket",
		"endpoint": r.sock, "expected_uid": float64(os.Geteuid()),
	})
	destID := strField(destData.(map[string]interface{}), "id")
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "qual-upol",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":[%q],"resources":["*"]}]`, h.uid, refID, destID),
	})
	subData, err := agentCall(t, h, ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": refID, "destination_id": destID,
	})
	if err != nil {
		t.Fatal(err)
	}
	opID := strField(subData.(map[string]interface{}), "op_id")
	showData := adminCall(t, h, ipc.MethodOpShow, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	rev := int(showData.(map[string]interface{})["revision"].(float64))
	adminCall(t, h, ipc.MethodApproveTransfer, map[string]interface{}{"op_id": opID, "expect_revision": float64(rev)})
	execData, execErr := func() (interface{}, error) {
		cli, err := ipc.Dial(h.admin)
		if err != nil {
			return nil, err
		}
		defer cli.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return cli.CallCtx(ctx, ipc.MethodExecuteTransfer, map[string]interface{}{"op_id": opID})
	}()
	_ = execData
	stData, err := agentCall(t, h, ipc.MethodStatus, map[string]interface{}{"op_type": "transfer", "op_id": opID})
	if err != nil {
		t.Fatal(err)
	}
	status := strField(stData.(map[string]interface{}), "status")
	// Recipient persisted despite the lost ack; broker must say uncertain.
	got, _ := r.snapshot()
	persisted := false
	for k := range got {
		if strings.HasPrefix(k, opID+"/") {
			persisted = true
		}
	}
	h.recordTier("ack-loss", tierPost, "lost ack is uncertain, never false-completed",
		"status=uncertain + bytes durable at recipient",
		fmt.Sprintf("status=%s execErr=%v persisted=%v", status, execErr != nil, persisted),
		status == "uncertain" && persisted)

	// Reconciliation path (CV-10): the operator asks the recipient what
	// happened instead of guessing from the lost ack.
	rlData := adminCall(t, h, ipc.MethodRecipientStatus, map[string]interface{}{"op_id": opID})
	rlState := strField(rlData.(map[string]interface{}), "status")
	h.recordTier("ack-reconcile", tierCLI, "uncertain transfer has a reconciliation path, not just a warning",
		"recipient reports durably_accepted", "recipient.status="+rlState, rlState == "durably_accepted")

	writeManifest(t, h, "memory-test")
}

// TestQualMCPSmoke drives the real MCP stdio adapter as a harness would:
// initialize, tools/list, then secret_catalog — proving the adapter
// surface works end to end without ever carrying plaintext.
func TestQualMCPSmoke(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid())}
	h.bin = buildBinary(t, dir)
	startBroker(t, h)
	defer func() {
		_ = h.broker.Process.Signal(os.Interrupt)
		_ = h.broker.Wait()
	}()
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "qual-mcp"})
	refID := strField(refData.(map[string]interface{}), "id")
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "qual-mcpol",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":["*"],"resources":["*"]}]`, h.uid, refID),
	})

	mcp := exec.Command(h.bin, "mcp")
	mcp.Env = append(os.Environ(), "SEQ_PASS_SOCKET="+h.agent)
	stdin, _ := mcp.StdinPipe()
	stdout, _ := mcp.StdoutPipe()
	mcp.Stderr = os.Stderr
	if err := mcp.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mcp.Process.Kill() }()
	rd := bufio.NewReader(stdout)
	send := func(id int, method string, params string) {
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q`, id, method)
		if params != "" {
			msg += `,"params":` + params
		}
		msg += "}\n"
		if _, err := io.WriteString(stdin, msg); err != nil {
			t.Fatal(err)
		}
	}
	readReply := func() map[string]interface{} {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatalf("mcp reply: %v", err)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &v); err != nil {
			t.Fatalf("mcp decode %q: %v", line, err)
		}
		return v
	}
	send(1, "initialize", `{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"qual","version":"0"}}`)
	initReply := readReply()
	if _, ok := initReply["result"]; !ok {
		t.Fatalf("mcp initialize failed: %v", initReply)
	}
	if _, err := io.WriteString(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	send(2, "tools/list", `{}`)
	listReply := readReply()
	toolNames := map[string]bool{}
	if res, ok := listReply["result"].(map[string]interface{}); ok {
		if tools, ok := res["tools"].([]interface{}); ok {
			for _, t0 := range tools {
				if tm, ok := t0.(map[string]interface{}); ok {
					if n, ok := tm["name"].(string); ok {
						toolNames[n] = true
					}
				}
			}
		}
	}
	listOK := toolNames["secret_catalog"] && toolNames["secret_use"] && toolNames["secret_transfer"] && toolNames["secret_status"]
	h.recordTier("mcp-tools-list", tierMCP, "harness sees the full public tool surface",
		"catalog/use/transfer/status listed", fmt.Sprintf("tools=%v", toolNames), listOK)
	send(3, "tools/call", `{"name":"secret_catalog","arguments":{}}`)
	catReply := readReply()
	catText := fmt.Sprint(catReply)
	hasRef := strings.Contains(catText, "qual-mcp")
	h.recordTier("mcp-catalog", tierMCP, "harness discovers refs through MCP stdio, no plaintext",
		"catalog lists qual-mcp", fmt.Sprintf("lists=%v", hasRef), hasRef)
	_ = stdin.Close()
	_ = mcp.Wait()

	writeManifest(t, h, "memory-test")
}

// recordHostIntegrationGaps preserves the native-host review scenarios
// that unit/IPC tests cannot prove. They remain explicit not_exercised
// entries, never implicit green coverage (HI-04/HI-05 and §6).
func recordHostIntegrationGaps(h *harness) {
	for _, item := range []struct{ name, expected string }{
		{"hermes-native-ui", "actual Hermes TUI completes protected entry; synthetic credential absent from model transcript"},
		{"codex-native-ui", "actual stock Codex TUI completes protected entry with authenticated thread/session correlation"},
		{"claude-code-native-ui", "either actual supported Claude Code protected inline flow or explicit unsupported classification"},
		{"host-shell-attack", "agent shell/process tools cannot observe protected value or intake transport"},
		{"host-log-attack", "agent transcript, MCP recordings, replay logs and debug output contain no synthetic credential"},
		{"fake-prompt-attack", "agent-produced fake SeqPass text cannot activate trusted protected input"},
		{"host-upgrade-qualification", "changed host behavior invalidates the existing qualification until retested"},
		{"remote-session-trust", "protected input remains on trusted user side rather than untrusted remote agent side"},
	} {
		h.recordNotExercised(item.name, tierSystem, item.expected,
			"requires an unmodified normally launched host and independent disclosure-surface observation")
	}
}

func writeManifest(t *testing.T, h *harness, vault string) {
	t.Helper()
	rev := currentSourceRevision()
	if os.Getenv("SEQPASS_QUAL_ARTIFACT_DIR") != "" && !isFullSourceRevision(rev) {
		t.Fatalf("retained qualification evidence requires a full SeqPass source revision; got %q", rev)
	}
	binaryHash := ""
	if h.bin != "" {
		raw, err := os.ReadFile(h.bin)
		if err != nil {
			t.Fatalf("qual binary read failed: %v", err)
		}
		sum := sha256.Sum256(raw)
		binaryHash = hex.EncodeToString(sum[:])
	}
	pass, fail := 0, 0
	for _, c := range h.cases {
		// Blocked is an environmental exclusion, never a failure:
		// only failed statuses fail the run (CV-06).
		if c.Status == "blocked" || c.Status == "not_exercised" {
			continue
		}
		if c.Pass {
			pass++
		} else {
			fail++
		}
	}
	var contradicts []string
	for _, c := range h.cases {
		if c.Status == "failed" {
			contradicts = append(contradicts, c.Name+": expected="+c.Expected+" observed="+c.Observed)
		}
	}
	m := manifest{
		Suite:        "seqpass-qual/2",
		SourceRev:    rev,
		AegisKeysRev: strings.TrimSpace(os.Getenv("SEQPASS_QUAL_AEGISKEYS_REV")),
		BinaryHash:   binaryHash,
		UID:          uint32(os.Geteuid()),
		GID:          uint32(os.Getegid()),
		Agent:        h.uid,
		Env:          qualificationEnvironment(),
		Protocols:    map[string]string{"recipient-envelope": "v1", "mcp": "2024-11-05"},
		VaultMode:    vault,
		Topology:     h.topology,
		Cases:        h.cases,
		Residual:     []string{},
		Contradicts:  contradicts,
	}
	if h.topology != nil {
		h.topology["seqpass_source_revision"] = rev
		h.topology["seqpass_binary_sha256"] = binaryHash
		h.topology["go_version"] = runtime.Version()
	}
	if h.topology == nil {
		m.Residual = append(m.Residual, "true multi-UID isolation (distinct agent/admin OS users) not exercised")
	}
	recordHostIntegrationGaps(h)
	m.Residual = append(m.Residual, "real AegisKeys credential resolution, grant policy, and rotation not exercised")
	m.Residual = append(m.Residual,
		"provider and recipient side effects are independently observed only in the full cross-broker qualification",
		"recipient application identity beyond UID pinning not proven")
	out, _ := json.MarshalIndent(m, "", "  ")
	path := filepath.Join(h.dir, "qual-manifest.json")
	_ = os.WriteFile(path, out, 0600)
	// Retained evidence (CV-06): when an artifact directory is
	// configured, the manifest survives the temp-dir cleanup under a
	// unique name. Write failures there fail the run — silently lost
	// assurance evidence is worse than none.
	if art := os.Getenv("SEQPASS_QUAL_ARTIFACT_DIR"); art != "" {
		artPath := filepath.Join(art, fmt.Sprintf("qual-%s-%s-%d.json",
			h.t.Name(), rev, time.Now().UnixNano()))
		artifact, err := os.OpenFile(artPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			h.t.Fatalf("qual artifact write failed: %v", err)
		}
		if _, err := artifact.Write(out); err != nil {
			_ = artifact.Close()
			h.t.Fatalf("qual artifact write failed: %v", err)
		}
		if err := artifact.Sync(); err != nil {
			_ = artifact.Close()
			h.t.Fatalf("qual artifact sync failed: %v", err)
		}
		if err := artifact.Close(); err != nil {
			h.t.Fatalf("qual artifact close failed: %v", err)
		}
		h.t.Logf("QUAL ARTIFACT retained at %s", artPath)
	}
	shortHash := "not-built"
	if len(binaryHash) >= 12 {
		shortHash = binaryHash[:12]
	}
	t.Logf("QUAL MANIFEST rev=%s bin=%s pass=%d fail=%d manifest=%s",
		rev, shortHash, pass, fail, path)
	for _, c := range h.cases {
		if c.Status == "failed" || (!c.Pass && c.Status != "blocked" && c.Status != "not_exercised") {
			t.Errorf("case failed: %+v", c)
		}
	}
}

func currentSourceRevision() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	rev := strings.TrimSpace(string(out))
	if !isFullSourceRevision(rev) {
		return "unknown"
	}
	return rev
}

func isFullSourceRevision(rev string) bool {
	if len(rev) != 40 {
		return false
	}
	_, err := hex.DecodeString(rev)
	return err == nil
}

func TestCurrentSourceRevisionIsFull(t *testing.T) {
	rev := currentSourceRevision()
	if rev == "unknown" {
		t.Skip("source checkout has no full Git revision")
	}
	if !isFullSourceRevision(rev) {
		t.Fatalf("source revision is not a full 40-character SHA-1: %q", rev)
	}
	previousArtifactDir, hadArtifactDir := os.LookupEnv("SEQPASS_QUAL_ARTIFACT_DIR")
	_ = os.Unsetenv("SEQPASS_QUAL_ARTIFACT_DIR")
	t.Cleanup(func() {
		if hadArtifactDir {
			_ = os.Setenv("SEQPASS_QUAL_ARTIFACT_DIR", previousArtifactDir)
		} else {
			_ = os.Unsetenv("SEQPASS_QUAL_ARTIFACT_DIR")
		}
	})
	h := &harness{t: t, dir: t.TempDir()}
	writeManifest(t, h, "memory-test")
	raw, err := os.ReadFile(filepath.Join(h.dir, "qual-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.SourceRev != rev {
		t.Fatalf("manifest source revision = %q, want full revision %q", m.SourceRev, rev)
	}
}

func qualificationEnvironment() envFingerprint {
	info := envFingerprint{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version()}
	if out, err := exec.Command("uname", "-srmo").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}
	return info
}
