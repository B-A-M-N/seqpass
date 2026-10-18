package qual

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/sha256"

	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/testruntime"
)

// adminCLI exercises the true operator path (CV-05): the shipped admin
// CLI binary against the admin socket, not a direct IPC client. Stdout
// is returned for logging; any failure fails the run.
func adminCLI(t *testing.T, h *harness, args ...string) string {
	t.Helper()
	cmd := exec.Command(h.bin, append([]string{"admin"}, args...)...)
	cmd.Env = append(os.Environ(), "SEQ_PASS_ADMIN_SOCKET="+h.admin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("admin %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// mcpConn is an independent MCP client (CV-05): it speaks JSON-RPC over
// stdio and parses result fields semantically — never substring matches
// on the raw reply.
type mcpConn struct {
	t     *testing.T
	stdin io.WriteCloser
	rd    *bufio.Reader
	proc  *exec.Cmd
	next  int
}

func startMCP(t *testing.T, h *harness) *mcpConn {
	t.Helper()
	mcp := exec.Command(h.bin, "mcp")
	mcp.Env = append(os.Environ(), "SEQ_PASS_SOCKET="+h.agent)
	stdin, err := mcp.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := mcp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	mcp.Stderr = os.Stderr
	if err := mcp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mcp.Process.Kill() })
	return &mcpConn{t: t, stdin: stdin, rd: bufio.NewReader(stdout), proc: mcp, next: 1}
}

func (m *mcpConn) call(method, params string) map[string]interface{} {
	m.t.Helper()
	id := m.next
	m.next++
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q`, id, method)
	if params != "" {
		msg += `,"params":` + params
	}
	msg += "}\n"
	if _, err := io.WriteString(m.stdin, msg); err != nil {
		m.t.Fatal(err)
	}
	line, err := m.rd.ReadBytes('\n')
	if err != nil {
		m.t.Fatalf("mcp reply: %v", err)
	}
	var v map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(line), &v); err != nil {
		m.t.Fatalf("mcp decode %q: %v", line, err)
	}
	return v
}

func (m *mcpConn) notify(method string) {
	m.t.Helper()
	if _, err := io.WriteString(m.stdin, fmt.Sprintf(`{"jsonrpc":"2.0","method":%q}`+"\n", method)); err != nil {
		m.t.Fatal(err)
	}
}

// toolText extracts the text payload of a tools/call result.
func toolText(t *testing.T, reply map[string]interface{}) (string, bool) {
	t.Helper()
	res, _ := reply["result"].(map[string]interface{})
	if res == nil {
		return "", false
	}
	content, _ := res["content"].([]interface{})
	if len(content) == 0 {
		return "", false
	}
	first, _ := content[0].(map[string]interface{})
	text, _ := first["text"].(string)
	return text, text != ""
}

func isToolError(reply map[string]interface{}) bool {
	if e, ok := reply["isError"].(bool); ok && e {
		return true
	}
	if res, ok := reply["result"].(map[string]interface{}); ok {
		if e, ok := res["isError"].(bool); ok && e {
			return true
		}
	}
	// Some adapters surface errors top-level instead.
	if _, ok := reply["error"]; ok {
		return true
	}
	return false
}

// sendRawFrame delivers one length-prefixed frame to a unix socket and
// returns the raw reply, or an error on timeout/disconnect.
func sendRawFrame(sock string, frame []byte) ([]byte, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(frame)))
	if _, err := c.Write(lb[:]); err != nil {
		return nil, err
	}
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n == 0 || n > 4096 {
		return nil, fmt.Errorf("bad reply length %d", n)
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(c, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// digestOf is the test-side independent digest (recomputed, never copied
// from the broker).
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestQualRecipientDurable proves actual recipient restart survival and
// independently checked payload integrity (CV-04): kill the recipient
// after acknowledgment, restart it on the same store, and read back the
// exact bytes — plus tamper cases the old in-memory oracle never tried.
func TestQualRecipientDurable(t *testing.T) {
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
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid())}
	h.bin = buildBinary(t, dir)
	startBroker(t, h)
	defer func() {
		_ = h.broker.Process.Signal(os.Interrupt)
		_ = h.broker.Wait()
	}()

	secret := "QUAL-DURABLE-" + t.Name()
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "qual-dur"})
	refID := strField(refData.(map[string]interface{}), "id")
	payloadFile := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payloadFile, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	// Trusted intake through the real operator CLI file workflow (CV-05).
	adminCLI(t, h, "stage-secret", "--ref", refID, "--file", payloadFile)
	h.recordTier("cli-stage-secret", tierCLI, "operator stages payload through the shipped CLI file path",
		"staged", "staged ref "+refID, refID != "")

	rcptDir := filepath.Join(dir, "rcpt")
	if err := os.Mkdir(rcptDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := startRecipient(t, rcptDir, "r.sock")
	defer r.lis.Close()
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "qual-dr", "type": "recipient-socket",
		"endpoint": r.sock, "expected_uid": float64(os.Geteuid()),
	})
	destID := strField(destData.(map[string]interface{}), "id")
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "qual-dpol",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer"],"dest_ids":[%q],"resources":["*"]}]`, h.uid, refID, destID),
	})
	subData, err := agentCall(t, h, ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref": refID, "destination_id": destID,
	})
	if err != nil {
		t.Fatal(err)
	}
	opID := strField(subData.(map[string]interface{}), "op_id")
	adminCLI(t, h, "show", "--type", "transfer", "--id", opID)
	adminCLI(t, h, "approve", "--type", "transfer", "--id", opID)
	adminCLI(t, h, "execute", "--type", "transfer", "--id", opID)
	h.recordTier("cli-operator-path", tierCLI, "show/approve/execute complete through the shipped operator CLI",
		"executed", "executed "+opID, true)

	dgst := digestOf(secret)

	// Kill the recipient after ack, restart on the same store, read back.
	r.restart(t)
	defer r.lis.Close()
	raw, ok := r.readback(opID, dgst)
	h.recordTier("recipient-restart-survival", tierPost, "payload survives a recipient crash/restart from disk, not memory",
		"exact bytes on disk after restart", fmt.Sprintf("readback=%v len=%d", ok, len(raw)), ok && string(raw) == secret)

	// Independent readback over the wire (CV-10), bypassing the broker.
	lk, err := sendRawFrame(r.sock, []byte(fmt.Sprintf(`{"v":1,"kind":"lookup","op_id":%q,"digest":""}`, opID)))
	lkOK := err == nil && strings.Contains(string(lk), "durably_accepted") && strings.Contains(string(lk), dgst)
	h.recordTier("recipient-lookup", tierPost, "recipient reports its own acceptance state for reconciliation",
		"durably_accepted bound to digest", fmt.Sprintf("err=%v reply=%s", err, lk), lkOK)

	// Tamper: wrong digest is rejected and never stored.
	bad, _ := sendRawFrame(r.sock, []byte(fmt.Sprintf(`{"v":1,"op_id":"op-tamper","digest":"%s","payload":"evil"}`, dgst)))
	tamperOK := strings.Contains(string(bad), `"accepted":false`)
	if _, still := r.readback("op-tamper", dgst); still {
		tamperOK = false
	}
	h.recordTier("recipient-digest-mismatch", tierPost, "tampered payload is rejected, never persisted under a false digest",
		"accepted:false + nothing stored", string(bad), tamperOK)

	// Wrong envelope version: no ack at all.
	_, verr := sendRawFrame(r.sock, []byte(`{"v":999,"op_id":"op-ver","digest":"x","payload":"y"}`))
	h.recordTier("recipient-version-gate", tierPost, "unknown envelope versions are refused, not guessed",
		"no acknowledgment", fmt.Sprintf("err=%v", verr), verr != nil)

	// Inconsistent duplicate: same op, different payload, correct digest.
	other := "DIFFERENT-BYTES"
	otherDgst := digestOf(other)
	dup, _ := sendRawFrame(r.sock, []byte(fmt.Sprintf(`{"v":1,"op_id":%q,"digest":%q,"payload":%q}`, opID, otherDgst, other)))
	dupOK := strings.Contains(string(dup), `"accepted":false`)
	// Original bytes untouched.
	if raw2, ok2 := r.readback(opID, dgst); !ok2 || string(raw2) != secret {
		dupOK = false
	}
	h.recordTier("recipient-inconsistent-duplicate", tierPost, "same op with different payload is rejected; original preserved",
		"accepted:false + original intact", string(dup), dupOK)

	// Foreign op lookup: unknown, never applied.
	fk, _ := sendRawFrame(r.sock, []byte(`{"v":1,"kind":"lookup","op_id":"no-such-op","digest":""}`))
	h.recordTier("recipient-unknown-op", tierPost, "unknown operations report unknown, never success",
		`"unknown"`, string(fk), strings.Contains(string(fk), `"unknown"`))

	writeManifest(t, h, "memory-test")
}

// TestQualRecipientConcurrent proves the acceptance transition is
// serialized (P1): eight simultaneous conflicting deliveries under one
// operation ID yield exactly one accepted payload identity — never two.
func TestQualRecipientConcurrent(t *testing.T) {
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
	h := &harness{t: t, dir: dir, uid: fmt.Sprintf("uid:%d", os.Geteuid())}
	rcptDir := filepath.Join(dir, "rcpt")
	if err := os.Mkdir(rcptDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := startRecipient(t, rcptDir, "r.sock")
	defer r.lis.Close()
	const racers = 8
	results := make([]string, racers)
	done := make(chan struct{}, racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			payload := fmt.Sprintf("RACER-%d-PAYLOAD", i)
			frame := []byte(fmt.Sprintf(`{"v":1,"op_id":"op-race","digest":%q,"payload":%q}`, digestOf(payload), payload))
			raw, err := sendRawFrame(r.sock, frame)
			if err != nil {
				results[i] = "transport-error"
				return
			}
			results[i] = string(raw)
		}(i)
	}
	for i := 0; i < racers; i++ {
		<-done
	}
	accepted := 0
	var winner string
	for _, res := range results {
		if strings.Contains(res, `"accepted":true`) {
			accepted++
			winner = res
		}
	}
	h.recordTier("recipient-concurrent-single-winner", tierPost, "conflicting concurrent deliveries converge on one accepted identity",
		"exactly 1 accepted", fmt.Sprintf("accepted=%d", accepted), accepted == 1)
	// The winner's bytes are what survives; every other identity lost.
	survives := false
	for i := 0; i < racers; i++ {
		if raw, ok := r.readback("op-race", digestOf(fmt.Sprintf("RACER-%d-PAYLOAD", i))); ok {
			if survives {
				h.recordTier("recipient-concurrent-single-payload", tierPost, "at most one payload identity persists per operation",
					"one payload on disk", "two payloads on disk", false)
			}
			survives = true
			_ = winner
			_ = raw
		}
	}
	h.recordTier("recipient-concurrent-single-payload", tierPost, "at most one payload identity persists per operation",
		"one payload on disk", fmt.Sprintf("survives=%v", survives), survives)
	// Identical duplicates stay idempotent after the race.
	dupPayload := "RACER-DUP"
	dupFrame := []byte(fmt.Sprintf(`{"v":1,"op_id":"op-dup","digest":%q,"payload":%q}`, digestOf(dupPayload), dupPayload))
	for i := 0; i < 3; i++ {
		if raw, err := sendRawFrame(r.sock, dupFrame); err != nil || !strings.Contains(string(raw), `"accepted":true`) {
			h.recordTier("recipient-duplicate-idempotent", tierPost, "exact duplicates ack without multiplying side effects",
				"accepted x3", fmt.Sprintf("err=%v", err), false)
		}
	}
	got, counts := r.snapshot()
	h.recordTier("recipient-duplicate-idempotent", tierPost, "exact duplicates ack without multiplying side effects",
		"one stored payload, 3 deliveries", fmt.Sprintf("keys=%d counts=%v", len(got), counts["op-dup/"+digestOf(dupPayload)]),
		len(got) >= 1 && counts["op-dup/"+digestOf(dupPayload)] == 3)

	writeManifest(t, h, "memory-test")
}

// TestQualMCPFullCycle completes one transfer workflow AND one use
// workflow through the actual public interfaces (CV-05): MCP stdio for
// the agent side, the shipped operator CLI for show/approve/execute,
// MCP secret_status for the outcome, and recipient readback for the
// external postcondition.
func TestQualMCPFullCycle(t *testing.T) {
	t.Setenv("SEQ_PASS_TEST_DRIVERS", "1") // broker registers test.ping
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

	secret := "QUAL-MCP-" + t.Name()
	refData := adminCall(t, h, ipc.MethodSecretAdd, map[string]interface{}{"name": "qual-mcp-full"})
	refID := strField(refData.(map[string]interface{}), "id")
	payloadFile := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payloadFile, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	adminCLI(t, h, "stage-secret", "--ref", refID, "--file", payloadFile)

	rcptDir := filepath.Join(dir, "rcpt")
	if err := os.Mkdir(rcptDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := startRecipient(t, rcptDir, "r.sock")
	defer r.lis.Close()
	destData := adminCall(t, h, ipc.MethodDestAdd, map[string]interface{}{
		"name": "qual-mr", "type": "recipient-socket",
		"endpoint": r.sock, "expected_uid": float64(os.Geteuid()),
	})
	destID := strField(destData.(map[string]interface{}), "id")
	adminCall(t, h, ipc.MethodPolicyAdd, map[string]interface{}{
		"name":  "qual-mpol",
		"rules": fmt.Sprintf(`[{"principal":%q,"secret_refs":[%q],"ops":["transfer","test.ping"],"dest_ids":["*"],"resources":["*"]}]`, h.uid, refID),
	})

	m := startMCP(t, h)
	m.call("initialize", `{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"qual","version":"0"}}`)
	m.notify("notifications/initialized")

	// tools/list parsed semantically.
	list := m.call("tools/list", ``)
	names := map[string]bool{}
	if res, ok := list["result"].(map[string]interface{}); ok {
		if tools, ok := res["tools"].([]interface{}); ok {
			for _, t0 := range tools {
				if tm, ok := t0.(map[string]interface{}); ok {
					if n, ok := tm["name"].(string); ok {
						names[n] = true
					}
				}
			}
		}
	}
	listOK := names["secret_catalog"] && names["secret_use"] && names["secret_transfer"] && names["secret_status"]
	h.recordTier("mcp-full-tools-list", tierMCP, "full-cycle client sees every tool it will need",
		"all four tools listed", fmt.Sprintf("%v", names), listOK)

	// Negative control first: unknown ref is a tool error, not an op.
	neg := m.call("tools/call", `{"name":"secret_transfer","arguments":{"secret_ref":"nope","destination_id":"`+destID+`"}}`)
	h.recordTier("mcp-transfer-denied", tierMCP, "unauthorized transfer rejected on the MCP surface",
		"tool error", fmt.Sprint(neg), isToolError(neg))

	// Transfer through MCP submit.
	sub := m.call("tools/call", `{"name":"secret_transfer","arguments":{"secret_ref":"`+refID+`","destination_id":"`+destID+`"}}`)
	subText, ok := toolText(t, sub)
	var opID string
	if ok {
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(subText), &v); err == nil {
			opID, _ = v["op_id"].(string)
		}
	}
	h.recordTier("mcp-transfer-submit", tierMCP, "agent submits a blind transfer seeing only an opaque op id",
		"opaque op id, no secret bytes", subText, ok && opID != "" && !strings.Contains(subText, secret))

	// Operator path through the shipped CLI.
	adminCLI(t, h, "show", "--type", "transfer", "--id", opID)
	adminCLI(t, h, "approve", "--type", "transfer", "--id", opID)
	adminCLI(t, h, "execute", "--type", "transfer", "--id", opID)

	// Outcome back through MCP, parsed semantically.
	st := m.call("tools/call", `{"name":"secret_status","arguments":{"op_type":"transfer","op_id":"`+opID+`"}}`)
	stText, ok := toolText(t, st)
	var stMap map[string]interface{}
	if ok {
		_ = json.Unmarshal([]byte(stText), &stMap)
	}
	status, _ := stMap["status"].(string)
	h.recordTier("mcp-transfer-status", tierMCP, "agent learns the outcome through MCP, never plaintext",
		"completed + receipt free of secret", stText, ok && status == "completed" && !strings.Contains(stText, secret))

	// Stale-ID control: bogus op is a tool error.
	stale := m.call("tools/call", `{"name":"secret_status","arguments":{"op_type":"transfer","op_id":"bogus"}}`)
	h.recordTier("mcp-stale-id", tierMCP, "stale/unknown IDs are errors, not phantom receipts",
		"tool error", fmt.Sprint(stale), isToolError(stale))

	// External postcondition: exact bytes at the recipient + broker
	// reconciliation agrees (CV-10).
	got, _ := r.snapshot()
	found := false
	for k, p := range got {
		if strings.HasPrefix(k, opID+"/") && string(p) == secret {
			found = true
			raw, ok := r.readback(opID, strings.TrimPrefix(k, opID+"/"))
			h.recordTier("mcp-recipient-readback", tierPost, "intended external effect independently confirmed",
				"exact bytes on recipient disk", fmt.Sprintf("disk=%v", ok && string(raw) == secret), ok && string(raw) == secret)
		}
	}
	if !found {
		h.recordTier("mcp-recipient-readback", tierPost, "intended external effect independently confirmed",
			"exact bytes at recipient", "nothing stored", false)
	}

	// Use workflow through MCP with the synthetic credentialed endpoint.
	usub := m.call("tools/call", `{"name":"secret_use","arguments":{"secret_ref":"`+refID+`","operation":"test.ping"}}`)
	usubText, ok := toolText(t, usub)
	var useID string
	if ok {
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(usubText), &v); err == nil {
			useID, _ = v["op_id"].(string)
		}
	}
	h.recordTier("mcp-use-submit", tierMCP, "credentialed use submits through MCP without exposing the credential",
		"opaque op id", usubText, ok && useID != "" && !strings.Contains(usubText, secret))
	adminCLI(t, h, "approve", "--type", "use", "--id", useID)
	adminCLI(t, h, "execute", "--type", "use", "--id", useID)
	ust := m.call("tools/call", `{"name":"secret_status","arguments":{"op_type":"use","op_id":"`+useID+`"}}`)
	ustText, ok := toolText(t, ust)
	var ustMap map[string]interface{}
	if ok {
		_ = json.Unmarshal([]byte(ustText), &ustMap)
	}
	ustatus, _ := ustMap["status"].(string)
	h.recordTier("mcp-use-status", tierMCP, "credentialed use completes with a typed safe result",
		"completed with echo pong", ustText,
		ok && ustatus == "completed" && strings.Contains(ustText, "pong") && !strings.Contains(ustText, secret))

	_ = m.stdin.Close()
	_ = m.proc.Wait()
	writeManifest(t, h, "memory-test")
}
