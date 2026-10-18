package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with stdout redirected and returns what was printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = pw
	defer func() { os.Stdout = saved }()
	fn()
	_ = pw.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, pr); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	return buf.String()
}

// The generic agent CLI is a trust boundary: whatever the broker returns is
// untrusted, and an unqualified state must never be reported to the agent. A
// qualified state is reported with credential-bearing fields scrubbed.
func TestReportAgentStatusFailsClosedOnUnqualifiedState(t *testing.T) {
	cases := []interface{}{
		map[string]interface{}{"status": "WEIRD_STATE"},
		map[string]interface{}{"status": ""},
		map[string]interface{}{},
		map[string]interface{}{"status": true},
	}
	for _, data := range cases {
		out := captureStdout(t, func() {
			if err := reportAgentStatus("req-1", data); err == nil {
				t.Errorf("reportAgentStatus(%v) accepted an unqualified payload", data)
			}
		})
		if strings.Contains(out, "secret-value") {
			t.Errorf("a refused payload still printed %q", out)
		}
	}
}

func TestReportAgentStatusReportsQualifiedStateScrubbed(t *testing.T) {
	data := map[string]interface{}{
		"status":      "awaiting_user",
		"outcome":     "",
		"next_action": "protected_input",
		"payload":     "secret-value",
	}
	var out string
	var err error
	out = captureStdout(t, func() {
		err = reportAgentStatus("req-9", data)
	})
	if err != nil {
		t.Fatalf("qualified state refused: %v", err)
	}
	if strings.Contains(out, "secret-value") {
		t.Fatal("a scrubbed report leaked a credential-bearing field")
	}
	// Two frames are printed: the adapter event, then the scrubbed summary.
	// Both must be valid JSON and must not carry the payload.
	dec := json.NewDecoder(strings.NewReader(out))
	var frames []map[string]interface{}
	for dec.More() {
		var frame map[string]interface{}
		if jerr := dec.Decode(&frame); jerr != nil {
			t.Fatalf("output is not JSON frames: %v (%q)", jerr, out)
		}
		frames = append(frames, frame)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want event + summary (%q)", len(frames), out)
	}
	event, summary := frames[0], frames[1]
	if event["type"] != "state_changed" || event["request_id"] != "req-9" || event["state"] != "awaiting_user" {
		t.Fatalf("event frame = %v", event)
	}
	// The summary carries the derived facts, so an agent never has to
	// interpret broker vocabulary itself.
	if summary["status"] != "awaiting_user" {
		t.Fatalf("summary status = %v", summary["status"])
	}
	if summary["settled"] != false || summary["succeeded"] != false {
		t.Fatalf("summary facts = %v %v", summary["settled"], summary["succeeded"])
	}
	// A credential-bearing field is redacted, not dropped or passed through.
	if summary["payload"] != "[redacted]" {
		t.Fatalf("summary payload = %v, want the redaction marker", summary["payload"])
	}
}
