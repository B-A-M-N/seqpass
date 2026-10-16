package hostnative

import (
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/harness"
)

func TestQualificationGateRequiresExactSnapshot(t *testing.T) {
	digest, err := harness.SecurityConfigDigest(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &harness.QualificationSnapshot{
		HostKind: harness.HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: harness.QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: harness.AdapterQualification{
			Status: harness.QualificationPassed, HostKind: harness.HostKindOpenCode,
			HostVersion: "2.0", AdapterVersion: "0.1", InputMode: harness.QualifiedHostNative,
			ExecutionTopology: "local", SecurityConfigDigest: digest,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	decision, err := harness.SelectNativeMode(snapshot, harness.HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || !decision.Qualified || decision.Mode != harness.InputHostNative {
		t.Fatalf("qualified native mode not selected: %+v err=%v", decision, err)
	}
	if decision.Assurance != "model_blind" {
		t.Fatal("native mode claimed isolation without boundary facts")
	}
	for name, mutate := range map[string]func(){
		"host":     func() { snapshot.HostVersion = "2.1" },
		"adapter":  func() { snapshot.AdapterVersion = "0.2" },
		"topology": func() { snapshot.Topology = "remote" },
		"digest":   func() { snapshot.ConfigDigest = "changed" },
	} {
		before := *snapshot
		mutate()
		if _, err := harness.SelectNativeMode(snapshot, harness.HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now()); err == nil {
			t.Fatalf("%s mismatch selected native mode", name)
		}
		*snapshot = before
	}
}

func TestAgentIsolatedRequiresAllBoundaries(t *testing.T) {
	digest, err := harness.SecurityConfigDigest(harness.HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	record := harness.AdapterQualification{
		Status: harness.QualificationPassed, HostKind: harness.HostKindOpenCode,
		HostVersion: "2.0", AdapterVersion: "0.1", InputMode: harness.QualifiedHostNative,
		ExecutionTopology: "local", SecurityConfigDigest: digest,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	snapshot := &harness.QualificationSnapshot{
		HostKind: harness.HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: harness.QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: record,
	}
	got, err := harness.SelectNativeMode(snapshot, harness.HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || got.Assurance != "model_blind" {
		t.Fatalf("partial boundary facts claimed isolation: %+v err=%v", got, err)
	}
	snapshot.Record.VerifiedProperties = map[string]bool{
		"intake_inaccessible": true, "terminal_isolated": true,
		"process_isolated": true, "transcript_isolated": true,
	}
	got, err = harness.SelectNativeMode(snapshot, harness.HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || got.Assurance != "agent_isolated" {
		t.Fatalf("complete boundary facts failed isolation gate: %+v err=%v", got, err)
	}
}
