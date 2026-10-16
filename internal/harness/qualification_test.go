package harness

import (
	"testing"
	"time"
)

func TestQualificationDigestChangesWithSecurityConfig(t *testing.T) {
	a, err := SecurityConfigDigest(HostKindCodex, "1.2.3", "4.5.6", "local-agent-uid-2001", map[string]string{"intake_group": "trusted"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SecurityConfigDigest(HostKindCodex, "1.2.3", "4.5.6", "local-agent-uid-2001", map[string]string{"intake_group": "changed"})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("security configuration change did not invalidate digest")
	}
}

func TestQualificationFailsClosedOnChange(t *testing.T) {
	digest, err := SecurityConfigDigest(HostKindCodex, "1.2.3", "4.5.6", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	q := AdapterQualification{
		Status:               QualificationPassed,
		HostKind:             HostKindCodex,
		HostVersion:          "1.2.3",
		AdapterVersion:       "4.5.6",
		InputMode:            QualifiedHostNative,
		ExecutionTopology:    "local",
		SecurityConfigDigest: digest,
		ExpiresAt:            time.Now().Add(time.Minute),
	}
	if err := q.ValidFor(HostKindCodex, "1.2.3", "4.5.6", QualifiedHostNative, "local", digest, time.Now()); err != nil {
		t.Fatalf("valid qualification refused: %v", err)
	}
	if err := q.ValidFor(HostKindCodex, "1.2.4", "4.5.6", QualifiedHostNative, "local", digest, time.Now()); err == nil {
		t.Fatal("upgraded host retained qualification")
	}
	if err := q.ValidFor(HostKindCodex, "1.2.3", "4.5.6", QualifiedHostNative, "remote", digest, time.Now()); err == nil {
		t.Fatal("changed topology retained qualification")
	}
	if err := q.ValidFor(HostKindCodex, "1.2.3", "4.5.6", QualifiedHostNative, "local", digest, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expired qualification accepted")
	}
}

func TestQualificationRequiresMandatoryFacts(t *testing.T) {
	if _, err := SecurityConfigDigest(HostKindCodex, "", "4", "local", nil); err == nil {
		t.Fatal("missing host version accepted")
	}
}

func TestSelectNativeModeFailsClosedWithoutSnapshot(t *testing.T) {
	d, err := SelectNativeMode(nil, HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil {
		t.Fatalf("safe fallback returned error: %v", err)
	}
	if d.Qualified || d.RecordUsed || d.Mode != InputExternalTTY || d.Assurance != "model_blind" {
		t.Fatalf("unsafe native decision without qualification: %+v", d)
	}
}

func TestSelectNativeModeRequiresExactQualification(t *testing.T) {
	digest, err := SecurityConfigDigest(HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &QualificationSnapshot{
		HostKind: HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: AdapterQualification{
			Status: QualificationPassed, HostKind: HostKindOpenCode,
			HostVersion: "2.0", AdapterVersion: "0.1", InputMode: QualifiedHostNative,
			ExecutionTopology: "local", SecurityConfigDigest: digest,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	valid, err := SelectNativeMode(snapshot, HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || !valid.Qualified || valid.Mode != InputHostNative {
		t.Fatalf("valid qualification not selected: %+v err=%v", valid, err)
	}
	if valid.Assurance != "model_blind" {
		t.Fatalf("native mode claimed isolation without boundary facts: %+v", valid)
	}
	for name, mutate := range map[string]func(){
		"host":     func() { snapshot.HostVersion = "2.1" },
		"adapter":  func() { snapshot.AdapterVersion = "0.2" },
		"topology": func() { snapshot.Topology = "remote" },
		"digest":   func() { snapshot.ConfigDigest = "changed" },
	} {
		before := *snapshot
		mutate()
		if _, err := SelectNativeMode(snapshot, HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now()); err == nil {
			t.Fatalf("%s mismatch selected native mode", name)
		}
		*snapshot = before
	}
}

func TestSelectNativeModeAgentIsolatedRequiresAllBoundaries(t *testing.T) {
	digest, err := SecurityConfigDigest(HostKindOpenCode, "2.0", "0.1", "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	record := AdapterQualification{
		Status: QualificationPassed, HostKind: HostKindOpenCode,
		HostVersion: "2.0", AdapterVersion: "0.1", InputMode: QualifiedHostNative,
		ExecutionTopology: "local", SecurityConfigDigest: digest,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	snapshot := &QualificationSnapshot{
		HostKind: HostKindOpenCode, HostVersion: "2.0", AdapterVersion: "0.1",
		InputMode: QualifiedHostNative, Topology: "local", ConfigDigest: digest,
		Record: record,
	}
	got, err := SelectNativeMode(snapshot, HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || got.Assurance != "model_blind" {
		t.Fatalf("incomplete properties claimed isolation: %+v err=%v", got, err)
	}
	snapshot.Record.VerifiedProperties = map[string]bool{
		"intake_inaccessible": true, "terminal_isolated": true,
		"process_isolated": true, "transcript_isolated": true,
	}
	got, err = SelectNativeMode(snapshot, HostKindOpenCode, "2.0", "0.1", "local", nil, time.Now())
	if err != nil || got.Assurance != "agent_isolated" {
		t.Fatalf("complete properties did not reach agent_isolated: %+v err=%v", got, err)
	}
}
