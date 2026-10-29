package main

import "testing"

func TestAgentHandoffIssueParsesOperationAndOutput(t *testing.T) {
	operationID, output, err := parseAgentHandoffIssueArgs([]string{"--op-id", "op-123", "--output", "/tmp/handoff.capsule"})
	if err != nil || operationID != "op-123" || output != "/tmp/handoff.capsule" {
		t.Fatalf("handoff issue args parsed as op=%q output=%q err=%v", operationID, output, err)
	}
}

func TestAgentHandoffIssueRequiresOperationID(t *testing.T) {
	if _, _, err := parseAgentHandoffIssueArgs([]string{"--output", "/tmp/handoff.capsule"}); err == nil {
		t.Fatal("handoff issue accepted a missing operation ID")
	}
}
