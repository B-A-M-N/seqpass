package secureops

import (
	"context"
	"os"
)

// test.ping is a synthetic credentialed operation for black-box
// qualification (CV-05): it lets the qual harness drive a complete
// secret_use workflow — submit, approve, execute, status, verify —
// through the real public surfaces without needing network credentials.
// It executes inside the trusted worker like any driver but ignores the
// credential and returns a fixed closed DTO.
//
// Activation is env-gated: registered only when SEQ_PASS_TEST_DRIVERS=1.
// Production brokers never set it, so the operation does not exist there
// (unknown-operation denial). Completion is ResponseValidated: correct
// authorization + the closed result gate IS completion, and no verifier
// is registered — claiming an independent observation for a synthetic
// no-op would be dishonest.
func init() {
	if os.Getenv("SEQ_PASS_TEST_DRIVERS") != "1" {
		return
	}
	Register(pingDriver{})
}

type pingDriver struct{}

func (pingDriver) Name() string               { return "test.ping" }
func (pingDriver) Completion() CompletionMode { return ResponseValidated }
func (pingDriver) RequiresDestination() bool  { return false }
func (pingDriver) Describe() DriverInfo {
	return DriverInfo{
		Description: "Synthetic qualification endpoint: returns a fixed pong (test drivers only)",
		Completion:  ResponseValidated,
	}
}
func (pingDriver) AllowedParams() []string { return []string{} }
func (pingDriver) Resource(map[string]string) ResourceDescriptor {
	return ResourceDescriptor{Kind: "test", Identifier: "ping"}
}
func (pingDriver) Validate(UseInput) error { return nil }
func (pingDriver) Execute(context.Context, Credential, UseInput) (SafeResult, error) {
	return SafeResult{Summary: "ping ok", Data: map[string]interface{}{"echo": "pong"}}, nil
}
