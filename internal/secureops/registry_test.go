package secureops

import (
	"context"
	"testing"
)

type fakeDriver struct {
	name string
	mode CompletionMode
}

func (f fakeDriver) Name() string                 { return f.name }
func (f fakeDriver) Completion() CompletionMode   { return f.mode }
func (f fakeDriver) RequiresDestination() bool    { return false }
func (f fakeDriver) Describe() DriverInfo {
	return DriverInfo{Description: "fake", Completion: f.mode}
}
func (f fakeDriver) AllowedParams() []string      { return []string{} }
func (f fakeDriver) Resource(map[string]string) ResourceDescriptor {
	return ResourceDescriptor{Kind: "test", Identifier: f.name}
}
func (f fakeDriver) Validate(UseInput) error { return nil }
func (f fakeDriver) Execute(context.Context, Credential, UseInput) (SafeResult, error) {
	return SafeResult{Summary: "ok"}, nil
}

type fakeVerifier struct{ state OutcomeState }

func (f fakeVerifier) Verify(context.Context, UseInput, SafeResult) (Outcome, error) {
	return Outcome{State: f.state}, nil
}

// CV-02 validation: a synthetic state-changing driver without a verifier
// fails activation instead of silently reporting success by default.
func TestActivationRejectsUnverifiableStateChange(t *testing.T) {
	ds := map[string]OperationDriver{"x.write": fakeDriver{"x.write", ExternalPostcondition}}
	if err := validateDriverSet(ds, map[string]verifierReg{}); err == nil {
		t.Fatal("state-changing driver without verifier activated")
	}
	// Correctly configured: passes.
	vs := map[string]verifierReg{"x.write": {v: fakeVerifier{OutcomeSatisfied}}}
	if err := validateDriverSet(ds, vs); err != nil {
		t.Fatalf("valid driver rejected: %v", err)
	}
	// Read-only driver carrying a verifier: rejected (no phantom
	// postcondition allowed).
	ds2 := map[string]OperationDriver{"x.read": fakeDriver{"x.read", ResponseValidated}}
	if err := validateDriverSet(ds2, map[string]verifierReg{"x.read": {v: fakeVerifier{OutcomeSatisfied}}}); err == nil {
		t.Fatal("read-only driver with verifier activated")
	}
	if err := validateDriverSet(ds2, map[string]verifierReg{}); err != nil {
		t.Fatalf("plain read-only driver rejected: %v", err)
	}
	// Unknown mode and nil driver: rejected.
	ds3 := map[string]OperationDriver{"x.odd": fakeDriver{"x.odd", "mystery"}}
	if err := validateDriverSet(ds3, map[string]verifierReg{}); err == nil {
		t.Fatal("unknown completion mode activated")
	}
	ds4 := map[string]OperationDriver{"x.nil": nil}
	if err := validateDriverSet(ds4, map[string]verifierReg{}); err == nil {
		t.Fatal("nil driver activated")
	}
}

// CV-07: the live registries reject duplicates loudly.
func TestLiveRegistriesRejectDuplicates(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("duplicate driver registration silently accepted")
			}
		}()
		Register(fakeDriver{"github.get_repo", ResponseValidated})
	}()
	// Duplicate verifier registration is rejected. The probe name has no
	// driver, so the leftover entry cannot affect driver activation.
	if err := RegisterVerifierEx("test.dup-probe", "p", "v1", fakeVerifier{OutcomeSatisfied}); err != nil {
		t.Fatalf("probe verifier rejected: %v", err)
	}
	if err := RegisterVerifierEx("test.dup-probe", "p", "v2", fakeVerifier{OutcomeSatisfied}); err == nil {
		t.Fatal("duplicate verifier registration silently accepted")
	}
	if err := RegisterVerifierEx("", "p", "v1", fakeVerifier{OutcomeSatisfied}); err == nil {
		t.Fatal("empty-name verifier registration accepted")
	}
	if err := RegisterVerifierEx("test.nil-probe", "p", "v1", nil); err == nil {
		t.Fatal("nil verifier registration accepted")
	}
}

// The live registry must be internally consistent after all init-time
// registrations (except test-registered observers, which ValidateRegistries
// tolerates only when their drivers agree — github drivers stay clean).
func TestLiveRegistriesConsistent(t *testing.T) {
	driversMu.RLock()
	defer driversMu.RUnlock()
	verifyMu.RLock()
	defer verifyMu.RUnlock()
	for name, d := range drivers {
		if d.Completion() == ResponseValidated {
			if _, ok := verifiers[name]; ok {
				t.Fatalf("read-only driver %s carries a verifier", name)
			}
		}
	}
}
