package secureops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/secretbridge/secretbridge/internal/types"
)

// UseInput is a validated typed operation request (no raw secrets).
type UseInput struct {
	Operation string
	Target    string
	Params    map[string]string
	OpID      string
	Principal string
	Resource  ResourceDescriptor
}

// SafeResult is sanitized output safe for model-visible responses.
type SafeResult struct {
	Summary string                 `json:"summary"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// Result value bounds (SC-09): the model-visible contract is closed at the
// shared boundary, not per driver. Drivers project into typed DTOs, and
// this gate rejects anything outside the DTO shape before persistence and
// IPC publication, so a future driver cannot smuggle arbitrary structures,
// oversized values, or secret-bearing nesting past the boundary.
const (
	maxSummaryLen = 1024
	maxResultKeys = 64
	maxKeyLen     = 128
	maxStringLen  = 4096
	maxArrayLen   = 256
	maxResultJSON = 32 * 1024 // receipt cap is 64 KiB; results stay well under
	maxValueDepth = 3         // Data -> DTO struct/array -> scalar fields
)

// ValidateSafeResult enforces the closed model-visible result contract.
// Allowed: string/bool/numeric/nil scalars, arrays of scalars or of flat
// scalar-valued objects (projected DTOs), and one level of flat
// scalar-valued objects. Rejected: deeper nesting, oversized values,
// excess keys, non-finite numbers, and anything that does not survive a
// JSON round-trip identically (map keys, unexported state, NaN).
func ValidateSafeResult(r SafeResult) error {
	if r.Summary == "" || len(r.Summary) > maxSummaryLen {
		return errors.New("result summary missing or oversized")
	}
	if len(r.Data) > maxResultKeys {
		return errors.New("result has too many fields")
	}
	raw, err := json.Marshal(r.Data)
	if err != nil {
		return fmt.Errorf("result not JSON-serializable: %w", err)
	}
	if len(raw) > maxResultJSON {
		return errors.New("result too large")
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return errors.New("result not JSON-stable")
	}
	m, _ := v.(map[string]interface{})
	if r.Data != nil && m == nil {
		return errors.New("result data must be an object")
	}
	for k, val := range m {
		if k == "" || len(k) > maxKeyLen {
			return fmt.Errorf("result field name invalid: %q", k)
		}
		if err := checkValue(val, 1); err != nil {
			return fmt.Errorf("result field %q: %w", k, err)
		}
	}
	return nil
}

// ValidateCredentialNonDisclosure is the final credential-aware egress gate.
// It checks the normalized JSON representation of the projected result, so
// escaped JSON spellings are decoded before exact credential containment is
// evaluated. The check covers the primary value and every resolved component.
func ValidateCredentialNonDisclosure(r SafeResult, cred Credential) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return errors.New("result cannot be checked for credential disclosure")
	}
	defer clear(raw)
	var normalized interface{}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return errors.New("result cannot be checked for credential disclosure")
	}
	if containsCredential(normalized, cred.Value) {
		return errors.New("result contains resolved credential material")
	}
	for _, value := range cred.Components {
		if containsCredential(normalized, value) {
			return errors.New("result contains resolved credential material")
		}
	}
	return nil
}

func containsCredential(value interface{}, credential string) bool {
	if credential == "" {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.Contains(v, credential)
	case []interface{}:
		for _, item := range v {
			if containsCredential(item, credential) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range v {
			if strings.Contains(key, credential) || containsCredential(item, credential) {
				return true
			}
		}
	}
	return false
}

func checkValue(v interface{}, depth int) error {
	if depth > maxValueDepth {
		return errors.New("value nested too deep")
	}
	switch t := v.(type) {
	case nil, bool, string:
		if s, ok := v.(string); ok && len(s) > maxStringLen {
			return errors.New("string value too large")
		}
		return nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return errors.New("non-finite number")
		}
		return nil
	case []interface{}:
		if len(t) > maxArrayLen {
			return errors.New("array too large")
		}
		for _, e := range t {
			// DTO arrays hold scalars or flat objects; arrays never
			// nest inside arrays.
			if _, ok := e.([]interface{}); ok {
				return errors.New("array nested in array")
			}
			if err := checkValue(e, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		if len(t) > maxResultKeys {
			return errors.New("object too large")
		}
		for k, e := range t {
			if k == "" || len(k) > maxKeyLen {
				return fmt.Errorf("nested field name invalid: %q", k)
			} // Objects nested in objects exceed the DTO shape; arrays of
			// scalars are still fine one level down.
			if _, ok := e.(map[string]interface{}); ok {
				return errors.New("object nested in object")
			}
			if err := checkValue(e, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
}

// Credential is plaintext available inside the trusted executor only.
type Credential struct {
	Value      string
	Components map[string]string
}

// ResourceDescriptor is the canonical resource a credential permission binds to.
type ResourceDescriptor = types.ResourceDescriptor

// CompletionMode declares what "done" means for an operation (CV-02).
// It is declared by the driver, never inferred from the absence of a
// verifier: inferring read-only semantics from a missing registration
// would let a future state-changing driver silently report success as
// verified by default.
type CompletionMode string

const (
	// ResponseValidated means correct authorization + valid response
	// schema + delivery of the permitted information IS completion.
	// No independent postcondition exists to observe; no verifier
	// may be registered for these operations.
	ResponseValidated CompletionMode = "response_validated"
	// ExternalPostcondition means completion requires an independently
	// observed external effect. A verifier MUST be registered; without
	// one the registry refuses to activate (fail closed).
	ExternalPostcondition CompletionMode = "external_postcondition"
)

// ParamInfo describes one accepted argument without carrying values.
type ParamInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// DriverInfo is the non-secret public face of a driver (G06): what the
// operation does, what it needs, and what "done" means. No credential
// shapes, no endpoint internals.
type DriverInfo struct {
	Description  string         `json:"description"`
	Params       []ParamInfo    `json:"params"`
	ResourceKind string         `json:"resource_kind,omitempty"`
	Completion   CompletionMode `json:"completion"`
	Destination  bool           `json:"requires_destination"`
}

// OperationDriver executes one allowlisted operation with a resolved credential.
// Drivers declare their typed contract so submission validates the exact
// resource semantics before persistence and approval.
type OperationDriver interface {
	Name() string
	// Describe exposes the non-secret invocation contract for
	// capability discovery (G06). Agents learn operations from the
	// catalog, never by guessing undocumented identifiers.
	Describe() DriverInfo
	// Completion declares what "done" means (CV-02). Every driver must
	// declare it; bootstrap validation rejects unknown modes and
	// ExternalPostcondition drivers without a registered verifier.
	Completion() CompletionMode
	// RequiresDestination reports whether the op takes a registered dest ID.
	RequiresDestination() bool
	// AllowedParams lists the only accepted param keys (unknown keys denied).
	AllowedParams() []string
	// Resource derives the canonical resource from validated arguments.
	Resource(params map[string]string) ResourceDescriptor
	Validate(UseInput) error
	Execute(ctx context.Context, cred Credential, input UseInput) (SafeResult, error)
}

var (
	drivers   = map[string]OperationDriver{}
	driversMu sync.RWMutex
	frozen    bool
)

// Register adds a driver. Called from init() in driver files.
// Nil drivers, empty names, and duplicate registrations panic (CV-07):
// the registry is the authority for security-sensitive completion
// semantics, so a mutable, permissive registry is not acceptable. After
// FreezeRegistries runs (broker startup), registration is refused.
func Register(d OperationDriver) {
	if d == nil || d.Name() == "" {
		panic("secureops: invalid driver registration")
	}
	driversMu.Lock()
	defer driversMu.Unlock()
	if frozen {
		panic("secureops: driver registration after freeze: " + d.Name())
	}
	if _, dup := drivers[d.Name()]; dup {
		panic("secureops: duplicate driver registration: " + d.Name())
	}
	drivers[d.Name()] = d
}

// Lookup returns a driver or an error for unknown operations (deny).
func Lookup(name string) (OperationDriver, error) {
	d, ok := drivers[name]
	if !ok {
		return nil, fmt.Errorf("unknown operation %q", name)
	}
	return d, nil
}

// ValidateRegistries is the bootstrap activation contract (CV-02/CV-07).
// It rejects nil drivers, unknown completion modes, ExternalPostcondition
// drivers without a registered verifier, and ResponseValidated drivers
// carrying a verifier (a verifier on a read-only op would imply an
// external postcondition that does not exist). Call at broker startup
// before accepting work; it freezes the registries against further
// silent replacement.
func ValidateRegistries() error {
	driversMu.RLock()
	defer driversMu.RUnlock()
	verifyMu.RLock()
	defer verifyMu.RUnlock()
	return validateDriverSet(drivers, verifiers)
}

// validateDriverSet is the pure activation check over one driver/verifier
// pair of maps, so the contract itself is unit-testable without mutating
// the global registries (CV-02/CV-07 validation).
func validateDriverSet(ds map[string]OperationDriver, vs map[string]verifierReg) error {
	for name, d := range ds {
		if d == nil {
			return errors.New("secureops: nil driver for " + name)
		}
		_, hasVerifier := vs[name]
		switch d.Completion() {
		case ResponseValidated:
			if hasVerifier {
				return errors.New("secureops: read-only driver " + name + " must not carry a verifier")
			}
		case ExternalPostcondition:
			if !hasVerifier {
				return errors.New("secureops: state-changing driver " + name + " has no registered verifier")
			}
		default:
			return errors.New("secureops: driver " + name + " declares unknown completion mode")
		}
	}
	return nil
}

// FreezeRegistries validates and then prohibits further registration.
// Late registration (e.g. a plugin attaching after startup) is refused
// instead of silently changing the active completion contract.
func FreezeRegistries() error {
	if err := ValidateRegistries(); err != nil {
		return err
	}
	driversMu.Lock()
	frozen = true
	driversMu.Unlock()
	verifyMu.Lock()
	verifiersFrozen = true
	verifyMu.Unlock()
	return nil
}

// All returns every registered driver for capability discovery (G06).
func All() []OperationDriver {
	driversMu.RLock()
	defer driversMu.RUnlock()
	out := make([]OperationDriver, 0, len(drivers))
	for _, d := range drivers {
		out = append(out, d)
	}
	return out
}

// Names lists registered operations for catalog display.
func Names() []string {
	out := make([]string, 0, len(drivers))
	for n := range drivers {
		out = append(out, n)
	}
	return out
}

func nonEmpty(v, name string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("missing " + name)
	}
	return nil
}
