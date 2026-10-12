package credential

import (
	"errors"
)

// Injector is retained only as a compatibility shim. New code must use
// internal/secureops drivers invoked from the trusted executor
// (service.ExecuteUse), which enforce allowlisted operations, atomic claims,
// response-size limits and secret redaction.
//
// The old behavior (read a credential, report success without using it) was a
// synthetic placeholder and has been removed. Any direct use is rejected.
type Injector struct{}

func NewInjector() *Injector { return &Injector{} }

func (i *Injector) Inject(_, _ string, _ map[string]string) (map[string]string, error) {
	return nil, errors.New("credential.Injector is retired: use secureops drivers via service.ExecuteUse")
}

func (i *Injector) ExecuteAuthorized(_ interface{}) (map[string]interface{}, error) {
	return nil, errors.New("credential.Injector is retired: use secureops drivers via service.ExecuteUse")
}
