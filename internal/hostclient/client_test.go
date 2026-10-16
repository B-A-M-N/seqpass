package hostclient_test

import (
	"testing"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/hostclient"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

func TestTrustedClientRequiresSession(t *testing.T) {
	if _, err := hostclient.New(nil, nil, harness.HostSessionToken{}); err == nil {
		t.Fatal("empty client accepted")
	}
	if _, err := hostclient.New(&ipc.Client{}, &ipc.Client{}, harness.HostSessionToken{}); err == nil {
		t.Fatal("empty host session accepted")
	}
}

func TestTrustedClientMatchesProtectedTransactionShape(t *testing.T) {
	var _ harness.ProtectedInputTransaction = (*hostclient.TrustedClient)(nil)
}
