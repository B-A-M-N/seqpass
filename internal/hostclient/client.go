package hostclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/secretbridge/secretbridge/internal/harness"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

// TrustedClient is the shared protected-input transaction client (CORE-02).
// It is for trusted host adapters only. Agents must never receive one, and
// construction does not by itself prove isolation; assurance still comes
// from broker qualification/topology.
type TrustedClient struct {
	intake  *ipc.Client
	host    *ipc.Client
	session harness.HostSessionToken
}

// New binds the trusted intake and display-only host connections to one
// broker-registered session. Clients should stay connected only for the
// protected workflow.
func New(intake, host *ipc.Client, session harness.HostSessionToken) (*TrustedClient, error) {
	if intake == nil || host == nil {
		return nil, fmt.Errorf("trusted client requires intake and host connections")
	}
	if session.SessionID == "" || session.Token == "" {
		return nil, fmt.Errorf("trusted client requires a broker-registered host session")
	}
	return &TrustedClient{intake: intake, host: host, session: session}, nil
}

func (c *TrustedClient) hostParams(requestID string) map[string]interface{} {
	return map[string]interface{}{
		"session_id":    c.session.SessionID,
		"session_token": c.session.Token,
		"request_id":    requestID,
	}
}

// GetRequest fetches the versioned payload-free protected-input notice.
func (c *TrustedClient) GetRequest(requestID string) (harness.ProtectedInputNotice, error) {
	data, err := c.host.Call(ipc.MethodHostNotice, c.hostParams(requestID))
	if err != nil {
		return harness.ProtectedInputNotice{}, err
	}
	notice, err := decodeNotice(data)
	if err != nil {
		return harness.ProtectedInputNotice{}, err
	}
	if err := notice.Validate(); err != nil {
		return harness.ProtectedInputNotice{}, err
	}
	return notice, nil
}

// Fulfill submits the payload through the protected intake boundary using
// the exact reviewed revision. The credential is encoded only for the local
// trusted IPC frame and never returned or logged.
func (c *TrustedClient) Fulfill(requestID string, expectedRev uint64, payload []byte) error {
	if expectedRev == 0 {
		return fmt.Errorf("missing reviewed request revision")
	}
	if len(payload) == 0 || len(payload) > 64*1024 {
		return fmt.Errorf("payload must be 1..65536 bytes")
	}
	_, err := c.intake.Call(ipc.MethodIntakeFulfill, map[string]interface{}{
		"request_id":       requestID,
		"request_revision": expectedRev,
		"payload":          base64.StdEncoding.EncodeToString(payload),
	})
	return err
}

// Reject rejects the pending relay using the exact reviewed revision.
func (c *TrustedClient) Reject(requestID string, expectedRev uint64) error {
	if expectedRev == 0 {
		return fmt.Errorf("missing reviewed request revision")
	}
	_, err := c.intake.Call(ipc.MethodIntakeReject, map[string]interface{}{
		"request_id":       requestID,
		"request_revision": expectedRev,
	})
	return err
}

// DismissPrompt invokes the display-only host cancellation path. It does
// not fabricate relay cancellation when dispatch has started.
func (c *TrustedClient) DismissPrompt(requestID string) error {
	_, err := c.host.Call(ipc.MethodHostCancelPrompt, c.hostParams(requestID))
	return err
}

// GetStatus returns the sanitized relay outcome for the bound agent.
func (c *TrustedClient) GetStatus(requestID string) (harness.RelayStatus, error) {
	data, err := c.host.Call(ipc.MethodHostStatus, c.hostParams(requestID))
	if err != nil {
		return harness.RelayStatus{}, err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return harness.RelayStatus{}, err
	}
	var st harness.RelayStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return harness.RelayStatus{}, fmt.Errorf("invalid status encoding")
	}
	if st.RequestID != requestID {
		return harness.RelayStatus{}, fmt.Errorf("status request ID mismatch")
	}
	return st, nil
}

func decodeNotice(data interface{}) (harness.ProtectedInputNotice, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return harness.ProtectedInputNotice{}, err
	}
	var notice harness.ProtectedInputNotice
	if err := json.Unmarshal(raw, &notice); err != nil {
		return harness.ProtectedInputNotice{}, fmt.Errorf("invalid notice encoding")
	}
	return notice, nil
}
