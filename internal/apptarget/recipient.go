package apptarget

import (
	"fmt"
	"path/filepath"

	"github.com/secretbridge/secretbridge/internal/types"
)

// RecipientOptions are recipient-local values. They are loaded from protected
// registration by the capsule path or trusted receiver service, never from
// capsule payload fields.
type RecipientOptions struct {
	OpenCodeCommand  string
	CodexCommand     string
	CodexHome        string
	FIGatewaySocket  string
	FIGatewayPeerUID *uint32
}

// NewRecipientAdapter selects only a compiled-in adapter revision. Recipient
// filesystem paths and executable pins are supplied by trusted local wiring.
func NewRecipientAdapter(target types.AppCredentialTarget, home string, opts RecipientOptions) (Adapter, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	switch target.UpdateMethod {
	case OpenCodeAuthJSONV1, OpenCodeAuthImportV2:
		return NewOpenCodeAdapter(target, home, opts.OpenCodeCommand)
	case CodexAuthFileV1:
		codexHome := opts.CodexHome
		if codexHome == "" {
			codexHome = filepath.Join(home, ".codex")
		}
		adapter := CodexAuthFile{CommandPath: opts.CodexCommand, HomeDir: home, CodexHome: codexHome}
		if err := adapter.validate(); err != nil {
			return nil, fmt.Errorf("registered Codex adapter is not usable: %w", err)
		}
		return adapter, nil
	case FIGatewayCredentialManagerV1:
		adapter := FIGatewayCredentialManager{SocketPath: opts.FIGatewaySocket, ExpectedPeerUID: opts.FIGatewayPeerUID}
		if err := adapter.validate(); err != nil {
			return nil, fmt.Errorf("registered FI Gateway adapter is not usable: %w", err)
		}
		return adapter, nil
	default:
		return nil, fmt.Errorf("no recipient adapter is registered for the target")
	}
}
