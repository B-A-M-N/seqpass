// Package apptarget installs credentials only at a locally configured,
// registered application target. Transport metadata never chooses a path.
package apptarget

import (
	"context"
	"errors"
	"fmt"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

var ErrTargetMismatch = errors.New("delivery does not match the locally registered application target")

type Adapter interface {
	App() string
	Apply(context.Context, types.AppCredentialTarget, string, []byte) (transfer.Committed, error)
	Reconcile(context.Context, types.AppCredentialTarget, string, []byte) (transfer.Committed, error)
}

// TransferCommitter is bound to one recipient-local target. The caller must
// construct it from trusted local configuration, never from agent parameters.
type TransferCommitter struct {
	Target  types.AppCredentialTarget
	Adapter Adapter
}

func (c *TransferCommitter) Commit(ctx context.Context, d transfer.Delivery) (transfer.Committed, error) {
	if err := c.validate(d); err != nil {
		return transfer.Committed{}, err
	}
	return c.Adapter.Apply(ctx, c.Target, d.OperationID, d.Payload)
}

func (c *TransferCommitter) Reconcile(ctx context.Context, d transfer.Delivery) (transfer.Committed, error) {
	if err := c.validate(d); err != nil {
		return transfer.Committed{}, err
	}
	return c.Adapter.Reconcile(ctx, c.Target, d.OperationID, d.Payload)
}

func (c *TransferCommitter) validate(d transfer.Delivery) error {
	if c == nil || c.Adapter == nil || d.Target == nil || d.DataKind != "api_key" || len(d.Payload) == 0 || c.Adapter.App() != c.Target.App || *d.Target != c.Target {
		return ErrTargetMismatch
	}
	if c.Target.ID == "" || c.Target.SourceRef == "" || c.Target.SourceRevision <= 0 || c.Target.UpdateMethod == "" {
		return fmt.Errorf("%w: incomplete target registration", ErrTargetMismatch)
	}
	return nil
}
