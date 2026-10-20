package service

import (
	"context"
	"fmt"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/secureops"
)

// aegisResolved performs one credential resolution through the trusted
// helper executable (P0-1) and maps the result into the same contract the
// in-process path returns: binding echo check (C13, defense in depth) and
// the helper's typed sentinel errors surfaced unchanged.
//
// The caller (resolveCredentialMaterial) has already validated the
// operation against the approved request; the helper carries the same
// triple hash-pinned by the approval, so a helper exchange cannot widen
// what was approved.
func aegisResolved(ctx context.Context, helperPath, socket, binding, operation, opID string) (secureops.Credential, error) {
	mat, err := aegiskeys.ResolveViaHelper(ctx, helperPath, socket, binding, operation, opID)
	if err != nil {
		return secureops.Credential{}, err
	}
	if mat.Binding != binding {
		return secureops.Credential{}, fmt.Errorf("binding identity mismatch: requested %q, resolved %q", binding, mat.Binding)
	}
	return secureops.Credential{Value: mat.Value, Components: mat.Components}, nil
}
