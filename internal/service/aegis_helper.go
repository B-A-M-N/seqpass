package service

import (
	"context"
	"crypto"
	"fmt"

	"github.com/secretbridge/secretbridge/internal/aegiskeys"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/types"
)

// aegisResolved performs one credential resolution through the trusted
// helper executable (P0-1) and maps the result into the same contract the
// in-process path returns: binding echo check (C13, defense in depth) and
// the helper's typed sentinel errors surfaced unchanged.
//
// attestKey is the executor's (broker's) in-memory ed25519 key
// (hardened-parent attestation): every request is signed with a fresh
// nonce inside ResolvePinnedViaHelper; the dumpable helper carries the
// signature but never the key. nil sends an unattested request (AegisKeys
// grants without an attest pin).
//
// src carries the stable identity pins (P0-3): provisioned refs bind every
// resolve to the provider's record/binding identity, so a later rebind of
// the binding name cannot silently redirect an approved operation.
//
// The caller (resolveCredentialMaterial) has already validated the
// operation against the approved request; the helper carries the same
// triple hash-pinned by the approval, so a helper exchange cannot widen
// what was approved.
func aegisResolved(ctx context.Context, helperPath, socket string, src types.SecretSource, operation, opID string, attestKey *aegiskeys.ExecutorAttestKey) (secureops.Credential, error) {
	var signer crypto.Signer
	if attestKey != nil {
		signer = attestKey.Private
	}
	mat, err := aegiskeys.ResolvePinnedViaHelper(ctx, helperPath, socket, aegiskeys.ResolvePinFromSource(src.Binding, src.BindingID, src.RecordID, operation, opID), signer)
	if err != nil {
		return secureops.Credential{}, err
	}
	respRef := mat.Binding
	wantRef := src.Binding
	if wantRef == "" {
		wantRef = src.BindingID
	}
	if respRef != wantRef {
		return secureops.Credential{}, fmt.Errorf("binding identity mismatch: requested %q, resolved %q", wantRef, respRef)
	}
	return secureops.Credential{Value: mat.Value, Components: mat.Components}, nil
}
