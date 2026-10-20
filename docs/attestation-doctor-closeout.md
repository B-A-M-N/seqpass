# External review item 6 — closeout: attestation health division of labor

Item 6 asked: "who owns the follow-up when hardened attestation is
misconfigured?" This note records the final division, accepted by both
implementations, so operators know exactly which component to consult.

## The two responsibilities

**AegisKeys owns grant enumeration — `diagnoseHardenedAttestation`**
(`internal/broker/provision_doctor.go`). When an operator asks the broker
for an attestation health report, AegisKeys enumerates every
attest-key-pinned grant and fails the diagnosis when the pin set is
inconsistent (e.g. mixed signed/unsigned grants targeting the same
consumer). This is the authoritative answer to "is my attestation
configuration coherent?" because only the broker holds the grant table.

**SeqPass owns key-material enforcement on its side:**

1. **Key material is always present in helper mode.** When
   `--aegiskeys-resolve-helper` is configured, the daemon ALWAYS holds an
   in-memory ed25519 attest key — derived from the provisioned seed when
   `--aegiskeys-attest-seed` is set, generated fresh otherwise
   (`daemon.go`: key derivation is not optional in helper mode) — and
   signs every resolve. Whether the operator's grant set actually PINS
   that key (and whether the pin set is coherent, i.e. no mixed
   signed/unsigned grants for the same consumer) is AegisKeys'
   `diagnoseHardenedAttestation` domain: SeqPass supplies the signature,
   the provider's grant contract enforces the pin.
2. **Rotation surfacing.** The broker persists the attest public half in
   `broker_state` (schema v5). A start with a fresh key while the
   persisted public half exists marks `AttestRotationPending()`; the
   admin surface and audit log surface it, and resolves under a
   rotated-out key fail closed at the provider (the grant pins the OLD
   key — an approved operation can never silently resolve with a new,
   unpinned key).
3. **Stable-seed mode.** `--aegiskeys-attest-seed` (systemd
   `LoadCredentialEncrypted`) derives the same key across restarts:
   `LoadAttestSeedFile` refuses symlinks, group/world-readable files,
   non-root/non-broker owners, and wrong-size seeds; the seed is read
   once at startup and the key pair exists only in non-dumpable memory.

## Why this split

The grant table (which grants pin which keys, and whether that set is
coherent) exists only in AegisKeys — SeqPass cannot enumerate it without
duplicating broker state and creating a second source of truth. The key
MATERIAL and its lifecycle (rotation detection, seed continuity, memory
posture) exist only in SeqPass — AegisKeys cannot observe the executor's
in-memory key or its startup configuration. Each component validates the
layer it actually holds; the boundary is the resolve request itself,
whose attestation signature is verified by exactly one party (the
provider's grant pin) against exactly one signer (the executor's key).

## Operator follow-up procedure

- `AegisKeys` reports `diagnoseHardenedAttestation` failures → fix the
  grant set in AegisKeys (re-stage the grant with the correct
  `attest_key` from `seqpass admin attest_public`).
- SeqPass reports rotation pending (`AttestRotationPending()`) → either
  restart with the SAME seed (`--aegiskeys-attest-seed`) to restore the
  original key, or re-pin the grants in AegisKeys with the new public
  half. Until one of these happens, provisioned resolves fail closed.
- Provisioning (`/v3/intake`) rides the same helper + attestation
  crossing; `diagnoseHardenedAttestation` covers PROVISIONING grants
  exactly as it covers resolve grants.
