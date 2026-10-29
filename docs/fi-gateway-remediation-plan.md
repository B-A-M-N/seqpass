# FI Gateway credential receiver remediation plan

This plan is based on the operator-provided adversarial rereview. The gateway
working tree is intentionally outside this SeqPass change: its current files,
diff, and build have not been independently inspected here. A gateway owner
must first verify each premise against the current gateway source before
applying the plan.

## P0: fail-closed target authorization

**Files:** `gateway/credentials/recipient.py`, `gateway/fi_gateway.py`, and
`test_gateway_credentials_recipient.py`.

1. Resolve receiver enablement and target configuration as one immutable
   startup policy. If the credential receiver is enabled, require a nonempty
   `FI_GW_CREDENTIAL_TARGETS` (or its approved replacement) value. Missing,
   whitespace-only, malformed, duplicate, or ambiguous entries must abort
   receiver startup before the socket is published.
2. Parse each entry into a canonical `target_id`, provider, account, and slot.
   Reuse the gateway manager's provider/account validators. Reject unknown
   slots and any `target_id` that does not encode the exact same tuple.
3. Require every request to name a registered target ID. Resolve provider,
   account, slot, and enabled state from the receiver's immutable trusted
   policy. Treat request provider/account fields only as consistency checks;
   never as authority. Reject cross-account, cross-provider, disabled,
   unknown, or modified targets before calling either `install_active()` or
   `active_matches()`.
4. Remove the production unrestricted mode. If tests need it, expose a
   test-only constructor that cannot be selected from production environment
   variables or CLI configuration.
5. Test receiver startup refusal for missing and malformed policy, duplicate
   target rejection, and zero manager mutations for every target mismatch.

## P0: durable operation claim and monotonic target ordering

**Files:** `gateway/credentials/manager.py`, `gateway/credentials/store.py`,
the durable store implementation, and `test_gateway_credentials_recipient.py`.

1. Extend the durable store transaction boundary to claim an operation before
   any credential write. A record binds issuer identity, operation ID, target
   ID, expected predecessor generation, target generation, keyed payload
   commitment, state, and eventual result metadata. Never store plaintext or
   a public unkeyed hash of a low-entropy credential.
2. Use database-level serialization such as `BEGIN IMMEDIATE` plus unique and
   compare-and-swap constraints. A manager object's `RLock` is only an
   in-process optimization and cannot authorize writes across processes.
3. Apply the credential only after the claim commits. Record `applying` before
   promotion and `applied` after the target generation is confirmed. A matching
   completed duplicate returns its recorded outcome without another install;
   a conflicting duplicate is refused. An interrupted `applying` operation
   becomes `uncertain` and must reconcile by inspecting the exact target.
4. Make promotion conditional on the target's expected predecessor generation.
   Every authorized update carries a monotonic generation/order token bound by
   SeqPass authorization. Reject a late operation whose predecessor is stale,
   even when its operation ID and payload were valid when first issued.
   Define and document how that token is allocated so request arrival order
   cannot decide which approved rotation wins.
5. Retain credential-manager versioning, active selection, and in-flight lease
   semantics. Operation identity controls whether mutation is authorized;
   the manager remains responsible for selecting and serving the credential.

## Required gateway tests

Use temporary durable stores and synthetic values only.

- Same operation ID and same target/payload is idempotent after restart.
- Same operation ID with changed payload or target is rejected without writes.
- A then B then replay A leaves B active, including after restart.
- A stale distinct operation is rejected after a newer target generation.
- Crash after claim, after secret persistence, after activation, and before ACK
  recovers to a single authoritative result without an unintended reinstall.
- Two independently started receiver processes contending for one target
  serialize through the durable store; exactly one generation transition wins.
- Missing, corrupt, or unavailable durable storage fails closed and never
  falls back to an in-memory manager or stale environment credential.

## P1: durable routing, backend reload, and receiver lifetime

**Files:** `gateway/credentials/runtime_store.py`,
`gateway/runtime/composition.py`, `gateway/runtime/coordinator.py`, and
`test_gateway_credentials_recipient.py`.

1. Test against the configured encrypted-file or OS-keyring backend, not only
   `MemoryCredentialStore`: install synthetic A, restart and route A; rotate
   to B, restart and route B; confirm A is never selected again.
2. Send a real gateway request to a local mock upstream that rejects A and
   accepts B. Assert the request uses the exact registered provider/account
   target and that only B reaches the mock. This proves `routing_verified`,
   not acceptance by a real upstream provider.
3. Test backend unavailable, corrupt key material, and failed startup. Each
   case must refuse managed-credential service rather than silently switching
   backends or using an environment key.
4. Compute an immutable backend identity from enabled state, store directory,
   and secret-backend configuration. On reload, reject incompatible changes
   or run an explicit migration. Do not report new settings active while
   retaining an old manager.
5. Bind receiver socket lifetime and target policy to the same runtime
   generation. On shutdown, unlink only the socket inode created by that
   receiver; a replacement path belonging to another process must survive.

## P2: request resource bounds and audit output

**File:** `gateway/credentials/recipient.py`.

- Bound concurrent handlers and outstanding requests; reject overload without
  blocking ordinary routing.
- Retain request-size, timeout, malformed-message, and peer-credential checks.
- Return generic client errors while logging bounded categories such as
  `unauthorized_peer`, `unknown_target`, `operation_conflict`,
  `stale_generation`, and `storage_failure`. Logs must omit request bodies,
  credentials, fingerprints, and secret-derived values.
- Remove the credential fingerprint from the socket response unless a
  concrete caller requires it; prefer a non-secret opaque generation ID.
- Test slow clients, connection exhaustion, stale policy generation, and
  shutdown/restart socket replacement behavior.

## Integrated acceptance gate

The gateway owner should run the gateway recipient and routing suites, the
cross-process crash/replay matrix, and the durable restart/mock-upstream test.
Then run the isolated three-identity SeqPass capsule qualification and confirm
the exact SeqPass snapshot and gateway source revision. A green SeqPass suite
does not close any gateway gate. Keep unavailable or skipped checks explicitly
unqualified; do not deploy or push as part of this remediation.
