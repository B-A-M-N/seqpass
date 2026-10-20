# Privileged cross-broker qualification

The ordinary `go test ./qual` suite exercises real SeqPass broker, IPC,
recipient, CLI, and MCP processes with synthetic fixtures. It runs under one
OS identity and does not prove multi-UID isolation or a real AegisKeys grant.
`TestQualPrivileged` has an opt-in Linux process-boundary tier. That tier can
prove that the real SeqPass broker reports `isolated`, a distinct agent UID can
use only the agent socket, and the agent cannot connect to live trusted sockets
or read protected files. It also runs the real MCP adapter under the agent UID,
creates a relay request, fulfills it through trusted intake under the service
UID, and observes durable recipient acceptance without disclosing the
synthetic value through MCP, process metadata/memory, logs, or broker receipts.
`TestQualPrivilegedSyntheticUse` (below) additionally runs the credentialed
scenarios against protocol-faithful in-process mocks of AegisKeys and the
consuming provider. A real AegisKeys deployment is still required before any
cross-broker interop claim, and a full AI-blind claim still requires a
protected live run.

## Executable process-boundary tier

Run this only in a disposable Linux VM with root access. Use dedicated,
non-root service and agent accounts, a dedicated agent socket group, a live
AegisKeys broker configured for the service account, and a fresh protected
qualification artifact directory. The existing AegisKeys vault and metadata
are inspected for access denial but are never modified. The test creates its
SeqPass database and socket directories under a disposable `/tmp` tree and
removes them at completion.

The agent account must be a member of the configured socket group and must not
be the service account. The service account must have whatever group access the
AegisKeys socket requires. The test uses the account database to configure
supplementary groups; it does not create or change users or groups.

Set the following environment and run the one test:

```sh
export SEQPASS_QUAL_PRIVILEGED=1
export SEQPASS_QUAL_SERVICE_UID='<dedicated SeqPass/AegisKeys service UID>'
export SEQPASS_QUAL_AGENT_UID='<dedicated untrusted agent UID>'
export SEQPASS_QUAL_AGENT_GROUP='<agent socket group name>'
export SEQPASS_QUAL_AEGISKEYS_SOCKET='/run/aegiskeys/broker.sock'
export SEQPASS_QUAL_AEGISKEYS_VAULT='/secure/aegiskeys/vault.enc'
export SEQPASS_QUAL_AEGISKEYS_METADATA='/secure/aegiskeys/broker.json'
export SEQPASS_QUAL_AEGISKEYS_REV='<full 40-character AegisKeys Git revision used by this deployment>'
export SEQPASS_QUAL_ARTIFACT_DIR='/secure/qualification-evidence'
go test ./qual -run '^TestQualPrivileged$' -count=1 -v
```

Optional `SEQPASS_QUAL_AEGISKEYS_DIR` is passed to the broker when that
installation needs an explicit config directory. The artifact directory must
already exist, be owned by the test UID, and have mode 0700 or tighter. The
test writes its manifest and captured broker output with mode 0600. It records
the PID, UID, executable hash, and available build metadata of the process
accepting the AegisKeys socket. Never use a production credential for a full
credentialed qualification.

A process-boundary pass requires all three admin, intake, and AegisKeys
sockets to be live before checking agent denial. It also checks the socket
owner/group/modes, the protected state directory, the SeqPass database, and the
agent's observed UID and group membership. The test then starts an actual MCP
stdio child as the agent UID, requests a relay to a pinned local recipient,
and fulfills it from the trusted service UID through the intake socket. A
random synthetic value is staged in a mode-0600 service-owned file; the agent
must receive EACCES/EPERM for that path. The independent harness checks the
recipient's persisted bytes and scans the live agent's readable `/proc` memory
maps, argv, environment, MCP responses, broker output, and SeqPass database/WAL
for the value. If `/proc/<pid>/mem` cannot be read, memory observation is
recorded as blocked and cannot support a strict isolation claim. The value is
retained only as a SHA-256 digest in the manifest. A failure is recorded as
`failed`; missing identities, paths, or listeners are `blocked`.

## Synthetic AegisKeys credential tier

`TestQualPrivilegedSyntheticUse` (opt-in with the same
`SEQPASS_QUAL_PRIVILEGED=1`) runs the credentialed scenarios in any
disposable multi-UID Linux lab without a real AegisKeys installation. It
starts two stdlib in-process fixtures: an AegisKeys mock that serves the
same HTTP-over-Unix `/v1/status` and `/v2/resolve` contract (rotating the
synthetic value once after the first authorized resolve and logging
binding identities — never values), and a real credential-consuming
provider on loopback TCP that admits only the currently authorized bearer
value, rejects rotated-away values with 401, and echoes the credential
both literally and JSON-escaped so the closed response projection must
drop them. The mock socket and its vault/metadata files are root-owned
with the service group only, so the kernel denies the agent exactly as in
a live topology.

The tier launches the real broker under the dedicated service UID with
`--vault aegiskeys --aegiskeys-socket <mock> --assurance isolated`,
registers the secret ref, pinned provider origin, and a scoped
`no_approval` policy through the trusted admin IPC under the service UID,
then drives the real MCP adapter under the agent UID through:
`secret_catalog` discovery, one authorized `http.request` use executed by
the trusted admin surface, an unauthorized `process.run` submission, a
second authorized use after rotation, and a resubmission after the policy
is disabled. It records: provider receipt of the exact current bearer
value, exactly-one/authorized-only resolve counts, echo-field rejection,
credential absence from MCP traffic, agent argv/environ/memory, broker
logs, and the SeqPass database/WAL (digests only in the manifest), plus
kernel denials for the agent on trusted sockets and protected files.
Scenario aggregates are recorded under their PRIVILEGED scenario names
(`authorized-credentialed-read`, `adversarial-credential-echo`,
`unauthorized-operation`, `credential-rotation`, `revocation-barrier`);
the remaining scenarios stay `not_exercised` and still require a live
deployment run. Post-dispatch revocation (in-flight semantics), lost
acknowledgment, restart, and config overlay are not covered by this tier.

```sh
export SEQPASS_QUAL_PRIVILEGED=1
export SEQPASS_QUAL_SERVICE_UID='<dedicated SeqPass service UID>'
export SEQPASS_QUAL_AGENT_UID='<dedicated untrusted agent UID>'
export SEQPASS_QUAL_AGENT_GROUP='<agent socket group name>'
export SEQPASS_QUAL_ARTIFACT_DIR='/secure/qualification-evidence'
go test ./qual -run '^TestQualPrivilegedSyntheticUse$' -count=1 -v
```

The agent UID must not be a member of the service account's primary
group: the mock AegisKeys socket is isolated through that group, and the
tier refuses to run (blocked, not failed) when the groups overlap, rather
than under-check the boundary. The fixture itself is unit-validated
without root by `TestMockUpstreamContract`, including negative controls
for vault-to-credential binding and post-rotation rejection.

## Full cross-broker tier still required

Beyond the protected relay scenario exercised by the process-boundary tier,
the scenarios below remain `not_exercised`. Run them separately in the
disposable lab using a fresh AegisKeys test vault, a
synthetic non-production credential, and a local mock provider/recipient that
records requests independently. Provision a binding and grant only the
SeqPass executor identity `broker_resolve`, enable the corresponding secret
policy, and configure one allowlisted read operation plus one pinned Unix
socket recipient. The mock provider must echo the test credential both
literally and as JSON escapes. Do not record the credential value; use only a
cryptographic digest in retained evidence.

Retain a mode-0600 JSON record under `SEQPASS_QUAL_ARTIFACT_DIR` (or an
equivalent protected evidence directory). Record exact AegisKeys and SeqPass
revisions, binary hashes, Go versions, kernel/architecture, UID/GID and
supplementary-group map, socket paths/modes/owners, assurance mode, a digest of
the synthetic credential, and each scenario's expected and observed result.
Keep observer output and service logs access-controlled. Search them for the
test credential before accepting a run. Never put raw credentials, bearer
headers, or credential-bearing requests in the record.

### Credential-resolution helper (P0-1) — live-tier requirements

The live tier must run the broker with
`--aegiskeys-resolve-helper /usr/local/bin/seqpass` (the AegisKeys grant must
be pinned to that executable). Verify in the live run:

1. Broker self-resolve is refused at the peer-identity layer
   (`PR_SET_DUMPABLE=0`): the lab finding must reproduce against the live
   broker without the helper configured (proven negative control).
2. With the helper configured, an authorized op resolves through the helper:
   AegisKeys audit shows the resolving pid = helper child of the broker, exe =
   the pinned `seqpass` path.
3. Impersonation: an agent UID invoking `seqpass resolve-helper` directly is
   denied on grant UID mismatch (no credential, no audit resolve).
4. Grant drift: rotating the AegisKeys grant hash (or path) denies the helper
   until re-pinned — proving the identity is actually pinned, not merely
   path-checked.
5. Crash posture: `kill -ABRT` on a mid-resolve helper produces no core file
   (`RLIMIT_CORE=0`) while the broker stays non-dumpable.

| Scenario | Required observation |
| --- | --- |
| Authorized credentialed read | Correct mock response reaches the agent; exact credential absent from MCP input/output, process-readable agent files, receipts, logs, and status. |
| Direct access denial | Agent cannot connect to AegisKeys, admin, or trusted-intake sockets or read protected backing files; it can reach the configured agent socket. |
| Unauthorized operation | No provider request and no AegisKeys resolve occurs. |
| Revocation barrier | Revocation committed before dispatch prevents the provider request; post-dispatch revocation is recorded as in-flight. |
| Rotation | Next authorized resolution uses the rotated value; the mock provider rejects the prior value. |
| Concurrent consumers | Independent operations complete without cross-operation value mix-up or deadlock. |
| Lost acknowledgment | Operation becomes uncertain; independent recipient readback reconciles it without automatic replay. |
| Restart | Durable evidence remains truthful; in-memory relay payload is unavailable after restart and never reconstructed. |
| Adversarial echo | Literal and JSON-escaped credential echoes are rejected before receipt persistence or agent publication. |
| Config overlay | Overlapping launches restore the baseline unless an external edit is detected and preserved. |

Any missing scenario remains `blocked` or `not_exercised`, never `passed`. A
strict AI-blind claim requires zero credential disclosures and zero
unauthorized dispatches across the full run, plus independent review of socket,
file, executable, and group permissions. The result applies only to the exact
recorded revisions and topology.

## Failure correction record

Retained qualification artifacts are append-only evidence. Never edit an old
manifest to turn a failed or contradicted case into a pass. A new
counterexample invalidates earlier passing evidence for that claim until a
corrected revision passes a fresh run with the negative control retained.
For each material correction, keep a companion record linking the prior
artifact and falsifying scenario to the expected and observed behavior, the
authority or contract changed, correction scope, collateral-effect tests,
independent re-verification, and the supported revision/topology envelope.
Record an unavailable independent review as unavailable instead of inferring
it from a green local test suite.

## Current evidence

The executable boundary and protected-relay harness is implemented, and the
synthetic AegisKeys credential tier is implemented and unit-validated at the
fixture level (`TestMockUpstreamContract`, including negative controls), but no
dedicated-UID live run has been performed in the current workspace. The full
cross-broker scenarios against a real AegisKeys deployment remain unverified
until a protected run record passes every remaining scenario above.
