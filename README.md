# SeqPass

Agent-agnostic secret broker for native coding-harness integration. In the
`isolated` Linux topology, agents run under separate UIDs and the broker
keeps credential material outside those process identities. Same-user
`best-effort` deployments do not provide that isolation guarantee.

- **Mode A (credential use):** broker executes an allowlisted operation with a
  credential resolved from AegisKeys, returns sanitized DTOs + receipt.
- **Mode B (blind transfer):** broker delivers sensitive data directly to a
  trusted recipient socket. Agent sees receipt + destination + status only.
  Production transfers resolve AegisKeys bindings (default value or one
  explicit `component:<name>` selector. Resolve v2 matches logical AegisKeys
  component keys; the backward-compatible v1 fallback matches response-map
  keys, historically component environment-variable names. Unbound
  ephemeral payloads are a `memory-test --dev` fixture only and are rejected
  under `--vault aegiskeys`. Resolution follows rotation (latest authorized
  value of the approved binding); pinned-version semantics are not claimed.

## Architecture

```
harness (Codex / Claude / Hermes)
  └─ `seqpass mcp` (MCP stdio adapter, untrusted: no vault, no DB)
       └─ Unix socket IPC (peer-credential principals)
            └─ `seqpass broker` (privileged: policy, AegisKeys resolve, execution)
                 └─ AegisKeys broker socket (authoritative encrypted vault)
```

## Implementation status

| Capability | Status | Evidence |
|-----------|--------|----------|
| Broker core (operations, policy, destinations, approval) | Implemented, tested | `go test ./...` |
| Unix-socket IPC domains (agent / admin / intake / host) | Implemented, tested | IPC tests + socket tests |
| Relay workflow (request → review → fulfill → dispatch) | Implemented, tested | Service + integration tests |
| Administrative host-binding RPC | Implemented, tested | `internal/ipc/hostbinding_rpc_test.go` |
| Host-session registration + revocation lifecycle | Implemented, tested | `internal/service/hostsession_test.go` |
| Relay worker (bounded, deadline-priority) | Implemented, tested | `internal/service/relay_test.go` |
| Transactional quota enforcement | Implemented, tested | `internal/metadata/relay.go` |
| OpenCode adapter (trusted host + agent domain) | Type-checked, unit-tested | `bun x tsc --noEmit` + `bun x vitest run` |
| Pi adapter (trusted host + agent domain) | Type-checked, unit-tested | `bun x tsc --noEmit` + `bun x vitest run` |
| **Native protected-input isolation** | **Not yet production-qualified** | Requires live multi-UID topology + AegisKeys qualification |
| **AegisKeys production resolution** | **Not yet production-qualified** | Requires live dedicated-UID grant + rotation tests |
| Recipient durability contract | Implemented, tested | `internal/transfer/recipient_test.go` + `recipient_server_test.go` |
| Real credential consumer (`SecretConsumer`) | Implemented, tested | `internal/transfer/consumer.go` + `internal/service/real_consumer_test.go` (delivery → commit → verified `applied`) |
| Credentialed operations (`http.request`, `process.run`, `git.fetch`, `git.push` pinned profiles) | Implemented, tested | `internal/secureops/` — pinned executables/origins/remotes/sources, credential never in argv/env/URL/DTO (fd-injected; mutation-tested negative controls). `git.push` pushes a branch of the operator-pinned source repository to the operator-pinned remote; no `--force`, the agent supplies only the branch |
| Generic agent adapter (MCP + CLI) | Implemented, tested | `internal/adapter/` + `cmd/seqpass/agent.go` |
| Versioned adapter contract (`protocol_version`, sealed frames) | Implemented, tested | `internal/adapter/protocol.go` (`Seal`/`Unseal` refuse unknown versions) |
| Adapter host-version qualification (register-time detection, incompatible-major refusal) | Implemented, tested | `integrations/opencode/index.ts` + `integrations/pi/client.ts`, vitest suites |
| `seqpass install <adapter>` (endpoints-only adapter config) | Implemented, tested | `cmd/seqpass/install.go` (no credentials/session tokens in snippets; `--force` overwrite guard) |
| Installation-wide config (`/etc/seqpass/config.json`, `/run/seqpass`, `/var/lib/seqpass`) | Implemented, tested | `internal/config/config.go` loader (fail-closed on malformed config; dev home-dir fallback unchanged) |
| Live isolation boundary check + drift revocation | Implemented, tested | `internal/isolation/` + `internal/daemon/isolation_test.go` |
| `seqpass recipient` (deployable consumer endpoint) | Implemented, tested | `cmd/seqpass/recipient.go` |
| **Recipient live-socket integration** | **Not yet production-qualified** | Requires real recipient process + privileged Unix-socket topology |
| **Multi-UID isolation qualification (G2–G8)** | **Not yet production-qualified** | Requires separate agent/operator/broker/recipient UIDs; see `qual/PRIVILEGED.md` |

A capability is **implemented** when code exists and tests pass. A capability
is **production-qualified** only after the required live deployment,
credential, and isolation evidence has been independently verified.

No HTTP listener, no browser UI, no TCP port. Approvals happen in the
operator's trusted terminal (`seqpass admin`); agents observe approval state
from inside the harness via `secret_status`.

## Build

```bash
go build -o seqpass ./cmd/seqpass
```

## Run

```bash
# 1. Development or local single-user setup (best-effort only).
#    best-effort is development-only and is always reported as unverified;
#    a production vault refuses it outright, so development uses the
#    ephemeral memory vault and must opt in with --dev:
# ./seqpass broker --vault memory-test --dev --assurance best-effort
#
# Production topology: broker and AegisKeys use a dedicated service UID;
# each agent runs as a different UID. The trusted terminal/admin CLI runs as
# the service UID because the admin and intake sockets are owner-only.
# --vault is required: aegiskeys for production. A production vault defaults
# to --assurance isolated and refuses to start unless the live boundary
# check passes.
sudo -u seqpass ./seqpass broker --vault aegiskeys --assurance isolated \
  --socket /run/seqpass/agents/broker.sock \
  --admin-socket /run/seqpass/admin/broker.sock \
  --intake-socket /run/seqpass/intake/broker.sock \
  --admin-uid $(id -u seqpass) --intake-uid $(id -u seqpass) \
  --agent-uid 2001,2002 --socket-group seqpass-agents
# Optional: --auto-execute runs the trusted worker that executes authorized
# ops without manual `admin execute` (approval still required).

# 2. Register the harness adapter (Codex)
codex mcp add seqpass -- /usr/local/bin/seqpass mcp
# Or generate adapter configuration with the install command (endpoints
# only — never credentials or session tokens; tokens are minted by
# host.register at runtime):
# ./seqpass install mcp --print        # exact MCP server registration stanza
# ./seqpass install opencode --out <plugin-config> --intake-socket ... --host-socket ...
# ./seqpass install pi --out <extension-config> --intake-socket ... --host-socket ... --agent-socket ...
# Claude Code
claude mcp add --scope user seqpass -- /usr/local/bin/seqpass mcp
# Hermes (~/.hermes/config.yaml): mcp_servers.seqpass.command=/usr/local/bin/seqpass,
# args=[mcp --socket /run/seqpass/agents/broker.sock],
# tools.include=[relay_request relay_status secret_catalog secret_use secret_transfer secret_status]
# No credential travels in this config. The MCP adapter returns an opaque ID;
# a trusted terminal runs `seqpass relay fulfill` to supply values.

# 3. Operator terminal: register, approve, execute
./seqpass admin add-secret --name github/staging --binding inference/staging
# Dev-mode bounded intake only (memory-test): production payloads live in AegisKeys.
./seqpass admin add-secret --name intake/demo && ./seqpass admin stage-secret --ref <ref-id> --file ./payload.bin
./seqpass admin add-dest --name runner --type recipient-socket --endpoint /run/trusted/recipient.sock --expect-uid 3001
./seqpass admin add-policy --name team --rules '[{"principal":"uid:2001","secret_refs":["<ref>"],"ops":["transfer"],"dest_ids":["<dest>"]}]'
./seqpass admin pending
./seqpass admin approve --type transfer --id <op-id>
./seqpass admin execute --type transfer --id <op-id>
./seqpass admin verify --type transfer --id <op-id>   # independent postcondition check (SC-14)
./seqpass admin set-policy --id <pol> --enabled false   # revokes outstanding approvals
./seqpass admin update-dest --id <dest> --endpoint /run/trusted/new.sock  # invalidates approvals
./seqpass admin update-dest --id <dest> --endpoint /run/trusted/new.sock --expect-uid 3002  # re-pin identity

# 4. Health (no secrets)
./seqpass status
```

## Secure handoff (relay): trusted terminal intake

The relay is the primary product flow. The agent decides it needs a
sensitive value; the user supplies it through a trusted path; SeqPass
delivers it to the registered recipient; the agent gets status only.

```bash
# Agent (inside Claude Code / Codex / Hermes) calls relay_request:
# { destination_id, data_kind: password|one_time_code|api_key|token|pin|text,
#   purpose, ttl_seconds } -> { request_id, awaiting_user }
# The MCP adapter returns only an opaque request ID and instructions.
# It never opens a native elicitation form or handles plaintext. The value
# enters through the trusted terminal below, outside the agent process.

# User (own terminal session, never the agent's terminal):
./seqpass tui                               # persistent native inbox TUI (preferred)
./seqpass relay inbox                       # pending requests, verified fields
./seqpass relay fulfill <request-id>        # review recipient/action/expiry,
                                            # enter value hidden, confirm, authorize
./seqpass relay status <request-id>         # delivered / uncertain / ...
./seqpass relay cancel <request-id>         # withdraw

# User-initiated (no agent request needed; one trusted interaction,
# intake socket only — needs no agent IPC privileges):
./seqpass relay request --to <dest> --kind password --ttl 90s [--file ./secret]

# Broker serves three sockets: agent (harness), admin (operator), and
# intake (human value-release, owner-only by default, separate UID
# allowlist via --intake-uid defaulting to admin UIDs; --intake-group
# opts a distinct-user deployment into a group-accessible intake socket,
# never the agent group, never world-accessible).
#
# Three capabilities: quick relay (single-use handoff), reusable
# reference (bounded/concurrent deliveries until expiry), and authorized
# operation execution. Agent requests create SINGLE-USE relays only;
# reusable/bounded grants need an explicit trusted-user choice.
# Recipient acknowledgment attests durable acceptance by the pinned
# recipient process — not proof of downstream task completion.
# Fulfilled quick relays dispatch from the default broker-managed relay
# queue (no --auto-execute needed); disable with --no-relay-auto-deliver.
```

### Native host presentation (HI-02/HI-03/HI-05/HI-07)

SeqPass separates the agent control plane from host presentation. The
optional `--host-socket PATH` enables a display-only native-host
presentation domain. A trusted host adapter registers over the protected
intake trust boundary with `host.register`, receives a broker-minted
session token, and can then call only `host.event`, `host.notice`,
`host.review`, and `host.cancel_prompt`.
Those methods return broker-verified public metadata and a versioned
protected-input notice; they cannot fulfill or reject a relay.

A host-native secure-input mode is not enabled by this socket. Registration
negotiates the host kind and non-secret capability flags (`presentation`,
`input_transport`, `supports_resume`, `supports_cancel_prompt`, and
`supports_multiple_pending`); the broker always normalizes
`credential_form_via_mcp=false`. Capability flags describe UI support, not
security. A native input requires a version-, adapter-, topology- and
security-configuration-bound qualification record
(`harness.AdapterQualification`), and the default classification remains
`model_blind`/`external_tty` until all terminal, process/tool and transcript
boundaries are verified. Purpose text is untrusted annotation; only
broker-rendered `trusted_host_render` review DTOs may initiate protected
input.

Known broker host kinds are `codex`, `opencode`, `pi`, `jcode`,
`qwen-code`, `claude-code`, and `agy` (plus `generic` for legacy adapters).



Lifecycle: a pending relay survives an adapter restart until its own
deadline; host disconnection is only a display-state hint, not user
rejection. A host adapter may withdraw a still-pending prompt with
`host.cancel_prompt`; once dispatch has started, the broker returns
`prompt_cancelled=false` and preserves the uncertain/reconciled outcome
rather than fabricating a final result.

Relay guarantees: the grant binds exact agent + recipient (+ live
config) + purpose + deadline + delivery budget, without creating a
permanent policy and without bumping the global epoch; single-use
values admit exactly one delivery (concurrent racers converge, the
loser fails closed); reusable grants serve concurrent apps through the
bounded worker pool; expiry/revocation/restart (payloads are memory-
only) all read truthfully and can never start a new dispatch; receipts,
audit, status and the SQLite file never contain plaintext.

Identity caveat: intake authorizes by UID and the socket is owner-only.
`best-effort` supports local development and makes no strict process
isolation claim; it is available only with the development memory vault, and
a production (`aegiskeys`) installation refuses it outright. `isolated`
refuses broker/agent and trusted/agent UID overlap, requires an explicit
agent socket group whose membership includes every configured agent, and
requires distinct agent versus admin/intake socket directories. A production
installation defaults to `isolated` and refuses to start unless the live
boundary check passes. The trusted operator runs the intake CLI as the broker
service UID. This validates the configured topology; a strict AI-blind
claim still requires a passing multi-process qualification run and review of
filesystem ACLs, supplementary groups, executable permissions, and AegisKeys
grants on the deployment host. The acceptance procedure is in
[`qual/PRIVILEGED.md`](qual/PRIVILEGED.md); the current opt-in test records the
process-boundary and protected-relay tiers when a dedicated-UID lab is
provisioned. Without that environment it records those tiers as blocked; full
credentialed/provider scenarios remain `not_exercised` and are not a live
cross-broker qualification.

## Import in a harness (Go)

```go
import secretbridge "github.com/secretbridge/secretbridge"

c, _ := secretbridge.Dial(os.Getenv("SEQ_PASS_SOCKET"))
defer c.Close()
entries, _ := c.Catalog() // refs + discoverable ops (ready vs scoped)
opID, _ := c.Use("github/staging", "github.get_repo", "", map[string]string{"repo": "org/repo"})
status, _ := c.Status("use", opID)
```

## MCP tools

| Tool | Behavior |
| ---- | -------- |
| `secret_catalog` | References + capabilities for the authenticated identity |
| `secret_capabilities` | Discovery: allowlisted operations, accepted data kinds, the closed request-state vocabulary, and the broker's honest input-assurance facts. Never secret material |
| `secret_use` | Submit allowlisted op; returns opaque op ID |
| `secret_transfer` | Request broker→recipient transfer; returns opaque op ID |
| `secret_status` | Caller's own status + durable sanitized receipt when completed |
| `relay_request` | Request protected user input for a registered recipient; returns an opaque ID for trusted-terminal fulfillment |
| `relay_status` | Own relay request state, normalized to the closed vocabulary (awaiting_user, authorized, dispatching, accepted, applied, uncertain, rejected, expired, unavailable) — never the secret |
| `relay_cancel` | Withdraw your own relay request before fulfillment; safe to repeat |

An unqualified or unknown broker state is refused rather than reported to the
agent. `accepted` means the recipient durably stored the delivery; only
`applied` means the consumer verified the intended effect.

The same contract is available without MCP as
`seqpass agent capabilities|request|status|cancel`, for harnesses that speak
CLI instead of MCP.

## Security model

- Default-deny policy; DB errors deny; unknown ops/destinations deny.
- Principals come from socket peer credentials, never request fields.
- Admin methods require explicit admin-UID membership, not just reaching
  the admin socket. Filesystem 0600 sockets are a second control.
- Global authorization epoch: any policy/destination/binding change bumps
  it; approvals and claims are bound to principal + binding + op + params
  digest + destination digest + epoch. Revocation races fail closed.
- Atomic claim (`authorized` → `executing`, one winner); `uncertain` on lost ack.
- Submission validates the driver's typed contract (unknown ops/params
  never reach approval). Execution replays the persisted canonical envelope
  and re-evaluates current policy before credential release.
- Transfers go only to authenticated recipient sockets: the endpoint path is
  validated (socket, no symlink, expected owner), the peer UID/GID is
  verified before any payload byte is sent, and the ack must bind the exact
  operation ID + payload digest. File/network destinations are rejected.
- Delivery receipts carry no secret-derived fingerprint: the payload digest
  lives only inside the trusted delivery protocol and the broker-private
  dispatch record, so low-entropy secrets gain no offline guessing oracle.
- Reconciliation consults the original dispatch record (endpoint, identity,
  payload digest), never the destination's current configuration; a dead
  original reports unavailable instead of substituting a new recipient.
- One broker owns each database (lock file held for life); expiry is a
  visible lifecycle transition; authorized work is listed in `admin pending`
  under READY so preauthorized ops never strand.
- Credential-resolution helper (P0-1): the long-lived broker is
  non-dumpable (`PR_SET_DUMPABLE=0`, §11), and AegisKeys authenticates
  Unix-socket peers by reading `/proc/<pid>/exe` — which the kernel
  refuses for a non-dumpable process even to the same UID. In-broker
  resolves therefore fail at the peer-identity layer by design. The fix
  keeps the broker's posture and moves each resolve into a short-lived
  helper process (`seqpass resolve-helper`, configured via
  `--aegiskeys-resolve-helper`): spawned only by the broker's approved
  execution path, one request over a private CLOEXEC socketpair
  inherited as fd 3, credential material returns only on that
  descriptor (stdout/stderr are /dev/null), `RLIMIT_CORE=0` blocks core
  files while dumpability stays at the default so AegisKeys can verify
  the helper's executable identity. The helper is the grant target —
  an agent-spawned helper authenticates with the agent UID and is
  denied; the helper path is operator configuration, never
  agent-supplied. Attestation closes the courier hole: the broker
  signs every resolve with an in-memory ed25519 key (`admin
  attest_public` retrieves the hex public half for the AegisKeys
  grant's `attest_key` pin); the dumpable helper only carries
  nonce+signature over the socketpair, so a same-UID process that
  execs the helper directly still cannot produce a signature the
  grant accepts (the private key lives in non-dumpable memory, the
  one same-UID-unreadable store). A grant pinning an attest key never
  matches an unattested or invalidly signed request. Residual: a
  same-UID process could ptrace the millisecond-lived helper, but
  what it would observe (nonce+signature over already-approved
  binding/op) forges nothing — replay of a captured request is denied
  by fresh-nonce attestation, and the credential itself is not
  observable on the peer-verified socket.

## Recipient wire protocol (v1)

Broker → recipient: 4-byte big-endian length + JSON envelope
`{"v":1,"op_id":"...","digest":"sha256-hex","payload":"..."}`.
Recipient → broker: 4-byte big-endian length + JSON ack
`{"accepted":true,"op_id":"...","digest":"sha256-hex","bytes":N}`.

The recipient must persist the payload under `(op_id, digest)` and only then
ack quoting both back; byte counts alone are rejected as `uncertain`.
Recipients must reject unknown envelope versions. Recipient processes run
under the UID pinned at registration (`--expect-uid`); a substituted process
receives nothing.

Recipient obligations (SC-06):

- Run as a DEDICATED service UID shared with no other process. UID pinning
  authenticates the OS principal, not one application binary — a same-UID
  hostile process can otherwise impersonate the recipient.
- Serve the socket from a directory owned by the recipient UID (or root)
  with no group/other write permission; the broker verifies this before
  connecting and refuses otherwise. No symlinks in the socket path.
- Treat `(op_id, digest)` as an idempotency key: a lost ack may cause the
  broker to redeliver the identical envelope, which must be acked WITHOUT
  re-applying side effects.
- An ack attests durable acceptance (persisted), not downstream application
  of the payload. "Applied" state needs independent outcome verification.
- Memory vault is a test fixture; production credentials live in AegisKeys.
- `Vault.Get` exists only inside the trusted executor.

### Running a recipient

```bash
seqpass recipient --socket /run/seqpass/recipient/cred.sock \
  --journal /var/lib/seqpass-recipient/journal \
  --consumer file --consumer-dir /var/lib/seqpass-recipient/destination \
  --trust-broker-uid $(id -u seqpass) --socket-mode 0600
```

`--consumer file` commits the credential to `--consumer-dir` and verifies the
intended effect by reading it back before reporting `applied`.
`--consumer reference` is the metadata-only fixture: it journals durable
acceptance but applies nothing, and is for wire tests and development only.
There is no default consumer, and no mode prints the secret to stdout.

`--trust-broker-uid` is the server-side allowlist: the recipient verifies the
connecting peer's OS identity BEFORE reading any frame, with
`SO_PEERCRED`, and refuses any unlisted caller. Omitting it allows only the
recipient's own UID.

## Deployment requirements (isolation must be proven, not assumed)

Supported identity topology (C02):

| Component | OS identity | Access |
| --------- | ----------- | ------ |
| AegisKeys broker | Dedicated service UID (`seqpass`) | Vault, key, private broker socket |
| SeqPass broker (trusted executor) | Same service UID (`seqpass`) | AegisKeys `resolve`, private state, both SeqPass sockets |
| Agent identities | Separate unprivileged UIDs in group `seqpass-agents` | Agent-request socket only |
| Operator admin client | Explicitly authorized UID (normally `seqpass` itself) | Admin socket only |

Setup:

```bash
# Dedicated service user + agent group (agents are never seqpass, never root)
useradd -r -s /usr/sbin/nologin seqpass
groupadd --system seqpass-agents
for a in agent1 agent2; do useradd -m -s /bin/bash $a; usermod -aG seqpass-agents $a; done

# Agent socket dir: service-owned, group-traverse so approved agents connect.
# Admin socket dir: separate, owner-only, invisible to agents.
mkdir -p /run/seqpass/agents /run/seqpass/admin /run/seqpass/intake
chown seqpass:seqpass-agents /run/seqpass/agents; chmod 0710 /run/seqpass/agents
chown seqpass:seqpass /run/seqpass/admin; chmod 0700 /run/seqpass/admin
chown seqpass:seqpass /run/seqpass/intake; chmod 0700 /run/seqpass/intake

# Broker: agent socket 0660 (group), admin socket 0600 (owner-only).
# --agent-uid lists EVERY approved agent UID; anything else is denied even
# with a valid peer credential. --admin-uid gates the admin socket.
sudo -u seqpass ./seqpass broker --vault aegiskeys --assurance isolated \
  --socket /run/seqpass/agents/broker.sock \
  --admin-socket /run/seqpass/admin/broker.sock.admin \
  --intake-socket /run/seqpass/intake/broker.sock.intake \
  --socket-group seqpass-agents \
  --agent-uid "$(id -u agent1),$(id -u agent2)" \
  --admin-uid "$(id -u seqpass)" --intake-uid "$(id -u seqpass)"
# --socket-group is what makes the documented permissions real: the broker
# chowns the agent socket (and its directory) to that group and verifies
# the result at startup, failing closed on mismatch.
# Legacy destinations without a pinned recipient UID fail closed at delivery
# until re-pinned via `update-dest --expect-uid`.

# MCP adapter runs AS THE AGENT user (never as seqpass):
sudo -u agent1 SEQ_PASS_SOCKET=/run/seqpass/agents/broker.sock ./seqpass mcp
```

Rules:

- Broker + admin CLI run as the dedicated service user; agents run as
  separate users with no write access to the broker's executable, DB,
  socket dirs, or AegisKeys grant config.
- `resolve` in AegisKeys is granted only to the trusted executor identity.
  The existing AegisKeys same-UID constraint is preserved: SeqPass's broker
  and AegisKeys run under the same service UID. Agents must have no access
  to the AegisKeys socket (do not add agents to AegisKeys' UID or group).
- Same-user agent + broker deployments do NOT satisfy the secrecy claim.
- `relay_request` only creates a request and returns an opaque ID. The MCP
  adapter never calls native elicitation and never receives the value. A
  trusted operator reviews and fulfills it from a terminal running under the
  broker service UID with `seqpass relay inbox` and `seqpass relay fulfill
  <request-id>`; the owner-only intake socket must remain inaccessible to
  agent UIDs.
- Packaging warning: `seqpass` is one binary with `broker`, `mcp` and
  `admin` subcommands. AegisKeys' executable grant identifies the binary,
  not the subcommand, so subcommands do NOT establish different grant
  identities. Isolate by OS user (above), never by subcommand. For stronger
  executable-level separation, ship distinct `seqpass-broker` / `seqpass-mcp`
  binaries or prevent agent UIDs from executing the privileged binary as the
  service user (no sudo, no setuid).

### systemd service (recommended for the isolated topology)

`deploy/seqpass-broker.service` runs the broker under the dedicated
service identity with restart-on-failure (bounded by the `[Unit]`
restart window), restrictive filesystem privileges
(`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, writes
confined to `/run/seqpass` + `/var/lib/seqpass`), and **no
credential-bearing environment variables**. Topology configuration
(paths, UIDs, socket groups, AegisKeys endpoint) comes from the
mandatory `/etc/default/seqpass` — never credentials.

The unit enforces a two-stage gate:

1. `ExecStartPre` — `seqpass doctor --topology` preflight: validates the
   expanded configuration and filesystem topology before the broker
   exists. It deliberately does **not** pass `--require-verified`: a
   preflight cannot prove the isolation of a broker that has not
   started, and doctor refuses to claim otherwise.
2. `ExecStartPost` — bounded readiness gate: verifies the **running**
   broker's live isolation boundary (`doctor --require-verified`) with
   retries; the unit fails if the boundary never reports verified.

Install with:

```bash
sudo cp deploy/seqpass-broker.service /etc/systemd/system/
sudo editor /etc/default/seqpass   # required topology keys (see unit header)
sudo systemctl daemon-reload
sudo systemctl enable --now seqpass-broker
```

Override site-specific settings with a drop-in unit. Directive
placements and the two-stage gate contract are pinned by
`deploy/deploy_test.go` (including `systemd-analyze verify` where the
host has it), so a unit regression fails `go test ./...` rather than
being silently ignored by systemd.

## Sandbox note

Some sandboxed environments expose `/home` as `nobody:nogroup` even when the
test runtime directory itself is correctly owned. The broker refuses such
ancestors by design. In those environments, socket-based tests will skip
automatically; use a normal host or container where `/home` is broker-owned
to exercise the full Unix-socket coverage.

## Testing

```bash
go test ./...                                  # portable; socket suites skip
SEQPASS_TEST_RUNTIME_DIR=/tmp go test ./...    # full socket coverage
SEQPASS_TEST_RUNTIME_DIR=/tmp SEQPASS_REQUIRE_RUNTIME=1 go test ./...  # as CI
```

`SEQPASS_TEST_RUNTIME_DIR` names a directory with trusted ancestors (owned by
the test identity, not group- or world-writable) under which the Unix-socket
suites create their fixtures. It must be set to exercise the socket-based
coverage. Without it those suites skip, which keeps `go test ./...` portable
but silently reduces coverage.

`SEQPASS_REQUIRE_RUNTIME=1` turns a blocked prerequisite into a test failure
instead of a skip, so a coverage run cannot pass while omitting the socket
suites. Use it in CI and release verification.

Some tests do not need a trusted ancestor and instead create their own
owner-only directory under `/tmp` (which is world-traversable and therefore a
valid ancestor for a socket fixture). Those run everywhere.

## Relay request contract

`relay_request` returns:

```json
{
  "request_id": "req-...",
  "status": "awaiting_user",
  "input_required": true,
  "input_kind": "api_key",
  "next_action": "secure_input"
}
```

`input_kind` mirrors the requested data kind (for example `api_key` or
`password`). The harness should display a pending-input notice; the actual
value is never collected by the MCP form, the chat surface, or the agent.
