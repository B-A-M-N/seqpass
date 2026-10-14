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

No HTTP listener, no browser UI, no TCP port. Approvals happen in the
operator's trusted terminal (`seqpass admin`); agents observe approval state
from inside the harness via `secret_status`.

## Build

```bash
go build -o seqpass ./cmd/seqpass
```

## Run

```bash
# 1. Development or local single-user setup (best-effort only):
# ./seqpass broker --vault aegiskeys --assurance best-effort
#
# Production topology: broker and AegisKeys use a dedicated service UID;
# each agent runs as a different UID. The trusted terminal/admin CLI runs as
# the service UID because the admin and intake sockets are owner-only.
# --vault is required: aegiskeys for production; memory-test --dev is for
# development only and never holds production credentials.
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
isolation claim. `isolated` refuses broker/agent and trusted/agent UID
overlap, requires an explicit agent socket group whose membership includes
every configured agent, and requires distinct agent versus admin/intake
socket directories. The trusted operator runs the intake CLI as the broker
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
| `secret_use` | Submit allowlisted op; returns opaque op ID |
| `secret_transfer` | Request broker→recipient transfer; returns opaque op ID |
| `secret_status` | Caller's own status + durable sanitized receipt when completed |
| `relay_request` | Request protected user input for a registered recipient; returns an opaque ID for trusted-terminal fulfillment |
| `relay_status` | Own relay request state: awaiting_user, authorized, delivered, uncertain, rejected, expired, cancelled, unavailable, failed — never the secret |

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

## Sandbox note

Some sandboxed environments expose `/home` as `nobody:nogroup` even when the
test runtime directory itself is correctly owned. The broker refuses such
ancestors by design. In those environments, socket-based tests will skip
automatically; use a normal host or container where `/home` is broker-owned
to exercise the full Unix-socket coverage.

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
