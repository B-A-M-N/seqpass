# SeqPass

An agent-agnostic secret broker for native coding-harness integration.

SeqPass lets an agent request a credential or a privileged operation without ever receiving the credential itself. A broker process running under its own OS identity resolves secrets from AegisKeys (or accepts a one-time value from a trusted human), applies default-deny policy, executes only allowlisted operations, and returns opaque IDs and receipts to the agent.

In the `isolated` Linux topology, agents run under separate UIDs and credential material stays outside those process identities. Same-user `best-effort` deployments do not provide that isolation guarantee and are development-only.

SeqPass is an experimental project tied to other applications: AegisKeys as the authoritative vault, the FI Gateway credential manager, and coding harnesses such as Codex, Claude Code, Hermes, OpenCode, and Pi. Work continues as time permits. See [Project status](#project-status).

## Why

Giving a coding agent an API key usually means putting that key somewhere the agent can read it: an environment variable, a config file, a chat message, or a tool argument. Once it is readable, it can be logged, echoed, or sent to a model. SeqPass inverts that arrangement. The agent sees an opaque request ID and a status; the secret moves only between trusted processes over authenticated Unix sockets, and every release is policy-checked and audited.

## What it does

| Mode | Flow | What the agent sees |
|---|---|---|
| **A - credential use** | Broker executes an allowlisted operation with a credential resolved from AegisKeys | Sanitized result DTO and receipt |
| **B - blind transfer** | Broker delivers sensitive data directly to a trusted recipient socket | Receipt, destination, and status only |
| **C - sealed handoff** | After approval, broker creates a short-lived HPKE capsule for a pinned recipient key and signs it with a separate issuer key | Opaque ciphertext it can carry but cannot read or retarget |

Resolution follows rotation: the latest authorized value of the approved binding is used. Pinned-version semantics are not claimed. Unbound ephemeral payloads are a `memory-test --dev` fixture only and are rejected under `--vault aegiskeys`.

## Architecture

```
harness (Codex / Claude / Hermes / OpenCode / Pi)
  └─ `seqpass mcp` (MCP stdio adapter, untrusted: no vault, no DB)
       └─ Unix socket IPC (peer-credential principals)
            └─ `seqpass broker` (privileged: policy, AegisKeys resolve, execution)
                 └─ AegisKeys broker socket (authoritative encrypted vault)
```

There is no HTTP listener, no browser UI, and no TCP port. Approvals happen in the operator's trusted terminal with `seqpass admin`; agents observe approval state from inside the harness with `secret_status`.

## Capability status

A capability is **implemented** when code exists and tests pass. It is **production-qualified** only after the required live deployment, credential, and isolation evidence has been independently verified.

| Capability | Status | Evidence |
|---|---|---|
| Broker core (operations, policy, destinations, approval) | Implemented, tested | `go test ./...` |
| Unix-socket IPC domains (agent / admin / intake / host) | Implemented, tested | IPC and socket tests |
| Relay workflow (request, review, fulfill, dispatch) | Implemented, tested | Service and integration tests |
| Administrative host-binding RPC | Implemented, tested | `internal/ipc/hostbinding_rpc_test.go` |
| Host-session registration and revocation lifecycle | Implemented, tested | `internal/service/hostsession_test.go` |
| Relay worker (bounded, deadline-priority) | Implemented, tested | `internal/service/relay_test.go` |
| Transactional quota enforcement | Implemented, tested | `internal/metadata/relay.go` |
| OpenCode adapter (trusted host + agent domain) | Type-checked, unit-tested | `bun x tsc --noEmit`, `bun x vitest run` |
| Pi adapter (trusted host + agent domain) | Type-checked, unit-tested | `bun x tsc --noEmit`, `bun x vitest run` |
| Recipient durability contract | Implemented, tested | `internal/transfer/recipient_test.go` |
| Mode A recipient-pull ticket | Implemented, tested | `internal/service/handoff_test.go` |
| Mode C signed HPKE capsule issue, import, receipt | Implemented, unit-tested | `internal/capsule/`, `internal/service/capsule_issue_test.go` |
| OpenCode recipient adapter (v1 auth.json + v2 credential store) | Implemented; v2.1.4 app-qualified with synthetic local provider | `internal/apptarget/opencode*.go`; opt-in `./qual` test |
| Codex recipient adapter (API key in recipient-pinned CODEX_HOME) | Implemented; codex-cli 0.165.0 app-qualified with synthetic local Responses API | `internal/apptarget/codex.go`; opt-in `./qual` test |
| Real credential consumer | Implemented, tested | `internal/transfer/consumer.go` (delivery, commit, verified `applied`) |
| Credentialed operations (`http.request`, `process.run`, `git.fetch`, `git.push`) | Implemented, tested | `internal/secureops/`; pinned executables, origins, remotes; credential never in argv, env, URL, or DTO |
| Generic agent adapter (MCP + CLI) | Implemented, tested | `internal/adapter/`, `cmd/seqpass/agent.go` |
| Versioned adapter contract (sealed frames) | Implemented, tested | `internal/adapter/protocol.go` (refuses unknown versions) |
| Adapter host-version qualification | Implemented, tested | `integrations/opencode/`, `integrations/pi/` |
| `seqpass install <adapter>` (endpoints-only config) | Implemented, tested | `cmd/seqpass/install.go` (no credentials or session tokens) |
| Installation-wide config | Implemented, tested | `internal/config/config.go` (fail-closed on malformed config) |
| Live isolation boundary check and drift revocation | Implemented, tested | `internal/isolation/`, `internal/daemon/isolation_test.go` |
| `seqpass recipient` (deployable consumer endpoint) | Implemented, tested | `cmd/seqpass/recipient.go` |
| **Native protected-input isolation** | **Not yet production-qualified** | Requires live multi-UID topology plus AegisKeys qualification |
| **AegisKeys production resolution** | **Not yet production-qualified** | Requires live dedicated-UID grant and rotation tests |
| **Recipient live-socket integration** | **Not yet production-qualified** | Requires real recipient process plus privileged Unix-socket topology |
| **Multi-UID isolation qualification (G2-G8)** | **Not yet production-qualified** | Requires separate agent, operator, broker, and recipient UIDs; see [privileged qualification](qual/PRIVILEGED.md) |

## Quick start

```bash
go build -o seqpass ./cmd/seqpass

# Development only: memory vault, best-effort assurance, explicit --dev opt-in.
./seqpass broker --vault memory-test --dev --assurance best-effort
```

Production uses dedicated UIDs and the AegisKeys vault. The broker requires `--vault aegiskeys`, defaults to `--assurance isolated`, and refuses to start unless the live boundary check passes:

```bash
sudo -u seqpass ./seqpass broker --vault aegiskeys --assurance isolated \
  --socket /run/seqpass/agents/broker.sock \
  --admin-socket /run/seqpass/admin/broker.sock \
  --intake-socket /run/seqpass/intake/broker.sock \
  --admin-uid $(id -u seqpass) --intake-uid $(id -u seqpass) \
  --agent-uid 2001,2002 --socket-group seqpass-agents
```

Register a harness adapter (the config contains endpoints only, never credentials):

```bash
codex mcp add seqpass -- /usr/local/bin/seqpass mcp
claude mcp add --scope user seqpass -- /usr/local/bin/seqpass mcp
./seqpass install opencode --out <plugin-config> --intake-socket ... --host-socket ...
```

Operator terminal:

```bash
./seqpass admin add-secret --name github/staging --binding inference/staging
./seqpass admin add-dest --name runner --type recipient-socket \
  --endpoint /run/trusted/recipient.sock --expect-uid 3001
./seqpass admin add-policy --name team --rules '[{"principal":"uid:2001","secret_refs":["<ref>"],"ops":["transfer"],"dest_ids":["<dest>"]}]'
./seqpass admin pending
./seqpass admin approve --type transfer --id <op-id>
./seqpass admin execute --type transfer --id <op-id>
./seqpass admin verify --type transfer --id <op-id>
./seqpass status
```

### Standalone relay-only mode

SeqPass can run as a multi-UID relay service without AegisKeys: use `--vault relay-only` with `--assurance isolated`. It keeps separate agent, intake, and admin identities and sockets; an authorized human supplies the payload and the broker holds it in memory for a single dispatch. `relay-only` has no persistent credential store and refuses credential references, AegisKeys resolution, provisioning, staged secret use, and protected credential operations. Use `--vault aegiskeys` for persistent API-key storage and scoped operations.

## MCP tools

| Tool | Behavior |
|---|---|
| `secret_catalog` | References and capabilities for the authenticated identity |
| `secret_capabilities` | Allowlisted operations, accepted data kinds, request-state vocabulary, and honest input-assurance facts; never secret material |
| `secret_use` | Submit an allowlisted operation; returns an opaque ID |
| `secret_transfer` | Request broker-to-recipient transfer; returns an opaque ID |
| `secret_status` | Caller's own status and durable sanitized receipt when complete |
| `relay_request` | Request protected user input for a registered recipient; returns an opaque ID |
| `relay_status` | Own relay state, normalized to a closed vocabulary, never the secret |
| `relay_cancel` | Withdraw your own relay request before fulfillment; safe to repeat |

An unqualified or unknown broker state is refused. `accepted` means the recipient durably stored the delivery; only `applied` means a consumer verified the intended effect. The same contract is available without MCP via `seqpass agent capabilities|request|status|cancel`.

## Trusted-terminal relay flow

The relay is the primary product flow. The agent decides it needs a value; a human supplies it through a trusted path; the broker delivers it to a registered recipient; the agent gets status only.

```bash
# User terminal, never the agent's terminal:
./seqpass tui                            # persistent native inbox (preferred)
./seqpass relay inbox                    # pending requests, verified fields
./seqpass relay fulfill <request-id>     # review recipient, action, expiry; enter hidden
./seqpass relay status <request-id>      # delivered / uncertain / ...
./seqpass relay cancel <request-id>      # withdraw
```

The MCP adapter never opens a native elicitation form and never handles plaintext. A grant binds exact agent, recipient, live config, purpose, deadline, and delivery budget without creating a permanent policy. Single-use values admit exactly one delivery; concurrent racers converge with the loser failing closed. Payloads are memory-only, so expiry, revocation, and restart all read truthfully and cannot start a new dispatch. Receipts, audit, status, and the SQLite file never contain plaintext.

Optional native host presentation (`--host-socket`) is display-only. A trusted host adapter receives a broker-minted session token and can call only `host.event`, `host.notice`, `host.review`, and `host.cancel_prompt`. Capability flags describe UI support, not security; a native secure-input mode requires a separate qualification record.

## Sealed application handoff

The recipient generates its HPKE key under its own service identity. The issuer Ed25519 key stays under the broker identity; only the issuer public key is copied to the recipient through a separately trusted enrollment channel. After approval the agent writes only an opaque envelope, and the recipient imports it through its application adapter.

Capsules expire within five minutes by default (30 seconds minimum, 15 minutes maximum). The recipient signs a receipt bound to its registered receipt key, destination revision, handoff ID, operation ID, capsule digest, and result; the issuer marks completion only after verifying that signature. Offline recipients courier the signed receipt back. Receipt signing uses a key separate from the HPKE decryption key, the issuer key, and the AegisKeys attestation key. For key replacement, follow the versioned, create-only procedure in [handoff key rotation](docs/handoff-key-rotation.md).

Recipient adapters exist for OpenCode, Codex, and the FI Gateway credential manager. The FI Gateway adapter sends the key over its peer-UID-authenticated local Unix socket into the gateway's managed credential store and reports only metadata.

Offline capsules cannot be revoked after issuance; a credential revoked later may remain usable in an issued capsule until it expires. Expiry does not erase a copied ciphertext. Separate agent, issuer, and recipient identities are required: same-UID deployments do not isolate the recipient private key from the agent.

## Security model

- Default-deny policy; database errors deny; unknown operations and destinations deny.
- Principals come from socket peer credentials, never from request fields.
- Admin methods require explicit admin-UID membership, not merely reaching the admin socket.
- A global authorization epoch is bumped by any policy, destination, or binding change. Approvals and claims bind principal, binding, operation, parameters digest, destination digest, and epoch; revocation races fail closed.
- Claiming is atomic (`authorized` to `executing`, one winner); a lost acknowledgement produces `uncertain`.
- Execution replays the persisted canonical envelope and re-evaluates current policy before credential release.
- Transfers go only to authenticated recipient sockets: path and owner are validated, peer UID/GID is verified before any payload byte, and the acknowledgement must bind the exact operation ID and payload digest.
- Delivery receipts carry no secret-derived fingerprint, so low-entropy secrets gain no offline guessing oracle.
- The long-lived broker is non-dumpable; AegisKeys resolves move into a short-lived, digest-pinned helper launched only by the approved execution path, with attestation signed by an in-memory key.
- One broker owns each database. Credentialed operations use fd injection so the secret never appears in argv, environment, URL, or DTO.

Residual caveats are documented in [attestation closeout](docs/attestation-doctor-closeout.md) and [FI Gateway remediation](docs/fi-gateway-remediation-plan.md). Real-app qualification runs are recorded in [Codex CLI](docs/qualification-codex-cli-0.165.0.md) and [OpenCode](docs/qualification-opencode-v2.1.4.md).

## Deployment and isolation

| Component | OS identity | Access |
|---|---|---|
| AegisKeys broker | Dedicated service UID (`seqpass`) | Vault, key, private broker socket |
| SeqPass broker | Same service UID (`seqpass`) | AegisKeys resolve, private state, broker sockets |
| Agent identities | Separate unprivileged UIDs in `seqpass-agents` | Agent socket only |
| Operator admin | Explicitly authorized UID | Admin socket only |

`isolated` refuses broker/agent and trusted/agent UID overlap, requires an explicit agent socket group containing every configured agent, and requires distinct agent versus admin/intake socket directories. Same-user deployments do not satisfy the secrecy claim. A `systemd` unit in `deploy/seqpass-broker.service` runs the broker under the service identity with restrictive filesystem privileges and no credential-bearing environment variables; its two-stage gate checks topology before start and live isolation after start.

A strict AI-blind claim still requires a passing multi-process qualification run and review of filesystem ACLs, supplementary groups, executable permissions, and AegisKeys grants on the deployment host. See [privileged qualification](qual/PRIVILEGED.md).

## Testing

```bash
go test ./...                                   # portable; socket suites skip
SEQPASS_TEST_RUNTIME_DIR=/tmp go test ./...     # full socket coverage
SEQPASS_TEST_RUNTIME_DIR=/tmp SEQPASS_REQUIRE_RUNTIME=1 go test ./...  # CI
```

`SEQPASS_TEST_RUNTIME_DIR` must point at a directory with trusted ancestors or socket suites skip. `SEQPASS_REQUIRE_RUNTIME=1` turns a blocked prerequisite into a failure instead of a skip.

## Project status

Experimental and maintained intermittently. Several security-critical capabilities remain **not production-qualified** until live multi-UID, AegisKeys, and recipient-socket evidence is independently verified. Same-user `best-effort` mode is development-only, and a production AegisKeys vault refuses it. No `LICENSE` file is published yet; all rights are reserved until one is added.

## Contributing

Issues and focused pull requests are welcome. Security-sensitive changes should include the relevant tests and an explicit statement of which isolation assumptions they rely on.

## Disclaimer

This project is an independent, experimental work by the repository author. It is not affiliated with, directed, endorsed, or approved by FreeInference.org ("FI"). FI has no involvement in this project's design, development, or publication, and bears no responsibility for it. Every decision to create, modify, and publish this work was made by me, at my own discretion.

If you find this project useful or helpful, please consider sponsoring or otherwise supporting FreeInference.org. FI provides a useful and valuable service to people who might not otherwise have the opportunity to access this kind of tooling.
