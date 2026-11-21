# SeqPass

SeqPass is an agent-agnostic secret broker for coding harnesses. It lets an agent request a credential or a privileged operation without ever receiving the credential itself. A broker process running under its own OS identity resolves secrets from AegisKeys (or accepts a one-time value from a trusted human), applies default-deny policy, executes only allowlisted operations, and returns opaque IDs and receipts to the agent.

Passing an API key directly to a coding agent puts that key somewhere the agent can read it: an environment variable, a config file, a chat message, or a tool argument. From there it can be logged, echoed, or sent to a model. SeqPass inverts that arrangement. The agent sees an opaque request ID and a status; the secret moves only between trusted processes over authenticated Unix sockets, and every release is policy-checked and audited. Stronger guarantees depend on a properly qualified, isolated deployment; no system can make secrets categorically impossible for an AI to obtain under every configuration.

**Status: experimental.** Components are implemented and tested, but multi-UID isolation, AegisKeys production resolution, live recipient-socket integration, and native input qualification remain outstanding. Not approved for general production use.

## Contents

- [What it gives you](#what-it-gives-you)
- [Three operating modes](#three-operating-modes)
- [Architecture and trust boundaries](#architecture-and-trust-boundaries)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Trusted-terminal relay](#trusted-terminal-relay)
- [Harness and application integration](#harness-and-application-integration)
- [Security caveats](#security-caveats)
- [Implementation and qualification status](#implementation-and-qualification-status)
- [Known limitations](#known-limitations)
- [Testing and verification](#testing-and-verification)
- [Deeper documentation](#deeper-documentation)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## What it gives you

| Capability | What it provides |
|---|---|
| Credentialed operations | A trusted process performs an allowlisted operation with a resolved credential; the agent receives a sanitized result and receipt |
| Blind transfer | Sensitive material goes directly to an authenticated recipient socket; the agent receives status only |
| Sealed handoff | An HPKE capsule for a pinned recipient key, signed by a separate issuer, with an authenticated receipt |
| Human-gated release | A trusted terminal or native TUI reviews and fulfills requests; the MCP adapter never handles plaintext |
| Default-deny policy | Unknown operations, destinations, and database errors deny; revocation races fail closed |
| Auditable outcomes | `accepted` means durable recipient storage; `applied` means a consumer verified the intended effect |

## Three operating modes

| Mode | What happens | Grounded use case | Guarantee boundary |
|---|---|---|---|
| **A - credentialed operation** | The broker resolves a credential from AegisKeys and executes an allowlisted operation. The agent sees a sanitized DTO and receipt. | An agent needs repository metadata; the broker runs a pinned `github.get_repo` operation without exposing the GitHub token. | The agent never receives the key; the trusted executor does. |
| **B - blind transfer** | The broker delivers sensitive data directly to a registered, authenticated recipient socket. | An agent requests a one-time code; a human supplies it in `seqpass tui`, and the broker delivers it to a recipient process pinned by UID. | The agent sees only destination and status; the recipient application handles plaintext. |
| **C - sealed handoff** | After approval, the broker creates a short-lived HPKE capsule for a pinned recipient key and signs it with a separate issuer key. | An agent must carry a credential to an offline recipient, which imports the opaque envelope and returns a signed receipt. | The courier can carry ciphertext but cannot read or retarget it. Offline capsules cannot be recalled after issuance. |

Resolution follows rotation: the latest authorized value of an approved binding is used. Pinned-version semantics are not claimed. Unbound ephemeral payloads are a `memory-test --dev` fixture only and are rejected under `--vault aegiskeys`. The three modes do not provide identical guarantees; choose by trust boundary, not convenience.

## Architecture and trust boundaries

```
coding agent (separate untrusted UID)
  └─ seqpass mcp / seqpass agent   [MCP stdio or CLI adapter - untrusted: no vault, no DB]
       └─ Unix socket IPC (peer-credential principals)
            └─ seqpass broker      [privileged: policy, approval, AegisKeys resolve, execution]
                 ├─ policy + approval boundary
                 ├─ AegisKeys broker socket   [authoritative encrypted vault]
                 └─ recipient socket          [trusted recipient application]

human operator
  └─ seqpass tui / seqpass relay / seqpass admin   [trusted terminal -> intake/admin sockets]
```

The MCP adapter is untrusted. It holds neither the vault nor the durable broker database, returns an opaque ID, and never calls native elicitation or handles plaintext. Plaintext is accessible only to the AegisKeys vault, the broker's approved execution path, the operator's trusted terminal, and the recipient application. An approval is required for every operation; an agent cannot approve its own request.

There is no HTTP listener, no browser UI, and no TCP port. Approvals happen in the operator's trusted terminal; agents observe approval state with `secret_status`.

## Requirements

| Deployment | Requirements | Assurance |
|---|---|---|
| Local development | Go 1.25.5, `memory-test --dev`, `--assurance best-effort` | Development only; always reported unverified; a production vault refuses it |
| Relay-only production | `--vault relay-only --assurance isolated`, dedicated service UID, separate intake/admin/agent sockets | Multi-UID relay with in-memory payload and no persistent credential store |
| Isolated production | Dedicated `seqpass` service UID, separate agent UIDs, agent socket group, owner-only admin/intake sockets, AegisKeys vault, digest-pinned resolve helper | Defaults to `--assurance isolated`; refuses to start unless the live boundary check passes |

`isolated` refuses broker/agent and trusted/agent UID overlap, requires an explicit agent socket group containing every configured agent, and requires distinct agent versus admin/intake socket directories. The systemd unit in `deploy/seqpass-broker.service` carries topology configuration from `/etc/default/seqpass` and no credential-bearing environment variables.

## Quick start

```bash
go build -o seqpass ./cmd/seqpass
./seqpass --help

# Development only: ephemeral memory vault, explicit opt-in.
./seqpass broker --vault memory-test --dev --assurance best-effort
```

Production-style launch (dedicated service identity, AegisKeys vault):

```bash
sudo -u seqpass ./seqpass broker --vault aegiskeys --assurance isolated \
  --socket /run/seqpass/agents/broker.sock \
  --admin-socket /run/seqpass/admin/broker.sock \
  --intake-socket /run/seqpass/intake/broker.sock \
  --admin-uid $(id -u seqpass) --intake-uid $(id -u seqpass) \
  --agent-uid 2001,2002 --socket-group seqpass-agents \
  --aegiskeys-resolve-helper PATH --aegiskeys-resolve-helper-sha256 SHA256
```

Register a harness adapter. These commands write endpoint configuration only, never credentials:

```bash
codex mcp add seqpass -- /usr/local/bin/seqpass mcp
claude mcp add --scope user seqpass -- /usr/local/bin/seqpass mcp
./seqpass install opencode --out <plugin-config> --intake-socket ... --host-socket ...
./seqpass install pi --out <extension-config> --intake-socket ... --host-socket ... --agent-socket ...
./seqpass install mcp --print
```

Operator checks and approval:

```bash
./seqpass doctor --topology      # live isolation boundary report
./seqpass status                 # health, no secrets
./seqpass admin pending          # READY operations awaiting approval
./seqpass admin approve --type transfer --id <op-id>
./seqpass admin execute --type transfer --id <op-id>
./seqpass admin verify --type transfer --id <op-id>
```

Do not install the memory vault or `best-effort` assurance on a host where the secret-isolation claim matters; a production vault refuses both.

## Trusted-terminal relay

The relay is the primary product flow. An agent calls `relay_request`; the MCP adapter returns only an opaque ID and instructions. The value is entered outside the agent process:

```bash
./seqpass tui [--intake-socket PATH]        # persistent native inbox (preferred)
./seqpass relay inbox                       # pending requests, verified fields
./seqpass relay fulfill <request-id>        # review recipient/action/expiry, enter value hidden
./seqpass relay status <request-id>         # delivered / uncertain / applied / ...
./seqpass relay cancel <request-id>         # withdraw
./seqpass relay request --to <dest> --kind password --ttl 90s
```

`seqpass tui` is a native terminal inbox, not an in-host model form. Human approval authorizes the operation; the broker then delivers to the registered recipient; the agent reads normalized status through `relay_status`. An agent-created relay is single-use; reusable grants require an explicit trusted-user choice. Payloads are memory-only, so expiry, revocation, and restart cannot start a new dispatch.

The optional native host presentation domain (`--host-socket`) is display-only. A trusted host adapter registers with `host.register`, receives a broker-minted session token, and may call only `host.event`, `host.notice`, `host.review`, and `host.cancel_prompt`. Capability flags describe UI support, not security; native secure input requires a separate qualification record.

## Harness and application integration

A generic MCP registration, a native host presentation adapter, and a credential-recipient adapter are three different things. Only the third writes a credential into an application.

| Integration | Generic MCP (`seqpass mcp`) | Native host presentation | Credential recipient adapter | Evidence |
|---|---|---|---|---|
| Codex | yes (`mcp_servers.seqpass`) | no | yes, `codex-auth-file-v1` via `codex login --with-api-key` into a recipient-pinned `CODEX_HOME` | codex-cli 0.165.0 app-qualified with a synthetic local Responses API, including rotation |
| Claude Code | yes (`claude mcp add --scope user`) | no | no | Generic MCP path only |
| Hermes | yes (stdio adapter registration) | no | no | Generic MCP path only |
| OpenCode | MCP tools stay on the SeqPass server | yes, `integrations/opencode` plugin via `--host-socket`; display-only, external terminal entry by default | yes, `opencode-auth-json-v1` and `opencode-auth-import-v2` | v2.1.4 app-qualified with a synthetic local provider; live TUI qualification still required |
| Pi | via its tool bridge | yes, `integrations/pi` extension; external terminal entry by default, masked component gated off | no | Functional against the declared `PiCustomUI` contract; live qualification requires an actual Pi |
| FI Gateway | not an agent harness | no | yes, `fi-gateway-credential-manager-v1` over the gateway's peer-UID-authenticated local Unix socket | Adapter implemented; remediation notes in docs |

A recipient adapter requires recipient-local wiring: executable paths, application homes, and socket identity come from protected registration, never from capsule payload fields or agent input. `accepted` means the recipient durably stored the delivery; only `applied` means a consumer verified the intended effect.

MCP tools: `secret_catalog`, `secret_capabilities`, `secret_use`, `secret_transfer`, `secret_status`, `relay_request`, `relay_status`, `relay_cancel`. An unqualified or unknown broker state is refused to the agent. The same contract is available as `seqpass agent capabilities|request|status|cancel` for harnesses that speak CLI.

Agent-carried sealed handoff uses separate HPKE, receipt, issuer, and AegisKeys attestation keys. Capsules expire within five minutes by default (30 seconds minimum, 15 minutes maximum). The recipient signs a receipt bound to its registered key, destination revision, handoff ID, operation ID, capsule digest, and result; the issuer marks completion only after verifying that signature. For key replacement use the versioned, create-only procedure in [handoff key rotation](docs/handoff-key-rotation.md).

## Security caveats

- Same-UID deployments do not provide the claimed secret isolation. A strict AI-blind claim requires a qualified multi-process run and review of filesystem ACLs, supplementary groups, executable permissions, and AegisKeys grants.
- AegisKeys production resolution is not qualified; it needs a live dedicated-UID grant and rotation tests.
- Live recipient-socket integration is not qualified; it needs a real recipient process and privileged Unix-socket topology.
- Multi-UID qualification gates (G2-G8) remain outstanding; see [privileged qualification](qual/PRIVILEGED.md).
- Offline sealed capsules cannot be recalled after issuance. A revoked credential may remain usable until the capsule expires; expiry does not erase a copied ciphertext.
- `accepted` is not `applied`. A recipient acknowledgement attests durable storage, not downstream task success.
- Implemented and unit-tested does not mean production-qualified. The status table below is the authoritative distinction.
- One binary provides `broker`, `mcp`, and `admin`; subcommands do not create separate executable grant identities. Isolate by OS user, never by subcommand.

The security model itself is default-deny: principals come from socket peer credentials, admin methods require explicit admin-UID membership, a global authorization epoch binds approvals to current policy, claiming is atomic, and execution replays the persisted canonical envelope after re-evaluating policy. Credentialed operations use fd injection so the secret never appears in argv, environment, URL, or DTO.

## Implementation and qualification status

| Area | Implemented and tested | App-qualified with synthetic local providers | Production-qualified |
|---|---|---|---|
| Broker core, policy, IPC, relay workflow | yes | n/a | requires live topology |
| Credentialed operations (`http.request`, `process.run`, `git.fetch`, `git.push`) | yes | n/a | no |
| Recipient durability and real consumer | yes | n/a | no live recipient socket |
| Mode C capsule issue/import/receipt | yes | n/a | no |
| Codex recipient adapter | yes | yes, codex-cli 0.165.0 | no |
| OpenCode recipient adapter | yes | yes, v2.1.4 | no |
| FI Gateway recipient adapter | yes | see remediation notes | no |
| Native protected-input isolation | no | no | no |
| AegisKeys production resolution | no | no | no |
| Multi-UID isolation G2-G8 | no | no | no |

## Known limitations

- `relay-only` has no persistent credential store and refuses credential references, AegisKeys resolution, provisioning, staged use, and protected credential operations.
- The file consumer writes a credential as plaintext into a private directory and reads it back before reporting success; it is trusted recipient-side storage, not encrypted-at-rest storage. There is no default consumer, and no mode prints a secret to stdout.
- Socket tests require trusted ancestors; without `SEQPASS_TEST_RUNTIME_DIR` they skip, which silently reduces coverage.
- Some sandboxed environments expose `/home` as `nobody:nogroup`; the broker refuses such ancestors by design.
- No LICENSE file is published; all rights are reserved until one is added.

## Testing and verification

```bash
go test ./...                                   # portable; socket suites skip
SEQPASS_TEST_RUNTIME_DIR=/tmp go test ./...     # full socket coverage
SEQPASS_TEST_RUNTIME_DIR=/tmp SEQPASS_REQUIRE_RUNTIME=1 go test ./...  # CI
```

`SEQPASS_REQUIRE_RUNTIME=1` turns a blocked prerequisite into a failure instead of a skip. Opt-in real-app qualifications use synthetic keys and local mock providers:

```bash
SEQPASS_QUAL_OPENCODE=1 go test ./qual -run '^TestQualOpenCodeHandoff$' -count=1
SEQPASS_QUAL_CODEX=1 go test ./qual -run '^TestQualCodexHandoff$' -count=1
```

## Deeper documentation

- [Privileged qualification](qual/PRIVILEGED.md) - acceptance procedure and outstanding gates
- [Handoff key rotation](docs/handoff-key-rotation.md) - versioned, create-only key replacement
- [Attestation closeout](docs/attestation-doctor-closeout.md) - resolve-helper residual risks
- [FI Gateway remediation](docs/fi-gateway-remediation-plan.md) - recipient integration notes
- [Codex qualification](docs/qualification-codex-cli-0.165.0.md) - synthetic local Responses API run
- [OpenCode qualification](docs/qualification-opencode-v2.1.4.md) - synthetic local provider run
- [Native host qualification notes](qual/host-native/README.md)

## Contributing

Issues and focused pull requests are welcome. Security-sensitive changes should include the relevant tests and an explicit statement of which isolation assumptions they rely on.

## License

No `LICENSE` file is published. All rights are reserved unless and until the owner publishes a license; do not assume an open-source license from the presence of Go or TypeScript source.

## Disclaimer

This project is an independent, experimental work by the repository author. It is not affiliated with, directed, endorsed, or approved by FreeInference.org ("FI"). FI has no involvement in this project's design, development, or publication, and bears no responsibility for it. Every decision to create, modify, and publish this work was made by me, at my own discretion.

If you find this project useful or helpful, please consider sponsoring or otherwise supporting FreeInference.org. FI provides a useful and valuable service to people who might not otherwise have the opportunity to access this kind of tooling.
