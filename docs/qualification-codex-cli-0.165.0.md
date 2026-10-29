# Codex CLI handoff qualification

Status: passed for the recorded Codex CLI and synthetic local-provider
scenario. This confirms the Codex recipient adapter installs, rotates, and
uses an API key through the real CLI; it does not qualify an upstream provider
or a separate multi-UID broker deployment.

## Recorded run

- Run date: 2026-10-29 America/Chicago.
- SeqPass checkout: base commit `90710d55be7cb64c6ca78277d3a4a07c4a2a7487`, with the
  Codex recipient adapter and qualification test present as working-tree changes.
- Codex: `codex-cli 0.165.0`.
- Codex executable SHA-256:
  `c06a67fd8ac76508dc78bd99ce20c9f317b8d568beda59485f3f4134df9962d5`.
- Command:
  `SEQPASS_QUAL_CODEX=1 go test ./qual -run '^TestQualCodexHandoff$' -count=1 -v`.
- Result: passed. The recipient adapter invoked Codex's supported API-key login
  command with a synthetic key on stdin and verified `CODEX_HOME/auth.json`.
  Codex sent a request to a loopback Responses API mock, which accepted only
  the installed synthetic key and returned a synthetic completion. The adapter
  then rotated the key; a second Codex request used the new key.
- Isolation: fresh temporary `HOME` and `CODEX_HOME`, empty project directory,
  minimal child environment, and loopback-only mock provider. No real account
  credential or upstream provider was used.

Codex's supported login command stores API-key authentication in its auth
record. The adapter pins an explicit command path and `CODEX_HOME`, strips
ambient credential variables, and does read-only reconciliation against the
registered auth file. See the [Codex auth storage implementation](https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/storage.rs)
and [Codex authentication mode](https://github.com/openai/codex/blob/main/codex-rs/protocol/src/auth.rs).

## Remaining qualification

This run does not qualify Codex versions other than 0.165.0, the ChatGPT OAuth
login mode, upstream API behavior, or agent/issuer/recipient process
separation. The three-identity capsule qualification is recorded separately
in [`qual/PRIVILEGED.md`](../qual/PRIVILEGED.md).
