# OpenCode v2 handoff qualification

Status: passed for the recorded OpenCode binary and synthetic local-provider
scenario. This is app-acceptance evidence for the OpenCode v2 recipient
adapter; it is not a multi-UID isolation or upstream-provider qualification.

## Recorded run

- Run date: 2026-10-28 America/Chicago.
- SeqPass checkout: base commit `90710d55be7cb64c6ca78277d3a4a07a4c2a7487`, with the
  OpenCode v2 adapter and qualification test present as working-tree changes.
- OpenCode: `opencode v2.1.4`.
- OpenCode executable SHA-256:
  `ca9b3ee262e33bb4e7aa0e1230dc61086a474c8c8016b980081d0719712fd2e7`.
- Command:
  `SEQPASS_QUAL_OPENCODE=1 go test ./qual -run '^TestQualOpenCodeHandoff$' -count=1 -v`.
- Result: passed. The actual OpenCode CLI imported and used the recipient
  adapter's synthetic credential for a chat completion against a loopback
  mock provider. The test then rotated the stored credential and verified the
  next request used the new synthetic value; the mock rejected the old value.
- Isolation: fresh temporary `HOME`, XDG config/data/state directories, empty
  project directory, and a minimal child environment. The mock endpoint was
  local; no real provider or credential was used.

The v2 adapter uses OpenCode's `auth import` and `auth export` commands instead
of editing its credential database. OpenCode v2 stores saved credentials in
SQLite and imports legacy `auth.json` during migration; it does not keep using
that file for new writes ([OpenCode v2 provider storage documentation](https://dev.opencode.ai/v2/docs/cli/providers)).

## Remaining qualification

This run does not qualify separate agent, issuer, and recipient operating
system identities, real upstream acceptance, or other OpenCode versions. The
multi-UID production qualification remains outstanding as described in
[`qual/PRIVILEGED.md`](../qual/PRIVILEGED.md).
