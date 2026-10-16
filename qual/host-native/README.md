# SeqPass host-native qualification

This suite records contract-level host-native qualification and reserves
evidence space for genuine host runs.

Current coverage:

- `contract/notice_test.go` — versioned payload-free notice wire contract.
- `contract/session_binding_test.go` — notice is bound to the broker-minted
  host session, authenticated human, and correct relay.
- `contract/assurance_test.go` — native mode requires an exact accepted
  qualification snapshot; `agent_isolated` requires all process, terminal,
  transcript, and intake boundaries to be verified.

Fixture directories are reserved for pinned trusted-recipient and synthetic
secret material. Evidence files are generated only when running the actual
host qualification; this checkout does not contain generated evidence yet.

Required acceptance remains unchanged: real host UI rendering, session
ownership, protected input path, process isolation, transcript disclosure,
fake-prompt resistance, recipient change invalidation, concurrent sessions,
host restart, application execution, and ordinary task continuation.
