# SeqPass OpenCode V2 adapter

Registers the `seqpass` slash command (plus `leader s p`) as a display-only
in-host inbox for pending protected-input requests: a `home_footer` slot
shows the pending count, and the review command lists broker-verified
requests (via `DialogSelect`) and opens the review flow for the selected
one. Model-facing relay tools stay on the SeqPass MCP server — nothing in
this plugin exposes credential bytes to the model.

## Credential entry is external in this build

The OpenCode V2 plugin surface has no masked input field (`DialogPrompt`
and the `@opentui` `InputRenderable` both echo typed characters), so this
adapter registers with `presentation: "request_status"` /
`input_transport: "external_tty"` and refuses in-host credential
collection even when a deployment qualification says
`host_native_verified` (`lib/nativeInput.ts` gate). The operator types the
value in their own `seqpass tui` terminal; the adapter only surfaces
broker-verified request metadata.

When a plugin API ships a verified masked field, flip
`NATIVE_MASKED_INPUT_SUPPORTED`, re-qualify the host, and the native
dialog branch activates.

## Wiring

The plugin receives `intakeSocket`, `hostSocket`, `sessionID`, and
`sessionToken` as plugin options and owns two IPC transports through the
shared wire client (`integrations/shared/ipc.ts`): the intake socket for
registration and fulfillment, the host socket for pending-notice polling
(5 s interval, disposed with the plugin lifecycle).

Status: functional against the documented `@opencode-ai/plugin` v2.0.x
contract; live TUI qualification still requires an actual OpenCode V2
installation.
