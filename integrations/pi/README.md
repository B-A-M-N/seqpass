# SeqPass Pi adapter

Uses `pi.registerTool()` for the model-facing bridge (`relay_request` /
`relay_status`, sanitized results only) and `ctx.ui.custom()` for the
protected input component. Falls back to trusted external fulfillment
when `ctx.hasUI` is false or the custom UI is unavailable.

## Transport rules

- The agent domain needs an explicitly configured `agentSocket`. When it
  is absent, relay RPCs fail closed with a clear error — the adapter
  never guesses a dial target, because the intake and host sockets have
  different authorization allowlists (SP-07).
- Registration claims `presentation: "request_status"` /
  `input_transport: "external_tty"`: this adapter surfaces broker-verified
  status in-host; the credential value is typed on the external trusted
  terminal (`seqpass tui`). The masked in-host component only ever
  renders one asterisk per entered character, and is additionally gated
  behind `SEQPASS_PI_NATIVE_INPUT=1` — a build-level qualification switch
  that defaults off, so an unqualified build routes even
  `host_native_verified` requests to the external terminal.
- Registration records the host version from the `hostVersion` config
  field (set it to the real Pi binary version) and fails closed when it
  is absent: no hardcoded version is ever claimed.

Both transports use the shared wire client (`integrations/shared/ipc.ts`),
the same one the OpenCode V2 adapter uses. Credential entry is external
by default (`presentation: "request_status"`); the in-host masked
component renders an asterisk echo only and activates solely when the
broker's qualification decides host-native mode AND the build-level
qualification gate is on.

Status: functional against the declared `PiCustomUI` contract; live
qualification still requires an actual Pi installation.
