/**
 * SP-01/SP-05 capability gate for in-host credential collection.
 *
 * The OpenCode plugin surface (`@opencode-ai/plugin` TUI contract)
 * exposes `ui.DialogPrompt` and `ui.Prompt` for text entry, but neither offers a
 * masked/secure field — typed characters render in plaintext, and the
 * underlying `@opentui` `InputRenderable` has no mask option either. A
 * dialog that echoes a credential on screen cannot carry the
 * `host_native_verified` contract, so this adapter refuses to collect
 * credential bytes in-host and directs the operator to the external
 * trusted terminal instead.
 *
 * This gate is defense in depth on top of the broker: `SelectNativeMode`
 * issues `host_native_verified` only against an operator-accepted
 * qualification snapshot and never trusts adapter registration flags.
 * If a deployment is nevertheless qualified for native input while this
 * build lacks a masked field, the component still falls back to the
 * external trusted terminal rather than render an unmasked field.
 *
 * When a future plugin API ships a verified masked field, flip this
 * constant, re-qualify the host (host kind/version/adapter version feed
 * the qualification digest), and the native branch activates.
 */
export const NATIVE_MASKED_INPUT_SUPPORTED = false;

// The operator's own terminal is the external trusted surface; `seqpass
// tui` resolves the configured intake socket itself.
export const EXTERNAL_TUI_HINT = "seqpass tui";

export type NativeInputDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

export function selectNativeInput(
  inputMode: string,
  maskedSupported: boolean = NATIVE_MASKED_INPUT_SUPPORTED,
): NativeInputDecision {
  if (inputMode !== "host_native_verified") {
    return {
      allowed: false,
      reason:
        `broker-verified input mode "${inputMode}" requires the external ` +
        `trusted terminal (${EXTERNAL_TUI_HINT})`,
    };
  }
  if (!maskedSupported) {
    return {
      allowed: false,
      reason:
        "this adapter build has no verified masked input field, so in-host " +
        `credential entry is disabled; use the external trusted terminal ` +
        `(${EXTERNAL_TUI_HINT})`,
    };
  }
  return { allowed: true };
}

// Footer label for the in-host display-only inbox. Deliberately terse:
// it carries a count only — never recipient labels, data kinds, or any
// other request metadata.
export function footerText(count: number): string | null {
  if (!Number.isInteger(count) || count <= 0) return null;
  return count === 1 ? "SeqPass: 1 pending request" : `SeqPass: ${count} pending requests`;
}

// Inbox option mapping for the DialogSelect display-only listing. Titles
// and descriptions are broker-verified fields only; the agent-supplied
// untrusted_purpose annotation never mixes into them (it is rendered
// only by the review dialog, explicitly labeled as untrusted).
export function inboxOptions(
  pending: Array<{ request_id: string; recipient_label: string; data_kind: string; consumption: string; untrusted_purpose?: string }>,
): Array<{ title: string; value: { request_id: string }; description: string }> {
  return pending.map(n => ({
    title: `${n.recipient_label} — ${n.data_kind}`,
    value: { request_id: n.request_id },
    description: n.consumption,
  }));
}
