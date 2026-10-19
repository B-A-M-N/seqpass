/**
 * Protected credential entry dialog contract.
 *
 * SP-05: the value goes to the trusted SeqPass intake socket with the
 * exact reviewed revision; it never enters OpenCode's session state,
 * composer, or model context. In-host entry is additionally gated by
 * lib/nativeInput: this adapter build has no verified masked field, so
 * it always routes to the external trusted terminal regardless of the
 * broker-issued input mode. The native branch below only activates once
 * NATIVE_MASKED_INPUT_SUPPORTED is flipped with a masking-capable plugin
 * API and the deployment is re-qualified.
 */
import type { TuiPluginApi } from "@opencode-ai/plugin/tui";
import type { ProtectedInputNotice } from "../types";
import type { SeqPassHostClient } from "../lib/client";
import { selectNativeInput, EXTERNAL_TUI_HINT } from "../lib/nativeInput";

export function SeqPassProtectedInputDialog(
  notice: ProtectedInputNotice,
  client: SeqPassHostClient,
  ui: TuiPluginApi["ui"],
) {
  if (!ui) throw new Error("OpenCode UI API unavailable");
  const decision = selectNativeInput(notice.input_mode);
  if (!decision.allowed) {
    return ExternalTTYFallback(notice, ui, decision.reason);
  }
  const close = () => {
    ui.dialog.clear();
  };
  ui.dialog.replace(() => ui.DialogPrompt({
    title: `Enter ${notice.data_kind} for ${notice.recipient_label}`,
    description: () => (
      <text content={`Recipient ${notice.recipient_label}; ${notice.consumption}; reviewed revision ${notice.request_revision}.`} />
    ),
    placeholder: "Paste the credential; it will not be shown.",
    onConfirm: async (value: string) => {
      try {
        await client.fulfill(notice.request_id, notice.request_revision, value);
      } finally {
        close();
      }
    },
    onCancel: () => {
      void client.dismissPrompt(notice.request_id);
      close();
    },
  }), close);
}

// ExternalTTYFallback returns a display-only result directing the user to
// the external trusted terminal. The adapter never collects or renders a
// credential-bearing input field in this mode.
function ExternalTTYFallback(
  notice: ProtectedInputNotice,
  ui: TuiPluginApi["ui"],
  reason: string,
) {
  ui.toast({
    title: "SeqPass",
    message:
      `Request ${notice.request_id} requires external trusted-terminal input. ` +
      `Run in your own terminal: ${EXTERNAL_TUI_HINT} (${reason})`,
    variant: "info",
  });
  return {
    get masked() { return false; },
    get fallback() { return true; },
    close: () => {},
  };
}
