/**
 * Protected credential entry dialog contract.
 *
 * Must be rendered with a masked field. The value goes to the trusted
 * SeqPass intake socket with the exact reviewed revision; it never
 * enters OpenCode's session state, composer, or model context.
 *
 * Placeholder contract; requires actual OpenCode V2 JSX wiring to
 * complete and qualify.
 */
import type { TuiPluginApi } from "@opencode-ai/plugin/tui";
import type { ProtectedInputNotice } from "../types";
import type { SeqPassHostClient } from "../lib/client";

export function SeqPassProtectedInputDialog(
  notice: ProtectedInputNotice,
  client: SeqPassHostClient,
  ui: TuiPluginApi["ui"],
) {
  if (!ui) throw new Error("OpenCode UI API unavailable");
  // SP-05: when the broker issues external_tty mode, the adapter must
  // direct the user to the external trusted-terminal flow instead of
  // rendering a native prompt that cannot prove process isolation.
  if (notice.input_mode !== "host_native_verified") {
    return ExternalTTYFallback(notice, ui);
  }
  let disposed = false;
  const close = () => {
    if (disposed) return;
    disposed = true;
    ui.dialog.clear();
  };
  ui.dialog.replace(() => ui.DialogPrompt({
    title: `Enter ${notice.data_kind} for ${notice.recipient_label}`,
    description: () => ({ type: "text", text: `Recipient ${notice.recipient_label}; ${notice.consumption}; reviewed revision ${notice.request_revision}.` } as any),
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
function ExternalTTYFallback(notice: ProtectedInputNotice, ui: TuiPluginApi["ui"]) {
  ui.toast({
    title: "SeqPass",
    message: `Request ${notice.request_id} requires external trusted-terminal input.`,
    variant: "info",
  });
  return {
    get masked() { return false; },
    get fallback() { return true; },
    close: () => {},
  };
}
