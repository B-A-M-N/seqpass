/**
 * Broker-verified request review dialog.
 *
 * Renders only fields from a ProtectedInputNotice. The agent's purpose
 * text is shown as explicitly untrusted annotation; it can never
 * overwrite recipient, consumption, or assurance facts.
 *
 * This is a JSX-compatible description object. The actual OpenCode V2
 * renderer (via api.ui.dialog.replace) accepts Solid JSX components; the
 * wiring to the concrete JSX element is in the plugin entry point.
 */
import type { ProtectedInputNotice } from "../types";
import type { SeqPassHostClient } from "../lib/client";
import type { TuiPluginApi } from "@opencode-ai/plugin/tui";
import { SeqPassProtectedInputDialog } from "./SeqPassProtectedInput";

export function SeqPassReviewDialog(
  notice: ProtectedInputNotice,
  client: SeqPassHostClient,
  ui: TuiPluginApi["ui"],
) {
  return {
    title: "SeqPass — protected credential request",
    recipient: notice.recipient_label,
    dataKind: notice.data_kind,
    usage: notice.consumption,
    expires: notice.expires_at,
    assurance: notice.input_assurance,
    untrustedNote: notice.untrusted_purpose ?? "(none)",
    actions: {
      approve: () => SeqPassProtectedInputDialog(notice, client, ui),
      reject: () => client.reject(notice.request_id, notice.request_revision),
      dismiss: () => client.dismissPrompt(notice.request_id),
    },
  };
}
