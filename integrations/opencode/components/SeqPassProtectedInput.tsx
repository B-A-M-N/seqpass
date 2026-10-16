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
import type { ProtectedInputNotice } from "../types";
import type { SeqPassHostClient } from "../lib/client";

export function SeqPassProtectedInputDialog(
  notice: ProtectedInputNotice,
  client: SeqPassHostClient,
) {
  return {
    title: `Enter ${notice.data_kind} for ${notice.recipient_label}`,
    masked: true,
    inputMode: "password",
    actions: {
      submit: (value: string) =>
        client.fulfill(notice.request_id, notice.request_revision, value),
      cancel: () => client.dismissPrompt(notice.request_id),
    },
  };
}
