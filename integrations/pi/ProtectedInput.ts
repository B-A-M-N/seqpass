/**
 * Protected credential entry component via ctx.ui.custom().
 *
 * Renders masked input only. The value goes through the trusted intake
 * socket with the exact reviewed revision; it never enters session state
 * or tool results.
 *
 * Placeholder contract; requires actual Pi TUI runtime to complete and
 * qualify. See plan §5 PI-02.
 */
import type { ProtectedInputNotice } from "./types";
import type { SeqPassClient } from "./client";

export function ProtectedInput(
  notice: ProtectedInputNotice,
  client: SeqPassClient,
) {
  return {
    title: `Enter ${notice.data_kind} for ${notice.recipient_label}`,
    masked: true,
    actions: {
      submit: (value: string) =>
        client.fulfill(notice.request_id, notice.request_revision, value),
      cancel: () => client.dismissPrompt(notice.request_id),
    },
  };
}
