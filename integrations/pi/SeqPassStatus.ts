/**
 * Status notification component for pending/completed relay requests.
 * Renders only broker-verified public metadata; never credential bytes.
 */
import type { ProtectedInputNotice } from "./types";

export interface SeqPassStatusNotice extends ProtectedInputNotice {
  state: string;
}

export function SeqPassStatus(notice: SeqPassStatusNotice) {
  const state = notice.state;
  return {
    title: "SeqPass relay",
    body: `${notice.recipient_label} — ${state}`,
  };
}
