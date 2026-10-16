/**
 * Status notification component for pending/completed relay requests.
 * Renders only broker-verified public metadata; never credential bytes.
 */
import type { ProtectedInputNotice } from "./types";

export function SeqPassStatus(notice: ProtectedInputNotice, state: string) {
  return {
    title: "SeqPass relay",
    body: `${notice.recipient_label} — ${state}`,
  };
}
