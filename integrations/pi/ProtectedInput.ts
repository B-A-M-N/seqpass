/**
 * Protected credential entry component via ctx.ui.custom().
 *
 * Implements masked input through Pi's actual TUI API, with keyboard
 * handling and explicit cleanup. The value goes through the trusted
 * intake socket with the exact reviewed revision; it never enters
 * session state or tool results.
 */
import type { ProtectedInputNotice } from "./types";
import type { SeqPassClient } from "./client";

export interface PiCustomUI {
  render: (text: string) => void;
  setKeyHandler: (handler: (key: string) => void) => void;
  close: () => void;
}

export function ProtectedInput(
  notice: ProtectedInputNotice,
  client: SeqPassClient,
  ui: PiCustomUI,
) {
  // SP-05: when the broker issues external_tty mode, the adapter must
  // direct the user to the external trusted-terminal flow instead of
  // rendering a native prompt that cannot prove process isolation.
  if (notice.input_mode !== "host_native_verified") {
    return ExternalTTYFallback(notice);
  }
  let value = "";
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    value = "";
    ui.close();
  };

  const redraw = () => {
    ui.render(`SeqPass ${notice.request_id} — enter ${notice.data_kind} for ${notice.recipient_label} (masked)`);
  };

  ui.setKeyHandler((key: string) => {
    if (closed) return;
    if (key === "escape") {
      void client.dismissPrompt(notice.request_id);
      close();
      return;
    }
    if (key === "backspace") {
      value = value.slice(0, -1);
      redraw();
      return;
    }
    if (key === "enter") {
      const submitted = value;
      value = "";
      close();
      void client.fulfill(notice.request_id, notice.request_revision, submitted);
      return;
    }
    if (key.length === 1) {
      value += key;
      redraw();
    }
  });

  redraw();
  return {
    get masked() {
      // This property only reports that the render text includes "(masked)".
      // It does NOT prove that other code in this process cannot observe
      // the value — that requires independent qualification evidence.
      return true;
    },
    close,
  };
}

// ExternalTTYFallback returns a display-only result directing the user to
// the external trusted terminal. The adapter never collects or renders a
// credential-bearing input field in this mode.
function ExternalTTYFallback(notice: ProtectedInputNotice) {
  return {
    get masked() { return false; },
    get fallback() { return true; },
    message: (
      `SeqPass request ${notice.request_id} requires external trusted-terminal input.\n` +
      `Run: seqpass relay fulfill ${notice.request_id} --intake-socket ${notice.host_session_id}`
    ),
    close: () => {},
  };
}
