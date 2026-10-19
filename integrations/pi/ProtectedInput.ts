/**
 * Protected credential entry component via ctx.ui.custom().
 *
 * Implements masked input through Pi's actual TUI API, with keyboard
 * handling and explicit cleanup. The value goes through the trusted
 * intake socket with the exact reviewed revision; it never enters
 * session state or tool results.
 *
 * The rendered surface only ever shows one asterisk per entered
 * character — the component has no code path that draws the value.
 * As with every in-host surface, this supports model-blind operation;
 * it does not prove that other code in the host process cannot observe
 * the value. That requires the independently qualified deployment
 * boundary (SP-05).
 */
import type { ProtectedInputNotice, SeqPassInputClient } from "./types";

export interface PiCustomUI {
  render: (text: string) => void;
  setKeyHandler: (handler: (key: string) => void) => void;
  close: () => void;
}

// SP-05: instructions shown for external_tty mode. The external trusted
// terminal is the operator's own `seqpass tui` session; the notice never
// carries socket paths (host_session_id is a session identifier, not a
// filesystem path), so the message only names the command. The TUI
// resolves the configured intake socket itself.
export function externalFallbackMessage(notice: ProtectedInputNotice): string {
  return (
    `SeqPass request ${notice.request_id} requires external trusted-terminal input.\n` +
    `Run in your own terminal: seqpass tui`
  );
}

export function maskedEcho(length: number): string {
  return "*".repeat(length);
}

export function ProtectedInput(
  notice: ProtectedInputNotice,
  client: SeqPassInputClient,
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
    // Masked progress only: never render the value itself.
    ui.render(
      `SeqPass ${notice.request_id} — enter ${notice.data_kind} for ${notice.recipient_label}: ${maskedEcho(value.length)}`,
    );
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
      // True by construction: the only render path draws asterisks
      // (maskedEcho) — the component has no code path that renders the
      // value. This does NOT prove that other code in this process
      // cannot observe the value; that requires independent
      // qualification evidence (SP-05).
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
    message: externalFallbackMessage(notice),
    close: () => {},
  };
}
