/**
 * Display-only in-host inbox footer (SP-02).
 *
 * Registers an OpenCode `home_footer` slot that surfaces the number of
 * pending protected-input requests. It is strictly display-only: it
 * shows a count and nothing else — never recipient labels, data kinds,
 * request purposes, or credential bytes. Opening the review flow always
 * goes through the seqpass.review command, which re-fetches
 * broker-verified notices before rendering anything.
 *
 * The plugin uses the real `TuiSlotPlugin` contract (an id-less solid
 * slot plugin whose `slots` map renders JSX); the host assigns the id
 * and calls the renderer on each render pass. `renderer.requestRender()`
 * after each poll makes the count refresh without solid signals.
 */
import type { TuiSlotPlugin } from "@opencode-ai/plugin/tui";
import { footerText } from "../lib/nativeInput";

export function seqPassFooter(count: () => number): TuiSlotPlugin<{ home_footer: {} }> {
  return {
    slots: {
      home_footer: () => {
        return <text content={footerText(count()) ?? ""} />;
      },
    },
  };
}
