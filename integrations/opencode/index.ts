/**
 * SeqPass OpenCode V2 CLI plugin entry point.
 *
 * Implements the `@opencode-ai/plugin` TuiPluginModule contract for
 * OpenCode v2.0.x. The protected input path submits through SeqPass's
 * trusted intake socket, never through OpenCode's model-facing session
 * APIs or composer.
 */
import type { TuiPluginModule, TuiPluginApi } from "@opencode-ai/plugin/tui";
import { SeqPassHostClient } from "./lib/client";
import { SeqPassReviewDialog } from "./components/SeqPassReview";
import { SeqPassProtectedInputDialog } from "./components/SeqPassProtectedInput";

export const id = "seqpass";

export const tui: TuiPluginModule["tui"] = async (
  api: TuiPluginApi,
  options: Record<string, unknown> | undefined,
) => {
  const intakeSocket = options?.intakeSocket as string | undefined;
  const hostSocket = options?.hostSocket as string | undefined;
  if (!intakeSocket || !hostSocket) {
    return;
  }

  const client = new SeqPassHostClient({ intakeSocket, hostSocket });

  api.keymap.registerLayer({
    commands: [
      {
        name: "seqpass.review",
        description: "Open broker-verified SeqPass relay review",
        category: "SeqPass",
        slash: { name: "seqpass", aliases: [] },
        run: async (ctx: any) => {
          const notice = await client.getPendingRequest();
          if (!notice) {
            api.ui.toast({ title: "SeqPass", message: "No pending request" });
            return;
          }
          // The keymap layer does not own a dialog stack; navigate to the
          // review route instead. Actual dialog wiring uses api.ui.dialog.
          api.route.navigate("seqpass-review");
        },
      },
    ],
    bindings: [
      { key: "leader s p", command: "seqpass.review" },
    ],
  });

  api.slots.register({
    slots: {
      home_footer: () => {
        const count = client.pendingCount();
        return count > 0 ? { jsx: `SeqPass: ${count} pending` } as any : null;
      },
    },
  } as any);
};

// Re-export the protected-input component so tests can exercise it without
// opening a live dialog.
export { SeqPassProtectedInputDialog };
