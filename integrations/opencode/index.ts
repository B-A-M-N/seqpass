/**
 * SeqPass OpenCode V2 CLI plugin entry point.
 *
 * Implements the `@opencode-ai/plugin` TuiPluginModule contract for
 * OpenCode v2.0.x. The protected input path submits through SeqPass's
 * trusted intake socket, never through OpenCode's model-facing session
 * APIs or composer.
 */
import type { TuiPluginModule, TuiPluginApi } from "@opencode-ai/plugin/tui";
import type { JSX } from "@opentui/solid";
import { SeqPassHostClient } from "./lib/client";
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

  const sessionID = options?.sessionID as string | undefined;
  const sessionToken = options?.sessionToken as string | undefined;
  if (!sessionID || !sessionToken) {
    api.ui.toast({ title: "SeqPass", message: "Missing authenticated host session", variant: "error" });
    return;
  }

  const client = new SeqPassHostClient({ intakeSocket, hostSocket, sessionID, sessionToken });
  try {
    await client.connect();
    await client.register();
  } catch (err) {
    api.ui.toast({ title: "SeqPass", message: "SeqPass broker unavailable", variant: "error" });
    return;
  }

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
          await client.refresh(notice.request_id);
          // SP-05: use the protected input component, which handles the
          // external-tty fallback and gates native input on broker
          // qualification. The raw DialogPrompt is never opened directly.
          try {
            SeqPassProtectedInputDialog(notice, client, api.ui);
          } catch (err) {
            api.ui.toast({ title: "SeqPass", message: err instanceof Error ? err.message : String(err), variant: "error" });
          }
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
        if (count <= 0) return null;
        return { jsx: `SeqPass: ${count} pending` };
      },
    },
  } as any);
};

// Re-export the protected-input component so tests can exercise it without
// opening a live dialog.
export { SeqPassProtectedInputDialog };
