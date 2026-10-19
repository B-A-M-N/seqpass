/**
 * SeqPass OpenCode V2 CLI plugin entry point.
 *
 * Implements the `@opencode-ai/plugin` TuiPluginModule contract for the
 * OpenCode v2 CLI (package version ^1.18.3 — there is no 2.x release).
 * The adapter surfaces broker-verified request status
 * in-host (display-only inbox footer + review command); credential bytes
 * are typed on the external trusted terminal (`seqpass tui`) and submit
 * through SeqPass's trusted intake socket — never through OpenCode's
 * model-facing session APIs or composer.
 */
import type { TuiPluginModule, TuiPluginApi } from "@opencode-ai/plugin/tui";
import type { ProtectedInputNotice } from "./types";
import { SeqPassHostClient } from "./lib/client";
import { inboxOptions } from "./lib/nativeInput";
import { SeqPassProtectedInputDialog } from "./components/SeqPassProtectedInput";
import { seqPassFooter } from "./components/SeqPassFooter";

export const id = "seqpass";

const pollIntervalMs = 5_000;

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
  // Dispose before the first dial: a failed registration must not leak
  // two open IPC sockets for the host's lifetime.
  api.lifecycle.onDispose(() => {
    void client.close();
  });
  try {
    await client.connect();
    await client.register();
  } catch {
    void client.close();
    api.ui.toast({ title: "SeqPass", message: "SeqPass broker unavailable", variant: "error" });
    return;
  }

  // SP-02: keep the display-only inbox count current. The poll only
  // refreshes broker-verified pending metadata; nothing here touches
  // credential bytes.
  const poll = setInterval(() => {
    client.listPendingRequests().then(() => {
      api.renderer.requestRender();
    }).catch(() => {
      // Broker temporarily unreachable: keep the last verified count.
    });
  }, pollIntervalMs);
  api.lifecycle.onDispose(() => {
    clearInterval(poll);
  });

  // Open the review flow for one broker-verified notice. The dialog
  // component owns the SP-05 gating: this adapter build has no masked
  // native field, so it routes to the external trusted terminal.
  const openReview = (notice: ProtectedInputNotice) => {
    try {
      SeqPassProtectedInputDialog(notice, client, api.ui);
    } catch (err) {
      api.ui.toast({ title: "SeqPass", message: err instanceof Error ? err.message : String(err), variant: "error" });
    }
  };

  const showInbox = async () => {
    const pending = await client.listPendingRequests();
    if (pending.length === 0) {
      api.ui.toast({ title: "SeqPass", message: "No pending request" });
      return;
    }
    // Display-only inbox: always list broker-verified requests — even a
    // single one — so the operator sees recipient, data kind, and
    // consumption metadata before choosing what to review. Only notice
    // metadata is shown; credential bytes never enter this surface.
    api.ui.dialog.replace(() => api.ui.DialogSelect<{ request_id: string }>({
      title: "SeqPass — pending requests",
      options: inboxOptions(pending),
      onSelect: (option) => {
        api.ui.dialog.clear();
        const notice = pending.find(n => n.request_id === option.value.request_id);
        if (notice) openReview(notice);
      },
    }));
  };

  api.keymap.registerLayer({
    commands: [
      {
        name: "seqpass.review",
        description: "Open the SeqPass display-only inbox and review pending relay requests",
        category: "SeqPass",
        slash: { name: "seqpass", aliases: [] },
        run: async () => {
          try {
            await showInbox();
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

  api.slots.register(seqPassFooter(() => client.pendingCount()));
};

// Re-export the protected-input component so tests can exercise it without
// opening a live dialog.
export { SeqPassProtectedInputDialog };
