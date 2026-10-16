/**
 * SeqPass Pi extension entry point.
 *
 * Registers relay_request / relay_status tools and the native protected
 * input component via ctx.ui.custom(). The agent receives only opaque
 * request IDs and sanitized status — never credential bytes.
 */
import { SeqPassClient } from "./client";
import { ProtectedInput } from "./ProtectedInput";
import { SeqPassStatus } from "./SeqPassStatus";

export interface SeqPassExtensionConfig {
  intakeSocket: string;
  hostSocket: string;
  sessionID: string;
  sessionToken: string;
}

export function registerSeqPass(config: SeqPassExtensionConfig) {
  const client = new SeqPassClient(config);

  return {
    registerTool: (pi: any) => {
      pi.registerTool("relay_request", {
        description: "Request protected credential handoff for a registered recipient",
        handler: async (args: any) => {
          const result = await client.requestRelay(args);
          return {
            content: [{ type: "text", text: JSON.stringify(result) }],
            details: {},
          };
        },
      });
      pi.registerTool("relay_status", {
        description: "Check sanitized relay request status",
        handler: async (args: any) => {
          const result = await client.getStatus(args.request_id);
          return {
            content: [{ type: "text", text: JSON.stringify(result) }],
            details: {},
          };
        },
      });
    },
    registerCommand: (pi: any) => {
      pi.registerCommand("/seqpass", async (ctx: any) => {
        if (!ctx.hasUI) {
          return;
        }
        const notice = await client.getPendingRequest();
        if (!notice) return;
        await ctx.ui.notify("SeqPass", "Pending protected input request");
        await ctx.ui.custom(ProtectedInput(notice, client));
      });
    },
  };
}
