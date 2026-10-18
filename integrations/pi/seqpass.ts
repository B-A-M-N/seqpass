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
  agentSocket?: string;
  // SP-08: sessionID/sessionToken may be empty at startup. When absent,
  // the trusted host must call register() to obtain fresh credentials from
  // the broker, then store them outside model-controlled configuration.
  sessionID?: string;
  sessionToken?: string;
}

export function registerSeqPass(config: SeqPassExtensionConfig) {
  const client = new SeqPassClient(config);
  let sessionReady = false;

  // SP-08: async bootstrap — register the host session if credentials are
  // not yet provisioned. The token is held only by this trusted adapter.
  const ensureSession = async () => {
    if (sessionReady) return;
    if (config.sessionID && config.sessionToken) {
      sessionReady = true;
      return;
    }
    await client.connect();
    const result = await client.register();
    if (result && typeof result === "object") {
      const m = result as { session?: { id?: string }; token?: { token?: string } };
      if (m.session?.id) client.setSession(m.session.id, m.token?.token ?? "");
      sessionReady = true;
    }
  };

  return {
    registerTool: (pi: any) => {
      pi.registerTool("relay_request", {
        description: "Request protected credential handoff for a registered recipient",
        handler: async (args: any) => {
          await ensureSession();
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
          await ensureSession();
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
        await ensureSession();
        await client.connect();
        const notice = await client.getPendingRequest();
        if (!notice) return;
        await ctx.ui.notify("SeqPass", "Pending protected input request");
        const result = ProtectedInput(notice, client, ctx.ui);
        // SP-05: when the broker issues external_tty mode, the fallback
        // result directs the user to the external trusted terminal instead
        // of opening a native input widget.
        if ("fallback" in result && (result as any).fallback) {
          await ctx.ui.notify("SeqPass", (result as any).message);
          return;
        }
        await ctx.ui.custom(result);
      });
    },
  };
}
