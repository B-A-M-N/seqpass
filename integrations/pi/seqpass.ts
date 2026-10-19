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
import type { ProtectedInputNotice } from "./types";

export interface SeqPassExtensionConfig {
  intakeSocket: string;
  hostSocket: string;
  // SP-10: the host version must be configured from the real Pi binary
  // version, never hardcoded: registration records it as qualification
  // evidence. An empty version fails registration closed.
  hostVersion: string;
  agentSocket?: string;
  // SP-08: sessionID/sessionToken may be empty at startup. When absent,
  // the trusted host must call register() to obtain fresh credentials from
  // the broker, then store them outside model-controlled configuration.
  sessionID?: string;
  sessionToken?: string;
}

// Structural seam so tests can drive the extension with a stub client.
// The real client satisfies this without modification.
export interface SeqPassClientLike {
  connect(): Promise<void>;
  connectAgent(): Promise<void>;
  register(hostVersion?: string): Promise<unknown>;
  setSession(sessionID: string, sessionToken: string): void;
  requestRelay(args: { destination_id: string; data_kind: string; purpose?: string; ttl_seconds?: number }): Promise<{ request_id?: string; status: string; error?: string }>;
  getStatus(requestID: string): Promise<{ status: string; error?: string }>;
  getPendingRequest(): Promise<ProtectedInputNotice | null>;
  fulfill(requestID: string, revision: number, value: string): Promise<void>;
  dismissPrompt(requestID: string): Promise<void>;
  close(): Promise<void> | void;
}

export function registerSeqPass(config: SeqPassExtensionConfig, deps?: { client?: SeqPassClientLike }) {
  const client: SeqPassClientLike = deps?.client ?? new SeqPassClient(config);
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
    const result = await client.register(config.hostVersion);
    if (result && typeof result === "object") {
      const m = result as { session?: { id?: string }; token?: { token?: string } };
      // Adopt the broker-minted credentials only as a pair. A partial
      // response must not install an unusable session identity that then
      // fails every host call with an authentication error.
      if (m.session?.id && m.token?.token) {
        client.setSession(m.session.id, m.token.token);
        sessionReady = true;
      }
    }
    if (!sessionReady) {
      throw new Error("SeqPass host session bootstrap failed");
    }
  };

  return {
    registerTool: (pi: any) => {
      pi.registerTool("relay_request", {
        description: "Request protected credential handoff for a registered recipient",
        handler: async (args: any) => {
          await ensureSession();
          // Fail closed on malformed agent input before it reaches the
          // broker; the sanitized error result keeps the wire contract.
          if (typeof args?.destination_id !== "string" || !args.destination_id) {
            return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "destination_id is required" }) }], details: {} };
          }
          if (typeof args?.data_kind !== "string" || !args.data_kind) {
            return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "data_kind is required" }) }], details: {} };
          }
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
          if (typeof args?.request_id !== "string" || !args.request_id) {
            return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "request_id is required" }) }], details: {} };
          }
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
