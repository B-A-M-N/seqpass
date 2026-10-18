/**
 * SeqPass trusted host client for Pi.
 *
 * Wraps the trusted intake and host IPC sockets. This is the only place
 * where credential bytes transit; they never enter Pi session state,
 * pi.appendEntry(), or tool results.
 *
 * S10 credential-buffer limits: fulfill() converts its JavaScript string
 * into an owned Buffer for base64 transport, but JS strings cannot be
 * reliably zeroed. Keep the lifetime short — do not store the value in
 * component state, logs, or session records — and let the local variable
 * go out of scope immediately after submission. This supports model-blind
 * operation without proving complete memory isolation from other code in
 * the Pi host process.
 */
import { SeqPassIpcClient } from "../opencode/lib/ipc";
import type { SeqPassExtensionConfig } from "./seqpass";
import type { ProtectedInputNotice } from "./types";

const maxPayloadBytes = 64 * 1024;

export class SeqPassClient {
  private intake: SeqPassIpcClient;
  private host: SeqPassIpcClient;
  private agent: SeqPassIpcClient;
  private sessionID: string;
  private sessionToken: string;
  private pending: ProtectedInputNotice[] = [];

  constructor(config: SeqPassExtensionConfig & { agentSocket?: string }) {
    this.intake = new SeqPassIpcClient(config.intakeSocket);
    this.host = new SeqPassIpcClient(config.hostSocket);
    // SP-07: agent-domain RPCs use a dedicated agent socket, not the
    // intake socket, which has a different authorization allowlist.
    this.agent = new SeqPassIpcClient(config.agentSocket ?? config.intakeSocket.replace(/\.intake$/, ""));
    // SP-08: sessionID/sessionToken may be empty at startup; register()
    // will populate them when the trusted host bootstraps.
    this.sessionID = config.sessionID ?? "";
    this.sessionToken = config.sessionToken ?? "";
  }

  // SP-08: update the session credentials after registration. The token
  // is held only by this trusted adapter instance, never written to config.
  setSession(sessionID: string, sessionToken: string): void {
    this.sessionID = sessionID;
    this.sessionToken = sessionToken;
  }

  private hostParams(requestID: string): Record<string, unknown> {
    return {
      session_id: this.sessionID,
      session_token: this.sessionToken,
      request_id: requestID,
    };
  }

  async connect(): Promise<void> {
    await Promise.all([this.intake.connect(), this.host.connect()]);
  }

  async connectAgent(): Promise<void> {
    await this.agent.connect();
  }

  async register(): Promise<unknown> {
    await this.connect();
    return await this.intake.call("host.register", {
      host_kind: "pi",
      host_version: "1.0",
      adapter_version: "0.1.0",
      presentation: "native",
      input_transport: "protected_intake",
      supports_cancel_prompt: "true",
      supports_multiple_pending: "true",
    });
  }

  async requestRelay(args: { destination_id: string; data_kind: string; purpose?: string; ttl_seconds?: number }): Promise<{ request_id?: string; status: string; error?: string }> {
    try {
      await this.agent.connect();
      const data = await this.agent.call("relay.request", args);
      const result = data as { request_id?: string; status?: string };
      return { request_id: result.request_id, status: result.status ?? "unknown" };
    } catch (err) {
      return { status: "error", error: err instanceof Error ? err.message : String(err) };
    }
  }

  async getStatus(requestID: string): Promise<{ status: string; error?: string }> {
    try {
      await this.agent.connect();
      const data = await this.agent.call("relay.status", { request_id: requestID });
      return { status: (data as { status?: string }).status ?? "unknown" };
    } catch (err) {
      return { status: "error", error: err instanceof Error ? err.message : String(err) };
    }
  }

  async getPendingRequest(): Promise<ProtectedInputNotice | null> {
    const pending = await this.listPendingRequests();
    return pending[0] ?? null;
  }

  async listPendingRequests(): Promise<ProtectedInputNotice[]> {
    await this.connect();
    const data = await this.host.call("host.pending", this.hostParams(""));
    if (!Array.isArray(data)) throw new Error("invalid pending request response");
    this.pending = data as ProtectedInputNotice[];
    return this.pending;
  }

  async fulfill(requestID: string, revision: number, value: string): Promise<void> {
    await this.connect();
    if (Buffer.byteLength(value, "utf-8") > maxPayloadBytes) {
      throw new Error("payload exceeds 64 KiB limit");
    }
    await this.intake.call("intake.fulfill", {
      request_id: requestID,
      request_revision: revision,
      payload: Buffer.from(value, "utf-8").toString("base64"),
    });
  }

  async reject(requestID: string, revision: number): Promise<void> {
    await this.connect();
    await this.intake.call("intake.reject", {
      request_id: requestID,
      request_revision: revision,
    });
  }

  async dismissPrompt(requestID: string): Promise<void> {
    await this.connect();
    await this.host.call("host.cancel_prompt", this.hostParams(requestID));
  }

  async close(): Promise<void> {
    await this.intake.close();
    await this.host.close();
    await this.agent.close();
  }
}
