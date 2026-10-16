/**
 * SeqPass trusted host client for OpenCode V2.
 *
 * Wraps the trusted intake and host IPC sockets. This is the only place
 * where credential bytes transit; they never enter OpenCode's session
 * state, tool results, or model context.
 *
 * This file is a contract stub. The actual IPC wire client must be
 * implemented against the Go broker's JSON-over-Unix-socket protocol
 * (see internal/ipc/client.go for the reference format).
 */
import { SeqPassIpcClient } from "./ipc";
import type { ProtectedInputNotice } from "../types";

export interface SeqPassHostClientConfig {
  intakeSocket: string;
  hostSocket: string;
  sessionID: string;
  sessionToken: string;
}

export class SeqPassHostClient {
  private intake: SeqPassIpcClient;
  private host: SeqPassIpcClient;
  private sessionID: string;
  private sessionToken: string;
  private pending: ProtectedInputNotice[] = [];

  constructor(config: SeqPassHostClientConfig) {
    this.intake = new SeqPassIpcClient(config.intakeSocket);
    this.host = new SeqPassIpcClient(config.hostSocket);
    this.sessionID = config.sessionID;
    this.sessionToken = config.sessionToken;
  }

  private hostParams(requestID: string): Record<string, unknown> {
    return {
      session_id: this.sessionID,
      session_token: this.sessionToken,
      request_id: requestID,
    };
  }

  async getPendingRequest(): Promise<ProtectedInputNotice | null> {
    const notice = this.pending[0];
    if (!notice) return null;
    return notice;
  }

  pendingCount(): number {
    return this.pending.length;
  }

  async refresh(requestID: string): Promise<void> {
    const data = await this.host.call("host.notice", this.hostParams(requestID));
    if (typeof data === "object" && data !== null) {
      const existing = this.pending.findIndex(n => n.request_id === requestID);
      const notice = data as ProtectedInputNotice;
      if (existing >= 0) this.pending[existing] = notice;
      else this.pending.push(notice);
    }
  }

  async fulfill(requestID: string, revision: number, value: string): Promise<void> {
    await this.intake.call("intake.fulfill", {
      request_id: requestID,
      request_revision: revision,
      payload: Buffer.from(value, "utf-8").toString("base64"),
    });
  }

  async reject(requestID: string, revision: number): Promise<void> {
    await this.intake.call("intake.reject", {
      request_id: requestID,
      request_revision: revision,
    });
  }

  async dismissPrompt(requestID: string): Promise<void> {
    await this.host.call("host.cancel_prompt", this.hostParams(requestID));
  }

  async close(): Promise<void> {
    await this.intake.close();
    await this.host.close();
  }
}
