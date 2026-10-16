/**
 * SeqPass trusted host client for Pi.
 *
 * Wraps the trusted intake and host IPC sockets. This is the only place
 * where credential bytes transit; they never enter Pi session state,
 * pi.appendEntry(), or tool results.
 */
import type { SeqPassExtensionConfig } from "./seqpass";
import type { ProtectedInputNotice } from "./types";

export class SeqPassClient {
  private config: SeqPassExtensionConfig;
  private pending: ProtectedInputNotice[] = [];

  constructor(config: SeqPassExtensionConfig) {
    this.config = config;
  }

  async requestRelay(args: any): Promise<{ request_id?: string; status: string; error?: string }> {
    // TODO: implement IPC call to broker's relay.request. Agent-facing
    // only; returns opaque ID and sanitized status. See plan §5 PI-01.
    return { status: "error", error: "not implemented" };
  }

  async getStatus(requestID: string): Promise<{ status: string; error?: string }> {
    // TODO: implement IPC call to broker's relay.status.
    return { status: "error", error: "not implemented" };
  }

  async getPendingRequest(): Promise<ProtectedInputNotice | null> {
    // TODO: implement host.notice call via IPC client. See plan §5 PI-02.
    return this.pending[0] ?? null;
  }

  async fulfill(requestID: string, revision: number, value: string): Promise<void> {
    // TODO: send to trusted intake socket with exact revision. See plan §5 PI-02.
  }

  async reject(requestID: string, revision: number): Promise<void> {
    // TODO: send rejection via trusted intake socket.
  }

  async dismissPrompt(requestID: string): Promise<void> {
    // TODO: send display-only dismissal via host socket.
  }
}
