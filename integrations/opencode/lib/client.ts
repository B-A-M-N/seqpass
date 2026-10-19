/**
 * SeqPass trusted host client for OpenCode V2.
 *
 * Wraps the trusted intake and host IPC sockets. This is the only place
 * where credential bytes transit; they never enter OpenCode's session
 * state, tool results, or model context.
 *
 * S10 credential-buffer limits: fulfill() converts its JavaScript string
 * into an owned Buffer for base64 transport, but JS strings cannot be
 * reliably zeroed. Keep the lifetime short — do not store the value in
 * component state, logs, or session records — and let the local variable
 * go out of scope immediately after submission. This supports model-blind
 * operation without proving complete memory isolation from other code in
 * the host process.
 */
import { SeqPassIpcClient } from "../../shared/ipc";
import type { ProtectedInputNotice } from "../types";

export interface SeqPassHostClientConfig {
  intakeSocket: string;
  hostSocket: string;
  // SP-08: session credentials are optional at construction; register()
  // adopts the broker-minted pair afterwards.
  sessionID?: string;
  sessionToken?: string;
}

const maxPayloadBytes = 64 * 1024;

export class SeqPassHostClient {
  private intake: SeqPassIpcClient;
  private host: SeqPassIpcClient;
  private sessionID: string;
  private sessionToken: string;
  private pending: ProtectedInputNotice[] = [];
  private connected = false;

  constructor(config: SeqPassHostClientConfig) {
    this.intake = new SeqPassIpcClient(config.intakeSocket);
    this.host = new SeqPassIpcClient(config.hostSocket);
    this.sessionID = config.sessionID ?? "";
    this.sessionToken = config.sessionToken ?? "";
  }

  async connect(): Promise<void> {
    if (this.connected) return;
    await Promise.all([this.intake.connect(), this.host.connect()]);
    this.connected = true;
  }

  async register(hostVersion?: string): Promise<unknown> {
    await this.connect();
    const version = (hostVersion ?? "").trim();
    if (!version) {
      // The host version must be detected from the real binary, never
      // assumed: a hardcoded value would claim qualification for a host
      // build this adapter was never tested against.
      throw new Error("SeqPass requires the host version (api.app.version) to register");
    }
    const result = await this.intake.call("host.register", {
      host_kind: "opencode",
      host_version: version,
      adapter_version: "0.1.0",
      // Presentation honestly describes what this adapter offers: it
      // surfaces broker-verified request status only. Credential bytes
      // are typed on the external trusted terminal, which owns the
      // protected-intake transport. The broker never trusts these flags
      // as security evidence (qualification decides the input mode) —
      // and this build has no masked native field (lib/nativeInput).
      presentation: "request_status",
      input_transport: "external_tty",
      supports_resume: "true",
      supports_cancel_prompt: "true",
      supports_multiple_pending: "true",
    });
    // SP-08: capture the newly minted session/token from registration
    // so subsequent host-domain calls use the current credentials.
    if (result && typeof result === "object") {
      const m = result as { session?: { id?: string }; token?: { token?: string } };
      if (m.session?.id) this.sessionID = m.session.id;
      if (m.token?.token) this.sessionToken = m.token.token;
    }
    return result;
  }

  private hostParams(requestID: string): Record<string, unknown> {
    return {
      session_id: this.sessionID,
      session_token: this.sessionToken,
      request_id: requestID,
    };
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

  pendingCount(): number {
    return this.pending.length;
  }

  async refresh(requestID: string): Promise<void> {
    await this.connect();
    const data = await this.host.call("host.notice", this.hostParams(requestID));
    if (typeof data === "object" && data !== null) {
      const existing = this.pending.findIndex(n => n.request_id === requestID);
      const notice = data as ProtectedInputNotice;
      if (existing >= 0) this.pending[existing] = notice;
      else this.pending.push(notice);
    }
  }

  async fulfill(requestID: string, revision: number, value: string): Promise<void> {
    // Validate before dialing: an oversized payload must be refused even
    // when the broker is unreachable, and dialing must not be the error
    // surfaced to the operator.
    if (Buffer.byteLength(value, "utf-8") > maxPayloadBytes) {
      throw new Error("payload exceeds 64 KiB limit");
    }
    await this.connect();
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
    this.connected = false;
    await this.intake.close();
    await this.host.close();
  }
}
