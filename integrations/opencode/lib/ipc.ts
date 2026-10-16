/**
 * SeqPass IPC wire client for OpenCode V2.
 *
 * Implements the Go broker's newline-delimited JSON-over-Unix-socket
 * protocol. Request shape: {"id":"cN","method":"...","params":{...}}.
 * Response shape: {"id":"cN","ok":true,"data":...} or
 * {"id":"cN","ok":false,"error":"..."}.
 *
 * This is the only module that opens Unix sockets. Credential bytes pass
 * through it only during fulfillment and never enter OpenCode's session
 * state, tool results, or model context.
 */
import { connect } from "node:net";

const defaultCallTimeout = 60_000;

export interface SeqPassRequest {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface SeqPassResponse {
  id: string;
  ok: boolean;
  data?: unknown;
  error?: string;
}

export class SeqPassIpcClient {
  private conn: ReturnType<typeof connect> | null = null;
  private seq = 0;
  private buffer = "";

  constructor(private socketPath: string) {}

  async connect(): Promise<void> {
    if (this.conn) return;
    this.conn = connect(this.socketPath);
    this.conn.setEncoding("utf-8");
    await new Promise<void>((resolve, reject) => {
      this.conn!.once("connect", () => resolve());
      this.conn!.once("error", (err) => reject(err));
    });
  }

  async close(): Promise<void> {
    if (this.conn) {
      this.conn.destroy();
      this.conn = null;
    }
  }

  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    if (!this.conn) throw new Error("not connected");
    const id = `c${++this.seq}`;
    const req: SeqPassRequest = { id, method, params };
    this.conn.write(JSON.stringify(req) + "\n");

    return await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error("broker timeout"));
      }, defaultCallTimeout);

      const onData = (chunk: string) => {
        this.buffer += chunk;
        const lines = this.buffer.split("\n");
        this.buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          let resp: SeqPassResponse;
          try {
            resp = JSON.parse(line);
          } catch {
            continue;
          }
          if (resp.id !== id) continue;
          cleanup();
          if (resp.ok) resolve(resp.data);
          else reject(new Error(resp.error ?? "broker error"));
          return;
        }
      };

      const cleanup = () => {
        clearTimeout(timeout);
        this.conn!.off("data", onData);
      };
      this.conn!.on("data", onData);
    });
  }
}
