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

const maxFrameBytes = 1_048_576;

export class SeqPassIpcClient {
  private conn: ReturnType<typeof connect> | null = null;
  private seq = 0;
  private generation = 0;
  private buffer = "";
  private failures: ((err: Error) => void)[] = [];
  private pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (err: Error) => void;
    timeout: NodeJS.Timeout;
    generation: number;
  }>();
  private connecting: Promise<void> | null = null;

  constructor(private socketPath: string) {}

  async connect(): Promise<void> {
    if (this.conn && !this.conn.destroyed && this.conn.readyState === "open") return;
    // SP-15: single-flight connection establishment. Concurrent callers
    // share one connect promise instead of racing to open competing sockets.
    if (this.connecting) return this.connecting;
    this.connecting = this.doConnect();
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async doConnect(): Promise<void> {
    const generation = ++this.generation;
    if (this.conn) { this.conn.destroy(); this.conn = null; }
    const conn = connect(this.socketPath);
    conn.setEncoding("utf-8");
    conn.on("data", (chunk: string) => {
      if (generation === this.generation) this.handleData(chunk);
    });
    conn.on("error", (err: Error) => {
      if (generation === this.generation) this.fail(err);
    });
    conn.on("close", () => {
      if (generation === this.generation) this.fail(new Error("broker connection closed"));
    });
    await new Promise<void>((resolve, reject) => {
      conn.once("connect", () => resolve());
      conn.once("error", (err: Error) => reject(err));
    });
    if (generation !== this.generation) { conn.destroy(); return; }
    this.conn = conn;
    this.buffer = "";
  }

  private handleData(chunk: string) {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer, "utf-8") > maxFrameBytes) {
      this.fail(new Error("broker frame exceeds 1 MiB"));
      return;
    }
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      let resp: SeqPassResponse;
      try {
        resp = JSON.parse(line) as SeqPassResponse;
      } catch {
        this.fail(new Error("malformed broker response"));
        return;
      }
      if (!resp || typeof resp.id !== "string" || typeof resp.ok !== "boolean") {
        this.fail(new Error("invalid broker response shape"));
        return;
      }
      const entry = this.pending.get(resp.id);
      if (!entry) continue;
      this.pending.delete(resp.id);
      clearTimeout(entry.timeout);
      if (resp.ok) entry.resolve(resp.data);
      else entry.reject(new Error(resp.error ?? "broker error"));
    }
  }

  private fail(err: Error) {
    for (const cb of this.failures.splice(0)) cb(err);
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timeout);
      entry.reject(err);
    }
    this.pending.clear();
    this.buffer = "";
    if (this.conn) { this.conn.destroy(); this.conn = null; }
  }

  onDisconnect(cb: (err: Error) => void): () => void {
    this.failures.push(cb);
    return () => {
      this.failures = this.failures.filter(x => x !== cb);
    };
  }

  ready(): boolean {
    return !!this.conn && !this.conn.destroyed && this.conn.readyState === "open";
  }

  async close(): Promise<void> {
    this.generation++;
    this.fail(new Error("broker connection closed"));
  }

  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    // SP-08: reconnect on demand — a dropped connection must not silently
    // fail subsequent calls or be treated as a declined request.
    try {
      await this.connect();
    } catch {
      // Reset and try once more.
      this.generation++;
      this.conn = null;
      this.connecting = null;
      await this.connect();
    }
    const generation = this.generation;
    const id = `c${++this.seq}`;
    const req: SeqPassRequest = { id, method, params };
    return await new Promise((resolve, reject) => {
      // SP-15: per-request timeout, not a shared handle. Each call owns
      // its own timer; completing one never clears another's deadline.
      const timeout = setTimeout(() => {
        const entry = this.pending.get(id);
        if (entry) {
          this.pending.delete(id);
          entry.reject(new Error("broker timeout"));
        }
      }, defaultCallTimeout);
      this.pending.set(id, { resolve, reject, timeout, generation });
      if (!this.conn || !this.conn.writable) {
        clearTimeout(timeout);
        this.pending.delete(id);
        reject(new Error("not connected"));
        return;
      }
      this.conn.write(JSON.stringify(req) + "\n", () => {});
    });
  }
}
