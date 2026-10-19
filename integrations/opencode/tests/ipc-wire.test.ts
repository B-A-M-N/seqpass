/**
 * Wire-contract tests for the shared SeqPass IPC client against a real
 * in-process unix-socket server. This module is the one transport shared
 * by every trusted adapter, so framing, demuxing, error propagation, and
 * deadlines are verified end-to-end here.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createServer, Server, Socket, type ListenOptions } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SeqPassIpcClient } from "../../shared/ipc";

let server: Server | null = null;
let dir: string | null = null;
let openSockets: Socket[] = [];
const clients: Array<{ close(): Promise<void> | void }> = [];

function trackServer(connections: (sock: Socket) => void): Server {
  openSockets = [];
  return createServer((sock: Socket) => {
    openSockets.push(sock);
    connections(sock);
  });
}

function echoServer(
  handler: (req: any) => Record<string, unknown> | Promise<Record<string, unknown>>,
): Promise<string> {
  dir = mkdtempSync(join(tmpdir(), "seqpass-ipc-test-"));
  const path = join(dir, "broker.sock");
  server = trackServer((sock) => {
    let buffer = "";
    sock.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id: string };
        Promise.resolve(handler(req)).then((out) => {
          sock.write(JSON.stringify({ id: req.id, ...out }) + "\n");
        });
      }
    });
  });
  return new Promise((resolve, reject) => {
    server!.listen({ path }, () => resolve(path));
    server!.on("error", reject);
  });
}

// A broker that accepts connections but never answers — for deadline and
// connection-drop tests.
function silentServer(): Promise<string> {
  dir = mkdtempSync(join(tmpdir(), "seqpass-ipc-test-"));
  const path = join(dir, "broker.sock");
  server = trackServer(() => {});
  return new Promise((resolve, reject) => {
    server!.listen({ path }, () => resolve(path));
    server!.on("error", reject);
  });
}

afterEach(() => {
  for (const c of clients.splice(0)) void c.close();
  for (const s of openSockets.splice(0)) s.destroy();
  if (server) server.close();
  server = null;
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = null;
});

describe("SeqPassIpcClient wire contract", () => {
  it("resolves a call with the broker's data payload", async () => {
    const path = await echoServer(() => ({ ok: true, data: { status: "pending" } }));
    const client = new SeqPassIpcClient(path);
    clients.push(client);
    await expect(client.call("host.pending", { session_id: "s" })).resolves.toEqual({ status: "pending" });
  });

  it("rejects with the broker's error string on ok:false", async () => {
    const path = await echoServer(() => ({ ok: false, error: "host is not authorized for this agent principal" }));
    const client = new SeqPassIpcClient(path);
    clients.push(client);
    await expect(client.call("host.register")).rejects.toThrow("not authorized");
  });

  it("demuxes concurrent calls to the matching response ids", async () => {
    // The server delays the second call so responses arrive OUT of
    // request order: FIFO demux would pair each caller with the wrong
    // payload.
    const path = await echoServer((req) => {
      const out = {
        ok: true,
        data: { echoed_method: req.method, echoed_params: req.params },
      };
      if (req.method === "host.notice") {
        return new Promise((resolve) => setTimeout(() => resolve(out), 120));
      }
      return out;
    });
    const client = new SeqPassIpcClient(path);
    clients.push(client);
    const [a, b, c] = await Promise.all([
      client.call("host.pending", { n: 1 }),
      client.call("host.notice", { n: 2 }),
      client.call("host.status"),
    ]);
    expect((a as any).echoed_method).toBe("host.pending");
    expect((b as any).echoed_method).toBe("host.notice");
    expect((c as any).echoed_method).toBe("host.status");
    expect((a as any).echoed_params).toEqual({ n: 1 });
  });

  it("fails every pending call when the connection drops", async () => {
    const path = await silentServer();
    const client = new SeqPassIpcClient(path, { callTimeoutMs: 5_000 });
    clients.push(client);
    const pendingCall = client.call("host.pending");
    // Give the client a moment to write, then kill the connection the
    // way a broker restart would.
    await new Promise((r) => setTimeout(r, 50));
    for (const s of openSockets) s.destroy();
    await expect(pendingCall).rejects.toThrow();
  });

  it("enforces the per-request deadline", async () => {
    const path = await silentServer();
    const client = new SeqPassIpcClient(path, { callTimeoutMs: 120 });
    clients.push(client);
    await expect(client.call("host.pending")).rejects.toThrow("broker timeout");
  });

  it("fails on a malformed response frame", async () => {
    dir = mkdtempSync(join(tmpdir(), "seqpass-ipc-test-"));
    const path = join(dir, "broker.sock");
    server = createServer((sock) => {
      sock.on("data", () => sock.write("not-json\n"));
    });
    await new Promise<void>((resolve, reject) => {
      server!.listen({ path }, () => resolve());
      server!.on("error", reject);
    });
    const client = new SeqPassIpcClient(path);
    clients.push(client);
    await expect(client.call("host.status")).rejects.toThrow("malformed broker response");
  });
});

describe("SeqPassHostClient payload validation", () => {
  it("refuses oversized payloads without dialing the broker", async () => {
    const { SeqPassHostClient } = await import("../lib/client");
    const client = new SeqPassHostClient({
      intakeSocket: join(dir ?? ".", "nonexistent.sock"),
      hostSocket: join(dir ?? ".", "nonexistent.sock"),
      sessionID: "host-1",
      sessionToken: "tok-test",
    });
    const oversized = "x".repeat(64 * 1024 + 1);
    await expect(client.fulfill("req-1", 1, oversized)).rejects.toThrow("payload exceeds 64 KiB limit");
  });
});

describe("SeqPassHostClient registration honesty", () => {
  it("registers as status-only presentation with external credential input", async () => {
    // The adapter must not claim a native credential-entry surface it
    // cannot deliver: presentation describes status display, and the
    // credential transport is the external trusted terminal. The broker
    // ignores these flags as security evidence, but honesty in the
    // registration record keeps the audit trail truthful.
    const requests: any[] = [];
    dir = mkdtempSync(join(tmpdir(), "seqpass-ipc-test-"));
    const path = join(dir, "broker.sock");
    server = createServer((sock: Socket) => {
      let buffer = "";
      sock.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf-8");
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const req = JSON.parse(line);
          if (req.method === "host.register") {
            requests.push(req);
            sock.write(JSON.stringify({
              id: req.id,
              ok: true,
              data: { session: { id: "session-1" }, token: { token: "tok-1" } },
            }) + "\n");
          } else {
            sock.write(JSON.stringify({ id: req.id, ok: true, data: [] }) + "\n");
          }
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      server!.listen({ path }, () => resolve());
      server!.on("error", reject);
    });
    const { SeqPassHostClient } = await import("../lib/client");
    const client = new SeqPassHostClient({
      intakeSocket: path,
      hostSocket: path,
      sessionID: "host-1",
      sessionToken: "tok-test",
    });
    clients.push(client);
    await client.register();
    expect(requests).toHaveLength(1);
    const params = requests[0].params;
    expect(params.presentation).toBe("request_status");
    expect(params.input_transport).toBe("external_tty");
    expect(params.host_kind).toBe("opencode");
  });
});
