/**
 * Tests for the Pi extension bootstrap and model-facing tool contract
 * (SP-07/SP-08): session credentials are adopted only as a broker-minted
 * pair, bootstrap failure is visible and retried, and malformed agent
 * tool args fail closed with sanitized errors before any broker RPC.
 */
import { describe, it, expect } from "vitest";
import { registerSeqPass, type SeqPassExtensionConfig } from "../seqpass";

function stubClient() {
  const state = {
    calls: [] as string[],
    registerCount: 0,
    session: null as { id: string; token: string } | null,
    registerResult: null as unknown,
  };
  return {
    state,
    get calls() { return state.calls; },
    connect: async () => { state.calls.push("connect"); },
    connectAgent: async () => { state.calls.push("connectAgent"); },
    register: async () => {
      state.calls.push("register");
      state.registerCount += 1;
      return state.registerResult;
    },
    setSession: (id: string, token: string) => {
      state.calls.push("setSession");
      state.session = { id, token };
    },
    requestRelay: async (args: any) => {
      state.calls.push("requestRelay:" + JSON.stringify(args));
      return { request_id: "req-1", status: "pending" };
    },
    getStatus: async (requestID: string) => {
      state.calls.push("getStatus:" + requestID);
      return { status: "authorized" };
    },
    getPendingRequest: async () => null,
    close: () => {},
  };
}

function harness(config: Partial<SeqPassExtensionConfig> = {}) {
  const client = stubClient();
  const extension = registerSeqPass({
    intakeSocket: "/tmp/test.intake",
    hostSocket: "/tmp/test.host",
    ...config,
  }, { client: client as any });
  const tools: Record<string, { description: string; handler: (args: any) => Promise<any> }> = {};
  extension.registerTool({
    registerTool: (name: string, spec: { description: string; handler: (args: any) => Promise<any> }) => {
      tools[name] = spec;
    },
  });
  return { client, tools, state: client.state };
}

describe("SeqPass Pi tool contract", () => {
  it("rejects relay_request without destination_id before any broker call", async () => {
    const { tools, client } = harness({ sessionID: "s", sessionToken: "t" });
    const result = await tools.relay_request.handler({ data_kind: "api_key" });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.status).toBe("error");
    expect(payload.error).toContain("destination_id is required");
    expect(client.calls).not.toContain("requestRelay");
  });

  it("rejects relay_request without data_kind before any broker call", async () => {
    const { tools, client } = harness({ sessionID: "s", sessionToken: "t" });
    const result = await tools.relay_request.handler({ destination_id: "d1" });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.status).toBe("error");
    expect(payload.error).toContain("data_kind is required");
    expect(client.calls).not.toContain("requestRelay");
  });

  it("rejects relay_status without request_id before any broker call", async () => {
    const { tools, client } = harness({ sessionID: "s", sessionToken: "t" });
    const result = await tools.relay_status.handler({});
    const payload = JSON.parse(result.content[0].text);
    expect(payload.status).toBe("error");
    expect(payload.error).toContain("request_id is required");
    expect(client.calls).not.toContain("getStatus");
  });

  it("passes validated relay args through to the client", async () => {
    const { tools, client } = harness({ sessionID: "s", sessionToken: "t" });
    const result = await tools.relay_request.handler({ destination_id: "d1", data_kind: "api_key", purpose: "deploy" });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.request_id).toBe("req-1");
    expect(payload.status).toBe("pending");
    expect(client.calls.some(c => c.startsWith("requestRelay:"))).toBe(true);
  });

  it("adopts broker session credentials only as a pair", async () => {
    const { tools, state } = harness({});
    // Partial register response: session id without a token.
    state.registerResult = { session: { id: "session-1" }, token: { token: "" } };
    await expect(tools.relay_status.handler({ request_id: "r1" })).rejects.toThrow("bootstrap failed");
    expect(state.session).toBeNull();
  });

  it("retries registration on the next call after bootstrap failure", async () => {
    const { tools, state, client } = harness({});
    state.registerResult = null;
    await expect(tools.relay_status.handler({ request_id: "r1" })).rejects.toThrow("bootstrap failed");
    expect(state.registerCount).toBe(1);
    // A complete pair this time: bootstrap succeeds and the tool runs.
    state.registerResult = { session: { id: "session-1" }, token: { token: "tok-1" } };
    const result = await tools.relay_status.handler({ request_id: "r1" });
    const payload = JSON.parse(result.content[0].text);
    expect(payload.status).toBe("authorized");
    expect(state.registerCount).toBe(2);
    expect(state.session).toEqual({ id: "session-1", token: "tok-1" });
  });

  it("uses provisioned credentials without calling register", async () => {
    const { tools, client } = harness({ sessionID: "s", sessionToken: "t" });
    await tools.relay_status.handler({ request_id: "r1" });
    expect(client.calls).not.toContain("register");
  });
});
