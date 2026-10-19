/**
 * Verifies the SeqPass Pi adapter contract: the agent-domain transport is
 * separate from the intake transport, and the native input component does
 * not claim security guarantees without independent qualification.
 */
import { describe, it, expect } from "vitest";
import { SeqPassClient } from "../client";
import { ProtectedInput, nativeEntry, NATIVE_MASKED_INPUT_SUPPORTED } from "../ProtectedInput";

const baseNotice = {
  version: 1,
  request_id: "req-fallback",
  request_revision: 1,
  host_session_id: "host-1",
  data_kind: "api_key",
  recipient_id: "rd1",
  recipient_label: "Test Recipient",
  consumption: "single_dispatch",
  expires_at: "2026-01-01T00:00:00Z",
  input_mode: "external_tty" as const,
  input_assurance: "model_blind",
  untrusted_purpose: "",
};

describe("SeqPass Pi adapter contract", () => {
  it("routes relay RPCs through the agent transport, not intake", () => {
    const config = {
      intakeSocket: "/tmp/test.intake",
      hostSocket: "/tmp/test.host",
      hostVersion: "1.2.3",
      agentSocket: "/tmp/test.agent",
      sessionID: "host-1",
      sessionToken: "tok-test",
    };
    const client = new SeqPassClient(config);
    // Verify the agent transport is distinct from the intake transport.
    expect((client as any).agent.socketPath).toBe("/tmp/test.agent");
    expect((client as any).intake.socketPath).toBe("/tmp/test.intake");
    expect((client as any).agent.socketPath).not.toBe((client as any).intake.socketPath);
    client.close();
  });

  it("fails relay RPCs closed when no agent socket is configured", async () => {
    // SP-07: without an explicitly configured agent socket the adapter
    // must not guess a dial target — agent-domain calls are refused
    // outright instead of silently hitting a foreign allowlist domain.
    const client = new SeqPassClient({
      intakeSocket: "/tmp/test.intake",
      hostSocket: "/tmp/test.host",
      hostVersion: "1.2.3",
      sessionID: "host-1",
      sessionToken: "tok-test",
    });
    expect((client as any).agent).toBeNull();
    const relay = await client.requestRelay({ destination_id: "d1", data_kind: "api_key" });
    expect(relay.status).toBe("error");
    expect(relay.error).toContain("agentSocket is not configured");
    const status = await client.getStatus("req-1");
    expect(status.status).toBe("error");
    expect(status.error).toContain("agentSocket is not configured");
    client.close();
  });

  it("refuses oversized payloads without dialing the broker", async () => {
    // Parity with the OpenCode client: validation precedes dialing, so
    // an oversized payload is refused even when the broker is down.
    const client = new SeqPassClient({
      intakeSocket: "/nonexistent/seqpass/intake.sock",
      hostSocket: "/nonexistent/seqpass/host.sock",
      hostVersion: "1.2.3",
      sessionID: "host-1",
      sessionToken: "tok-test",
    });
    const oversized = "x".repeat(64 * 1024 + 1);
    await expect(client.fulfill("req-1", 1, oversized)).rejects.toThrow("payload exceeds 64 KiB limit");
  });

  it("registers honestly as a status-only presentation surface", async () => {
    const client = new SeqPassClient({
      intakeSocket: "/tmp/test.intake",
      hostSocket: "/tmp/test.host",
      hostVersion: "1.2.3",
      agentSocket: "/tmp/test.agent",
      sessionID: "host-1",
      sessionToken: "tok-test",
    });
    const captured: Array<Record<string, unknown> | null> = [null];
    // Stub the dial so the payload can be inspected without a broker.
    (client as any).intake.connect = async () => {};
    (client as any).host.connect = async () => {};
    (client as any).intake.call = async (method: string, params?: Record<string, unknown>) => {
      if (method === "host.register") captured[0] = { ...params };
      throw new Error("not connected (expected in this test)");
    };
    try {
      await client.register("1.2.3");
    } catch {
      // The write itself may fail against a stubbed transport; only the
      // registration payload matters here.
    }
    expect(captured[0]).not.toBeNull();
    expect(captured[0]!.presentation).toBe("request_status");
    expect(captured[0]!.input_transport).toBe("external_tty");
    expect(captured[0]!.host_kind).toBe("pi");
  });

  it("native-mode entry renders asterisk progress only, never the value", async () => {
    // Drives the real key handler with typed characters and verifies
    // every rendered frame carries asterisk progress only; the value
    // itself appears solely in the fulfill call to the trusted client.
    // The qualification suite exercises nativeEntry directly: the
    // shipped build's gate is a compiled false constant, which the
    // following test pins separately.
    const renders: string[] = [];
    let handler: ((key: string) => void) | null = null;
    const ui = {
      render: (t: string) => renders.push(t),
      setKeyHandler: (h: (key: string) => void) => { handler = h; },
      close: () => {},
    };
    let submitted = "";
    const client = {
      fulfill: async (_id: string, _rev: number, value: string) => { submitted = value; },
      dismissPrompt: async () => {},
    };
    const notice = { ...baseNotice, input_mode: "host_native_verified" as const };
    const result = nativeEntry(notice, client as any, ui as any) as any;
    expect(result.fallback).toBeUndefined();
    // Type a value whose characters never appear in the header text.
    for (const key of ["z", "9", "$"]) handler!(key);
    for (const frame of renders) {
      expect(frame).not.toContain("z");
      expect(frame).not.toContain("9");
      expect(frame).not.toContain("$");
    }
    handler!("enter");
    expect(submitted).toBe("z9$");
    // Final frame shows three-asterisk progress, nothing of the value.
    expect(renders[renders.length - 1]).toContain("***");
  });

  it("fallback result exposes no credential-collection affordances", () => {
    // The external_tty fallback is display-only: it never installs a key
    // handler (no collection path), and the returned result carries no
    // value/submit affordances. A mutated component that started
    // collecting in fallback mode would trip either check.
    const keyHandlerInstalled = { current: false };
    const client = {} as any;
    const ui = {
      render: () => {},
      setKeyHandler: () => { keyHandlerInstalled.current = true; },
      close: () => {},
    };
    const result = ProtectedInput(baseNotice, client, ui) as any;
    expect(result.fallback).toBe(true);
    expect(keyHandlerInstalled.current).toBe(false);
    for (const forbidden of ["value", "submit", "setKeyHandler", "onKey", "handleKey"]) {
      expect(forbidden in result).toBe(false);
    }
    expect(typeof result.close).toBe("function");
  });

  it("host-native mode routes to the external fallback in a default build", () => {
    // The unqualified build gate is a security property: without
    // independent qualification evidence, an in-host masked field would
    // collect credentials inside the agent-controlled host process. The
    // gate is a compiled false constant (not an environment variable an
    // in-process actor could flip); this build routes even
    // host_native_verified requests to the external terminal. A mutated
    // gate (always-on native capture, or env-based) trips this test.
    const keyHandlerInstalled = { current: false };
    const ui = {
      render: () => {},
      setKeyHandler: () => { keyHandlerInstalled.current = true; },
      close: () => {},
    };
    const notice = { ...baseNotice, input_mode: "host_native_verified" as const };
    const result = ProtectedInput(notice, {} as any, ui) as any;
    expect(result.fallback).toBe(true);
    expect(keyHandlerInstalled.current).toBe(false);
    expect(NATIVE_MASKED_INPUT_SUPPORTED).toBe(false);
  });
});

// SP-05: When input_mode is external_tty, ProtectedInput returns a
// fallback that directs the user to the external trusted terminal —
// it does not render a credential-bearing native prompt.
describe("SeqPass Pi external-tty fallback", () => {
  it("returns a fallback result for external_tty mode", () => {
    const client = {} as any;
    const ui = {
      render: () => {},
      setKeyHandler: () => {},
      close: () => {},
    };
    const result = ProtectedInput(baseNotice, client, ui) as any;
    expect(result.fallback).toBe(true);
    expect(result.masked).toBe(false);
    expect(result.message).toContain("external trusted-terminal input");
    expect(result.message).toContain("req-fallback");
  });

  it("does not expose a value or submit handler in fallback mode", () => {
    const client = {} as any;
    const ui = { render: () => {}, setKeyHandler: () => {}, close: () => {} };
    const result = ProtectedInput(baseNotice, client, ui) as any;
    expect("value" in result).toBe(false);
    expect("submit" in result).toBe(false);
  });
});
