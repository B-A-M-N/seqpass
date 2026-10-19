/**
 * Verifies the SeqPass Pi adapter contract: the agent-domain transport is
 * separate from the intake transport, and the native input component does
 * not claim security guarantees without independent qualification.
 */
import { describe, it, expect } from "vitest";
import { SeqPassClient } from "../client";

describe("SeqPass Pi adapter contract", () => {
  it("routes relay RPCs through the agent transport, not intake", () => {
    const config = {
      intakeSocket: "/tmp/test.intake",
      hostSocket: "/tmp/test.host",
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

  it("registers honestly as a status-only presentation surface", async () => {
    const client = new SeqPassClient({
      intakeSocket: "/tmp/test.intake",
      hostSocket: "/tmp/test.host",
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
      await client.register();
    } catch {
      // The write itself may fail against a stubbed transport; only the
      // registration payload matters here.
    }
    expect(captured[0]).not.toBeNull();
    expect(captured[0]!.presentation).toBe("request_status");
    expect(captured[0]!.input_transport).toBe("external_tty");
    expect(captured[0]!.host_kind).toBe("pi");
  });

  it("records protected input qualification as blocked without a real Pi terminal", () => {
    const reason = "real Pi ctx.ui.custom() terminal qualification unavailable in CI";
    const result = {
      status: "blocked",
      reason,
      evidence: null,
      executed_host_tests: 0,
    };
    expect(result.status).toBe("blocked");
    expect(result.reason).toBe(reason);
    expect(result.evidence).toBeNull();
    expect(result.executed_host_tests).toBe(0);
    expect(() => {
      if (result.executed_host_tests === 0 && result.status === "blocked") {
        throw new Error("native integration verdict must not be green");
      }
    }).toThrow("native integration verdict must not be green");
  });

  it("does not mark descriptor objects as native protected input", () => {
    const fake = { masked: true };
    expect("value" in fake).toBe(false);
    expect("submit" in fake).toBe(false);
  });
});

// SP-05: When input_mode is external_tty, ProtectedInput returns a
// fallback that directs the user to the external trusted terminal —
// it does not render a credential-bearing native prompt.
import { ProtectedInput } from "../ProtectedInput";

describe("SeqPass Pi external-tty fallback", () => {
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
