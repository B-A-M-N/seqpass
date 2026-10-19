/**
 * Verifies the SP-05 native-input capability gate and the display-only
 * inbox footer contract: this adapter build has no verified masked input
 * field, so in-host credential collection is always refused — even when
 * the broker qualifies the deployment for host-native input — and the
 * footer surfaces a count only, never request metadata.
 */
import { describe, it, expect } from "vitest";
import {
  NATIVE_MASKED_INPUT_SUPPORTED,
  EXTERNAL_TUI_HINT,
  selectNativeInput,
  footerText,
  inboxOptions,
} from "../lib/nativeInput";

describe("SeqPass native input gating", () => {
  it("refuses in-host collection while the build lacks a masked field", () => {
    expect(NATIVE_MASKED_INPUT_SUPPORTED).toBe(false);
    const decision = selectNativeInput("host_native_verified");
    expect(decision.allowed).toBe(false);
  });

  it("refuses in-host collection for every non-native broker mode", () => {
    for (const mode of ["external_tty", "url", "unavailable"]) {
      const decision = selectNativeInput(mode);
      expect(decision.allowed).toBe(false);
      expect(decision.allowed === false && decision.reason).toContain(EXTERNAL_TUI_HINT);
    }
  });

  it("names the external trusted terminal as the fallback surface", () => {
    const decision = selectNativeInput("host_native_verified");
    expect(decision.allowed === false && decision.reason).toContain(EXTERNAL_TUI_HINT);
    expect(decision.allowed === false && decision.reason).toContain("masked");
  });
});

describe("SeqPass inbox footer", () => {
  it("exposes the real slot-plugin shape for the home_footer slot", async () => {
    // Imports the TSX component module so the pinned @opentui/solid JSX
    // transform is exercised by the suite, and checks the TuiSlotPlugin
    // contract shape: no id (the host assigns one), a slots map with a
    // renderer for home_footer only.
    const { seqPassFooter } = await import("../components/SeqPassFooter");
    const plugin = seqPassFooter(() => 2);
    expect(typeof plugin.slots.home_footer).toBe("function");
    expect("id" in plugin).toBe(false);
    expect(Object.keys(plugin.slots)).toEqual(["home_footer"]);
  });

  it("renders no footer text when nothing is pending", () => {
    expect(footerText(0)).toBeNull();
    expect(footerText(-1)).toBeNull();
  });

  it("renders a count-only label", () => {
    expect(footerText(1)).toBe("SeqPass: 1 pending request");
    expect(footerText(3)).toBe("SeqPass: 3 pending requests");
  });

  it("carries only a count — never request metadata", () => {
    const text = footerText(7) ?? "";
    expect(text).toMatch(/^SeqPass: \d+ pending/);
    expect(text).not.toContain("api");
    expect(text).not.toContain("recipient");
    expect(text).not.toContain("key");
  });
});

describe("SeqPass inbox listing", () => {
  it("maps notices to options carrying broker-verified fields only", () => {
    const options = inboxOptions([{
      request_id: "req-1",
      recipient_label: "Test Recipient",
      data_kind: "api_key",
      consumption: "single_dispatch",
      untrusted_purpose: "agent-authored text — must not leak into the listing",
    }]);
    expect(options).toHaveLength(1);
    expect(options[0].title).toBe("Test Recipient — api_key");
    expect(options[0].description).toBe("single_dispatch");
    expect(options[0].value).toEqual({ request_id: "req-1" });
  });

  it("keeps the agent-supplied untrusted purpose out of the listing", () => {
    const options = inboxOptions([{
      request_id: "req-1",
      recipient_label: "Test Recipient",
      data_kind: "api_key",
      consumption: "single_dispatch",
      untrusted_purpose: "agent-authored text — must not leak into the listing",
    }]);
    const flat = JSON.stringify(options);
    expect(flat).not.toContain("agent-authored text");
    expect(flat).not.toContain("untrusted_purpose");
  });
});
