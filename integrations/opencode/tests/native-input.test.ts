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
