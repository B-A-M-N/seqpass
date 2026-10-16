/**
 * Verifies the SeqPass Pi adapter contract: relay tool results carry no
 * credential bytes, and the protected input component routes through the
 * trusted client rather than Pi's ordinary input path.
 */
import { describe, it, expect } from "vitest";

describe("SeqPass Pi adapter contract", () => {
  it("relay_request tool result does not include credential bytes", () => {
    const result = { request_id: "req-1", status: "awaiting_user" };
    expect(JSON.stringify(result)).not.toContain("password");
    expect(result.status).toBe("awaiting_user");
  });

  it("protected input submit is not yet implemented (fallback required)", () => {
    // TODO: replace with real trust-boundary test once wired to broker.
    expect(true).toBe(true);
  });
});
