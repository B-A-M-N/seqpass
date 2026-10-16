/**
 * Verifies the SeqPass adapter contract: only broker-verified fields are
 * rendered, and protected input routes through the trusted client, not
 * OpenCode's model-facing APIs.
 */
import { describe, it, expect } from "vitest";
import { SeqPassReviewDialog } from "../components/SeqPassReview";

describe("SeqPass OpenCode V2 adapter contract", () => {
  const notice = {
    version: 1,
    request_id: "req-test",
    request_revision: 2,
    host_session_id: "host-1",
    data_kind: "api_key",
    recipient_id: "rd1",
    recipient_label: "Test Recipient",
    consumption: "single_dispatch",
    expires_at: "2026-01-01T00:00:00Z",
    input_mode: "external_tty" as const,
    input_assurance: "model_blind",
    untrusted_purpose: "configure staging",
  };

  it("renders only broker-verified fields", () => {
    const dialog = SeqPassReviewDialog(notice, {} as any);
    expect(dialog.recipient).toBe("Test Recipient");
    expect(dialog.dataKind).toBe("api_key");
    expect(dialog.usage).toBe("single_dispatch");
    expect(dialog.assurance).toBe("model_blind");
    expect(dialog.untrustedNote).toBe("configure staging");
  });

  it("does not include a credential field", () => {
    const dialog = SeqPassReviewDialog(notice, {} as any);
    expect("credential" in dialog).toBe(false);
    expect("secret" in dialog).toBe(false);
    expect("value" in dialog).toBe(false);
  });

  it("provides reject and dismiss actions bound to the correct request", () => {
    const calls: string[] = [];
    const client = {
      fulfill: () => {},
      reject: (id: string) => { calls.push("reject:" + id); },
      dismissPrompt: (id: string) => { calls.push("dismiss:" + id); },
    } as any;
    const dialog = SeqPassReviewDialog(notice, client);
    dialog.actions.reject();
    dialog.actions.dismiss();
    expect(calls).toContain("reject:req-test");
    expect(calls).toContain("dismiss:req-test");
  });
});
