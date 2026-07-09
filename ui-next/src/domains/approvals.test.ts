import { describe, expect, test } from "bun:test";
import {
  actionLabel,
  approvalActionDisabledReason,
  approvalId,
  approvalIsExpired,
  effectiveActionHash,
  type ApprovalRecord,
} from "./approvals";

const base: ApprovalRecord = {
  approval_id: "appr_1",
  status: "created",
  action_hash: "sha256:abc",
  tool_call: {
    tool: "github",
    action: "merge",
    mutates_state: true,
    parameters: { pr: 1 },
  },
};

describe("approval model", () => {
  test("approvalId prefers id then approval_id", () => {
    expect(approvalId({ approval_id: "a" })).toBe("a");
    expect(approvalId({ id: "b", approval_id: "a" })).toBe("b");
  });

  test("effectiveActionHash prefers effective over original", () => {
    expect(
      effectiveActionHash({
        original_action_hash: "o",
        action_hash: "a",
        effective_action_hash: "e",
      }),
    ).toBe("e");
  });

  test("actionLabel uses tool.action", () => {
    expect(actionLabel(base)).toBe("github.merge");
  });

  test("expired by status or expires_at", () => {
    expect(approvalIsExpired({ status: "EXPIRED" })).toBe(true);
    expect(
      approvalIsExpired({
        status: "created",
        expires_at: new Date(Date.now() - 1000).toISOString(),
      }),
    ).toBe(true);
    expect(
      approvalIsExpired({
        status: "created",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      }),
    ).toBe(false);
  });

  test("action disabled without identity or when expired", () => {
    expect(
      approvalActionDisabledReason(base, { busy: false, canAct: false }),
    ).toMatch(/operator identity/i);
    expect(
      approvalActionDisabledReason(
        { ...base, status: "approved" },
        { busy: false, canAct: true },
      ),
    ).toContain("approved");
    expect(
      approvalActionDisabledReason(base, { busy: false, canAct: true }),
    ).toBeUndefined();
  });
});
