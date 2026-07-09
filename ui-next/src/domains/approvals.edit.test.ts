import { describe, expect, test } from "bun:test";
import { parseEditedToolCall, type ApprovalRecord } from "./approvals";

const approval: ApprovalRecord = {
  approval_id: "a1",
  tool_call: {
    tool: "github",
    action: "merge",
    mutates_state: true,
    parameters: { pr: 1 },
  },
};

describe("parseEditedToolCall", () => {
  test("parses parameters and keeps tool/action", () => {
    const r = parseEditedToolCall(approval, '{"pr":2,"force":true}');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.editedToolCall.tool).toBe("github");
      expect(r.editedToolCall.action).toBe("merge");
      expect(r.editedToolCall.parameters).toEqual({ pr: 2, force: true });
    }
  });

  test("rejects invalid JSON", () => {
    const r = parseEditedToolCall(approval, "{");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/JSON/i);
  });

  test("fails closed without frozen tool call", () => {
    const r = parseEditedToolCall({ approval_id: "x" }, "{}");
    expect(r.ok).toBe(false);
  });
});
