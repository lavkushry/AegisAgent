import { describe, expect, it } from "vitest";

import {
  approvalActionDisabledReason,
  approvalConfirmationTarget,
  approvalIsExpired,
  approvalMetadataRows,
  canonicalActionBytes,
  editDisabledReason,
  effectiveActionHash,
  parseEditedToolCall,
  type ApprovalRow,
} from "./approvalCardModel";

const baseApproval: ApprovalRow = {
  approval_id: "approval-123",
  decision_id: "decision-456",
  agent_id: "agent-coder",
  run_id: "run-1",
  trace_id: "trace-1",
  source_trust: "untrusted",
  action_hash: "sha256:effective",
  original_action_hash: "sha256:original",
  expires_at: "2026-07-04T12:00:00Z",
  status: "created",
  approver_group: "platform-leads",
  decision_reason: "Critical mutation requires approval.",
  matched_policies: ["github_merge_pull_request", "critical_risk_requires_approval"],
  risk_score: 95,
  risk_level: "critical",
  composite_risk_score: 88,
  tool_call: {
    tool: "github",
    action: "merge_pull_request",
    resource: "lavkushry/AegisAgent#42",
    mutates_state: true,
    parameters: { z: 2, a: { b: true } },
  },
};

describe("approval card integrity model", () => {
  it("renders exact canonical action bytes and the effective action hash", () => {
    expect(canonicalActionBytes(baseApproval)).toBe(
      '{"action":"merge_pull_request","mutates_state":true,"parameters":{"a":{"b":true},"z":2},"resource":"lavkushry/AegisAgent#42","tool":"github"}',
    );
    expect(effectiveActionHash(baseApproval)).toBe("sha256:effective");
  });

  it("disables dangerous mutations for read-only, expired, missing, and decided approvals", () => {
    expect(
      approvalActionDisabledReason(baseApproval, {
        busy: false,
        canAct: false,
        denyReason: "Requires the approver or admin role",
      }),
    ).toBe("Requires the approver or admin role");

    expect(
      approvalActionDisabledReason(
        { ...baseApproval, status: "EXPIRED" },
        { busy: false, canAct: true },
      ),
    ).toBe("Approval expired; the gateway will fail closed");

    expect(
      approvalActionDisabledReason(
        { ...baseApproval, approval_id: undefined, id: undefined },
        { busy: false, canAct: true },
      ),
    ).toBe("Approval ID missing from gateway response");

    expect(
      approvalActionDisabledReason(
        { ...baseApproval, status: "approved" },
        { busy: false, canAct: true },
      ),
    ).toBe("Approval is approved; only pending approvals can be changed");
  });

  it("treats stale expires_at values as expired client-side defense in depth", () => {
    expect(
      approvalIsExpired(baseApproval, new Date("2026-07-04T12:00:01Z")),
    ).toBe(true);
    expect(
      approvalIsExpired(baseApproval, new Date("2026-07-04T11:59:59Z")),
    ).toBe(false);
  });

  it("prepares edited parameters as a new tool call and fails closed on invalid edit input", () => {
    expect(parseEditedToolCall(baseApproval, "{bad json")).toEqual({
      ok: false,
      error: "Parameters must be valid JSON.",
    });

    const edited = parseEditedToolCall(baseApproval, '{"base_branch":"main"}');
    expect(edited.ok).toBe(true);
    if (edited.ok) {
      expect(edited.editedToolCall).toMatchObject({
        tool: "github",
        action: "merge_pull_request",
        parameters: { base_branch: "main" },
      });
    }

    expect(
      editDisabledReason(
        { ...baseApproval, tool_call: undefined, edited_tool_call: undefined },
        { busy: false, canAct: true },
      ),
    ).toBe("Frozen tool call unavailable");
  });

  it("shows approval id, action, hash, and expiry in the confirmation target", () => {
    expect(approvalConfirmationTarget(baseApproval)).toBe(
      "approval-123 · github.merge_pull_request · sha256:effective · expires 2026-07-04T12:00:00Z",
    );
  });

  it("surfaces the decision context security engineers need to inspect", () => {
    const rows = approvalMetadataRows(baseApproval);
    expect(rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: "Approval ID", value: "approval-123" }),
        expect.objectContaining({ label: "Agent", value: "agent-coder" }),
        expect.objectContaining({ label: "Run / trace", value: "run-1 / trace-1" }),
        expect.objectContaining({ label: "Source trust", value: "untrusted", kind: "trust" }),
        expect.objectContaining({ label: "Resource", value: "lavkushry/AegisAgent#42" }),
        expect.objectContaining({ label: "Risk", value: "critical · 95/100 · composite 88/100" }),
        expect.objectContaining({ label: "Approver group", value: "platform-leads" }),
        expect.objectContaining({ label: "Policy reason", value: "Critical mutation requires approval." }),
        expect.objectContaining({
          label: "Policies",
          value: "github_merge_pull_request, critical_risk_requires_approval",
        }),
      ]),
    );
  });
});
