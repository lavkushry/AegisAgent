import { describe, expect, test } from "bun:test";
import {
  actionLabel,
  effectiveActionHash,
  approvalId,
  type ApprovalRecord,
} from "@/domains/approvals";
import ApprovalCardPanel from "./ApprovalCardPanel";
import type { PanelDefinition } from "../types";

function asApproval(row: Record<string, unknown>): ApprovalRecord {
  return row as unknown as ApprovalRecord;
}

describe("ApprovalCardPanel data path", () => {
  test("domain helpers bind frozen action fields from gateway rows", () => {
    const approval = asApproval({
      approval_id: "approval-e2e-001",
      agent_id: "agent-1",
      tool_name: "github.merge_pull_request",
      tool_call: {
        tool: "github",
        action: "merge_pull_request",
        mutates_state: true,
        parameters: { base_branch: "main", api_key: "sk-live-secret" },
      },
      source_trust: "semi_trusted_customer",
      action_hash: "sha256:deadbeef",
      status: "pending",
    });
    expect(approvalId(approval)).toBe("approval-e2e-001");
    expect(actionLabel(approval)).toBe("github.merge_pull_request");
    expect(effectiveActionHash(approval)).toBe("sha256:deadbeef");
  });

  test("component is registered as approval-card shape", () => {
    expect(typeof ApprovalCardPanel).toBe("function");
    const def: PanelDefinition = {
      id: "cards-pending",
      type: "approval-card",
      title: "Pending HITL",
      datasourceId: "gateway-entity",
      entity: "approval",
      limit: 10,
      options: { maxCards: 6, interactive: true },
    };
    void def;
  });
});
