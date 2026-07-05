import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { AgentDetailBody } from "./AgentDetailPage";
import type { AgentRecord } from "@/app/api";

const agent: AgentRecord = {
  id: "agent-1",
  agent_key: "coding-agent",
  name: "Coding Agent",
  environment: "production",
  risk_tier: "high",
  status: "active",
};

describe("AgentDetailPage", () => {
  it("renders detail metadata, drilldowns, and role-gated controls", () => {
    const html = renderToStaticMarkup(
      <AgentDetailBody
        agent={agent}
        permissions={["github"]}
        recentDecisions={[]}
        role="analyst"
        mutationError={null}
        pendingControl={null}
        auditReason=""
        busy={false}
        onBack={vi.fn()}
        onOpenControl={vi.fn()}
        onReasonChange={vi.fn()}
        onConfirmControl={vi.fn()}
        onCancelControl={vi.fn()}
        onDrillExplore={vi.fn()}
        onDrillIncidents={vi.fn()}
        onDrillApprovals={vi.fn()}
        onDrillMcp={vi.fn()}
        onDrillReceipts={vi.fn()}
      />,
    );
    expect(html).toContain("coding-agent");
    expect(html).toContain("SOC evidence drilldowns");
    expect(html).toContain("#1389");
    expect(html).toContain("Freeze");
    expect(html).toContain("Revoke");
  });
});