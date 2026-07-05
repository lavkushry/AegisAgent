import { describe, expect, it } from "vitest";

import type { AlertRecord } from "@/app/api";
import { alertsForMcpServer } from "./linkedSoc";

describe("alertsForMcpServer", () => {
  it("matches mcp manifest drift rules and server key in summary", () => {
    const alerts: AlertRecord[] = [
      {
        id: "1",
        alert_id: "a1",
        rule: "mcp_manifest_drift",
        severity: "high",
        summary: "Drift on github-mcp",
        agent_id: "agent-1",
        created_at: "2026-07-05T10:00:00Z",
        occurred_at: "2026-07-05T10:00:00Z",
      },
      {
        id: "2",
        alert_id: "a2",
        rule: "deny_burst",
        severity: "low",
        summary: "Unrelated",
        agent_id: "agent-1",
        created_at: "2026-07-05T10:00:00Z",
        occurred_at: "2026-07-05T10:00:00Z",
      },
    ];
    const matched = alertsForMcpServer(alerts, "github-mcp");
    expect(matched).toHaveLength(1);
    expect(matched[0]?.rule).toBe("mcp_manifest_drift");
  });
});