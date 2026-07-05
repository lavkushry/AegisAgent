import { describe, expect, it } from "vitest";

import type { AlertRecord } from "@/app/api";
import { filterAlerts } from "./alertFilters";

const sampleAlerts: AlertRecord[] = [
  {
    id: "1",
    alert_id: "alert-high",
    rule: "confused_deputy_block",
    severity: "high",
    summary: "Denied merge on main",
    agent_id: "agent-alpha",
    created_at: "2026-07-01T10:00:00Z",
    occurred_at: "2026-07-01T10:00:00Z",
    source_event_id: "evt-1",
  },
  {
    id: "2",
    alert_id: "alert-low",
    rule: "policy_drift",
    severity: "low",
    summary: "Policy drift detected",
    agent_id: "agent-beta",
    created_at: "2026-07-01T11:00:00Z",
    occurred_at: "2026-07-01T11:00:00Z",
    source_event_id: "evt-2",
  },
];

describe("filterAlerts", () => {
  it("returns all alerts when filters are empty", () => {
    expect(filterAlerts(sampleAlerts, "", "all")).toHaveLength(2);
  });

  it("filters by severity", () => {
    expect(filterAlerts(sampleAlerts, "", "high")).toEqual([sampleAlerts[0]]);
  });

  it("filters by search across rule, summary, agent, and alert id", () => {
    expect(filterAlerts(sampleAlerts, "agent-beta", "all")).toEqual([sampleAlerts[1]]);
    expect(filterAlerts(sampleAlerts, "alert-high", "all")).toEqual([sampleAlerts[0]]);
    expect(filterAlerts(sampleAlerts, "policy drift", "all")).toEqual([sampleAlerts[1]]);
  });

  it("combines severity and search filters", () => {
    expect(filterAlerts(sampleAlerts, "agent-alpha", "high")).toEqual([sampleAlerts[0]]);
    expect(filterAlerts(sampleAlerts, "agent-alpha", "low")).toEqual([]);
  });
});