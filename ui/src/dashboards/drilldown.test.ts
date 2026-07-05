import { describe, expect, it } from "vitest";

import { useAppStore } from "@/app/store";

import {
  applyDrilldownLink,
  exploreAqlForAgent,
  exploreAqlForDecision,
  exploreAqlForReceipt,
  fillTemplate,
  mapRowToVariables,
} from "./drilldown";

describe("drilldown helpers", () => {
  it("fills AQL templates from row fields", () => {
    expect(fillTemplate("agent_id:${agent_id}", { agent_id: "agent-1" })).toBe("agent_id:agent-1");
    expect(fillTemplate("decision:${decision}", { decision: "deny" })).toBe("decision:deny");
  });

  it("builds safe explore filters for common investigation pivots", () => {
    expect(exploreAqlForAgent("coding-agent")).toBe("agent_id:coding-agent");
    expect(exploreAqlForReceipt("rcpt-1")).toBe("receipt_id:rcpt-1");
    expect(exploreAqlForDecision("deny")).toBe("decision:deny");
  });

  it("maps dashboard variables from clicked rows", () => {
    expect(mapRowToVariables({ agent: "agent_id" }, { agent_id: "a-1" })).toEqual({ agent: "a-1" });
  });

  it("opens incidents from incident drilldown links", () => {
    useAppStore.setState({ activeView: "overview", activeIncidentId: null });
    applyDrilldownLink(
      {
        setActiveView: useAppStore.getState().setActiveView,
        setExploreSeed: useAppStore.getState().setExploreSeed,
        setActiveIncidentId: useAppStore.getState().setActiveIncidentId,
        setActiveReceiptId: useAppStore.getState().setActiveReceiptId,
        setActiveAgentId: useAppStore.getState().setActiveAgentId,
        setVariables: useAppStore.getState().setVariables,
        getVariables: () => useAppStore.getState().variables,
      },
      { label: "Open incident", target: { kind: "incident", incidentIdField: "id" } },
      { id: "inc-22" },
    );
    expect(useAppStore.getState()).toMatchObject({ activeView: "incidents", activeIncidentId: "inc-22" });
  });
});