import { beforeEach, describe, expect, it } from "vitest";

import { useAppStore } from "@/app/store";
import { applyDrilldownLink } from "@/dashboards/drilldown";

function navigationFromStore() {
  const state = useAppStore.getState();
  return {
    setActiveView: state.setActiveView,
    setExploreSeed: state.setExploreSeed,
    setActiveIncidentId: state.setActiveIncidentId,
    setActiveReceiptId: state.setActiveReceiptId,
    setActiveAgentId: state.setActiveAgentId,
    setVariables: state.setVariables,
    getVariables: () => useAppStore.getState().variables,
  };
}

describe("applyDrilldownLink", () => {
  beforeEach(() => {
    useAppStore.setState({
      activeView: "overview",
      exploreSeed: null,
      exploreQuery: "",
      activeIncidentId: null,
      activeReceiptId: null,
      activeAgentId: null,
      variables: {},
    });
  });

  it("seeds explore from AQL templates", () => {
    applyDrilldownLink(
      navigationFromStore(),
      { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
      { agent_id: "agent-42" },
    );
    expect(useAppStore.getState().activeView).toBe("explore");
    expect(useAppStore.getState().exploreQuery).toBe("agent_id:agent-42");
  });

  it("routes receipt and agent drilldowns to focused views", () => {
    applyDrilldownLink(
      navigationFromStore(),
      { label: "Open receipt", target: { kind: "receipt", receiptIdField: "receipt_id" } },
      { receipt_id: "rcpt-9" },
    );
    expect(useAppStore.getState()).toMatchObject({
      activeView: "receipts",
      activeReceiptId: "rcpt-9",
    });

    applyDrilldownLink(
      navigationFromStore(),
      { label: "Open agent", target: { kind: "agent", agentIdField: "agent_id" } },
      { agent_id: "agent-7" },
    );
    expect(useAppStore.getState()).toMatchObject({
      activeView: "agents",
      activeAgentId: "agent-7",
    });
  });

  it("maps dashboard variables before switching views", () => {
    applyDrilldownLink(
      navigationFromStore(),
      {
        label: "Agent dashboard",
        target: { kind: "dashboard", uid: "agents", mapVars: { agent: "agent_id" } },
      },
      { agent_id: "agent-x" },
    );
    expect(useAppStore.getState()).toMatchObject({
      activeView: "agents",
      variables: { agent: "agent-x" },
    });
  });
});