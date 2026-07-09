import { describe, expect, test } from "bun:test";
import type { EvidenceGraph } from "@/domains/graph";
import DecisionGraphPanel from "./DecisionGraphPanel";
import {
  GRAPH_LAYERS,
  countByGroup,
  layoutEvidenceGraph,
  shortLabel,
} from "./decisionGraphModel";
import type { PanelDefinition } from "../types";

const sample: EvidenceGraph = {
  nodes: [
    { id: "agent:a1", group: "agent", label: "Coding Agent" },
    { id: "tool_call:d1", group: "tool_call", label: "github.merge" },
    { id: "decision:d1", group: "decision", label: "require_approval" },
    { id: "receipt:r1", group: "receipt", label: "sha256:abc" },
  ],
  edges: [
    { from: "tool_call:d1", to: "decision:d1", label: "decided" },
    { from: "decision:d1", to: "receipt:r1", label: "produced" },
  ],
};

describe("DecisionGraphPanel layout", () => {
  test("layers nodes by group and keeps edge endpoints", () => {
    const layout = layoutEvidenceGraph(sample, 40);
    expect(layout.nodes.length).toBe(4);
    expect(layout.edges.length).toBe(2);
    const decision = layout.nodes.find((n) => n.id === "decision:d1");
    const tool = layout.nodes.find((n) => n.id === "tool_call:d1");
    expect(decision?.layer).toBe(GRAPH_LAYERS.indexOf("decision"));
    expect(tool?.layer).toBe(GRAPH_LAYERS.indexOf("tool_call"));
    expect(decision!.x).toBeGreaterThan(tool!.x);
  });

  test("counts groups and shortens labels", () => {
    expect(countByGroup(sample.nodes).decision).toBe(1);
    expect(shortLabel("abcdefghijklmnopqrstuvwxyz", 8)).toBe("abcdefg…");
  });

  test("component is registered as decision-graph shape", () => {
    expect(typeof DecisionGraphPanel).toBe("function");
    const def: PanelDefinition = {
      id: "graph-incident",
      type: "decision-graph",
      title: "Evidence graph",
      datasourceId: "gateway-entity",
      entity: "incident",
      limit: 1,
      options: { scopeKind: "incident", scopeIdField: "id", maxNodes: 40 },
    };
    void def;
  });
});
