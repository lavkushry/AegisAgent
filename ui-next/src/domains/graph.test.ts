import { describe, expect, test } from "bun:test";
import { normalizeEvidenceGraph } from "./graph";

describe("normalizeEvidenceGraph", () => {
  test("empty / garbage fails closed to empty graph", () => {
    expect(normalizeEvidenceGraph(null)).toEqual({ nodes: [], edges: [] });
    expect(normalizeEvidenceGraph("x")).toEqual({ nodes: [], edges: [] });
    expect(normalizeEvidenceGraph({})).toEqual({ nodes: [], edges: [] });
  });

  test("maps gateway nodes and edges", () => {
    const g = normalizeEvidenceGraph({
      nodes: [
        {
          id: "decision:d1",
          group: "decision",
          label: "require_approval",
          metadata: { risk_score: 72 },
        },
        { id: "tool_call:d1", group: "tool_call", label: "github.merge" },
      ],
      edges: [
        {
          from: "tool_call:d1",
          to: "decision:d1",
          label: "decided",
        },
      ],
    });
    expect(g.nodes).toHaveLength(2);
    expect(g.edges).toHaveLength(1);
    expect(g.nodes[0].group).toBe("decision");
    expect(g.edges[0].label).toBe("decided");
  });
});
