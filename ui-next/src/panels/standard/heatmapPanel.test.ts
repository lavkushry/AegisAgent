import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "@/datasources/frame";
import HeatmapPanel from "./HeatmapPanel";
import type { PanelDefinition } from "../types";

describe("HeatmapPanel data path", () => {
  test("builds a value/count frame for count_by rows", () => {
    const frame = rowsToFrame(
      [
        { value: "allow", count: 12 },
        { value: "deny", count: 3 },
        { value: "require_approval", count: 1 },
      ],
      ["value", "count"],
    );
    expect(frame.length).toBe(3);
    expect(frame.fields.find((f) => f.name === "value")?.values).toEqual([
      "allow",
      "deny",
      "require_approval",
    ]);
    expect(frame.fields.find((f) => f.name === "count")?.values).toEqual([
      12, 3, 1,
    ]);
  });

  test("component is a function with heatmap definition shape", () => {
    expect(typeof HeatmapPanel).toBe("function");
    const def: PanelDefinition = {
      id: "hm-decision",
      type: "heatmap",
      title: "Decision mix",
      datasourceId: "soc-query",
      entity: "decision",
      aggregate: "count_by",
      groupBy: "decision",
      options: {
        categoryField: "value",
        valueField: "count",
      },
    };
    void def;
  });
});
