import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "@/datasources/frame";
import TimeSeriesPanel from "./TimeSeriesPanel";
import type { PanelDefinition } from "../types";

// Smoke: module exports a component (render exercised via pure path in panel).
describe("TimeSeriesPanel data path", () => {
  test("builds a non-empty frame for bucket/count rows", () => {
    const frame = rowsToFrame(
      [
        { bucket: "2026-06-28T10:00:00.000Z", count: 4 },
        { bucket: "2026-06-28T11:00:00.000Z", count: 6 },
      ],
      ["bucket", "count"],
    );
    expect(frame.length).toBe(2);
    expect(frame.fields.find((f) => f.name === "count")?.values).toEqual([
      4, 6,
    ]);
  });

  test("component is a function", () => {
    expect(typeof TimeSeriesPanel).toBe("function");
    const def: PanelDefinition = {
      id: "ts",
      type: "timeseries",
      title: "Decisions",
      datasourceId: "soc-query",
      aggregate: "count_over_time",
      interval: "hour",
    };
    void def;
  });
});
