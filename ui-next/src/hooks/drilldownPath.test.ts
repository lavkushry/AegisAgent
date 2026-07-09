import { describe, expect, test } from "bun:test";
import { interpolate, resolveDrilldownPath } from "./drilldownPath";
import type { DrilldownLink } from "@/panels/types";

describe("resolveDrilldownPath", () => {
  test("maps explore AQL with row interpolation", () => {
    const link: DrilldownLink = {
      label: "Explore",
      target: {
        kind: "explore",
        aqlTemplate: "agent_id:${agent_id} AND decision:deny",
      },
    };
    const path = resolveDrilldownPath(link, { agent_id: "ag-1" });
    expect(path).toBe(
      `/explore?q=${encodeURIComponent("agent_id:ag-1 AND decision:deny")}`,
    );
  });

  test("maps reserved dashboard uids to feature routes", () => {
    const cases: Array<[string, string]> = [
      ["approvals", "/approvals"],
      ["integrity", "/integrity"],
      ["receipts", "/integrity"],
      ["fleet", "/agents"],
      ["detections", "/detections"],
      ["dashboards", "/dashboards"],
      ["unknown-board", "/"],
    ];
    for (const [uid, expected] of cases) {
      const link: DrilldownLink = {
        label: uid,
        target: { kind: "dashboard", uid },
      };
      expect(resolveDrilldownPath(link)).toBe(expected);
    }
  });

  test("agent drilldown prefers row id", () => {
    const link: DrilldownLink = {
      label: "Agent",
      target: { kind: "agent", agentIdField: "id" },
    };
    expect(resolveDrilldownPath(link, { id: "uuid-1" })).toBe(
      "/agents/uuid-1",
    );
    expect(resolveDrilldownPath(link, {})).toBe("/agents");
  });

  test("receipts open integrity", () => {
    const link: DrilldownLink = {
      label: "Verify",
      target: { kind: "verify-receipt", receiptIdField: "id" },
    };
    expect(resolveDrilldownPath(link)).toBe("/integrity");
  });
});

describe("interpolate", () => {
  test("leaves template unchanged without row", () => {
    expect(interpolate("agent_id:${id}")).toBe("agent_id:${id}");
  });

  test("substitutes known keys", () => {
    expect(interpolate("x:${a}/y:${b}", { a: 1, b: "two" })).toBe("x:1/y:two");
  });
});
