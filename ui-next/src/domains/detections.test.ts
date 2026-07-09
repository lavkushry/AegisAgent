import { describe, expect, test } from "bun:test";
import { filterAlerts, type AlertRecord } from "./detections";

const rows: AlertRecord[] = [
  {
    id: "1",
    severity: "high",
    summary: "Receipt chain broken",
    rule: "receipt-chain-broken",
    agent_id: "ag_1",
  },
  {
    id: "2",
    severity: "low",
    summary: "Noise",
    rule: "other",
    agent_id: "ag_2",
  },
];

describe("filterAlerts", () => {
  test("filters by severity", () => {
    expect(filterAlerts(rows, "", "high")).toHaveLength(1);
  });

  test("filters by free text", () => {
    expect(filterAlerts(rows, "chain", "")).toHaveLength(1);
    expect(filterAlerts(rows, "ag_2", "")[0].id).toBe("2");
  });
});
