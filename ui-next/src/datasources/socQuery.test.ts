import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "./frame";

// Exercise the same normalization path used by SocQueryDatasource without
// network: envelope → frame for count_over_time and count_by.
describe("soc-query response normalization", () => {
  test("count_over_time rows become a bucket/count frame", () => {
    const rows = [
      { bucket: "2026-06-28T10:00:00.000Z", count: 4 },
      { bucket: "2026-06-28T11:00:00.000Z", count: 6 },
    ];
    const frame = rowsToFrame(rows, ["bucket", "count"]);
    expect(frame.length).toBe(2);
    expect(frame.fields.map((f) => f.name)).toEqual(["bucket", "count"]);
    expect(frame.fields[1].values).toEqual([4, 6]);
  });

  test("count_by rows become a value/count frame", () => {
    const rows = [
      { value: "allow", count: 10 },
      { value: "deny", count: 2 },
    ];
    const frame = rowsToFrame(rows, ["value", "count"]);
    expect(frame.length).toBe(2);
    expect(frame.fields.map((f) => f.name)).toEqual(["value", "count"]);
    expect(frame.fields[0].values).toEqual(["allow", "deny"]);
    expect(frame.fields[1].values).toEqual([10, 2]);
  });
});
