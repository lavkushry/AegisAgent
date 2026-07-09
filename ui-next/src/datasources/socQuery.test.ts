import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "./frame";

// Exercise the same normalization path used by SocQueryDatasource without
// network: envelope → frame for count_over_time points.
describe("soc-query timeseries normalization", () => {
  test("envelope rows become a bucket/count frame", () => {
    const rows = [
      { bucket: "2026-06-28T10:00:00.000Z", count: 4 },
      { bucket: "2026-06-28T11:00:00.000Z", count: 6 },
    ];
    const frame = rowsToFrame(rows, ["bucket", "count"]);
    expect(frame.length).toBe(2);
    expect(frame.fields.map((f) => f.name)).toEqual(["bucket", "count"]);
    expect(frame.fields[1].values).toEqual([4, 6]);
  });
});
