import { describe, expect, test } from "bun:test";
import { frameRows, rowsToFrame, singleRowAsObject } from "./frame";

describe("rowsToFrame", () => {
  test("empty with order", () => {
    const f = rowsToFrame([], ["id"]);
    expect(f.length).toBe(0);
    expect(f.fields).toHaveLength(1);
  });

  test("infers hash and decision", () => {
    const f = rowsToFrame([
      { action_hash: "sha256:abc", decision: "allow", n: 1 },
    ]);
    expect(f.length).toBe(1);
    expect(f.fields.find((x) => x.name === "action_hash")?.type).toBe("hash");
    expect(f.fields.find((x) => x.name === "decision")?.type).toBe("decision");
    expect(frameRows(f)[0].decision).toBe("allow");
  });

  test("singleRowAsObject roundtrip", () => {
    const f = rowsToFrame([{ a: 1, b: "x" }]);
    expect(singleRowAsObject(f)).toEqual({ a: 1, b: "x" });
  });
});
