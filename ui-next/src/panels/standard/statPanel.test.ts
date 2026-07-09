import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "@/datasources/frame";

/**
 * Stat panel resolve logic mirrored for pure unit test (component needs DOM).
 */
function resolveValue(
  data: ReturnType<typeof rowsToFrame>,
  valueField?: string,
): number | null {
  if (valueField) {
    const field = data.fields.find((f) => f.name === valueField);
    if (!field || field.values.length === 0) return null;
    const sample = field.values[0];
    if (sample === null || sample === undefined) return null;
    return typeof sample === "number" ? sample : Number(sample) || 0;
  }
  const field = data.fields.find((f) => f.type === "number");
  if (field && field.values.length > 0) {
    const last = field.values[field.values.length - 1];
    return typeof last === "number" ? last : Number(last) || 0;
  }
  return data.length > 0 ? data.length : null;
}

describe("stat resolveValue", () => {
  test("reads valueField", () => {
    const frame = rowsToFrame([{ total_decisions: 42, decisions_deny: 3 }]);
    expect(resolveValue(frame, "total_decisions")).toBe(42);
    expect(resolveValue(frame, "decisions_deny")).toBe(3);
  });

  test("null when missing", () => {
    const frame = rowsToFrame([{ name: "x" }]);
    expect(resolveValue(frame, "total_decisions")).toBeNull();
  });
});
