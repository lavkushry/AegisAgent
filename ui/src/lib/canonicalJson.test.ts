import { describe, expect, it } from "vitest";

import { canonicalizeJson } from "./canonicalJson";

describe("aegis-jcs-1 evidence display", () => {
  it("sorts nested object keys and preserves raw Unicode", () => {
    expect(canonicalizeJson({ z: "東京", a: { y: 2, x: 1 } })).toBe(
      '{"a":{"x":1,"y":2},"z":"東京"}',
    );
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalizeJson({ score: Number.NaN })).toThrow("non-finite");
  });
});
