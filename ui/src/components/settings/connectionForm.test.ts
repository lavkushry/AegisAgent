import { describe, expect, it } from "vitest";

import { bearerTokenDisplayLabel, bearerTokenPlaceholder } from "./connectionForm";

describe("connectionForm", () => {
  it("never labels production tokens as persisted", () => {
    expect(bearerTokenDisplayLabel(true)).toContain("in-memory");
    expect(bearerTokenPlaceholder()).toContain("in-memory");
  });
});