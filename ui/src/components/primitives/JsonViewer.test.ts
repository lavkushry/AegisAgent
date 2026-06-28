import { describe, expect, it } from "vitest";

import { redactJson } from "./JsonViewer";

describe("JSON redaction", () => {
  it("redacts nested secret-shaped fields without changing evidence fields", () => {
    expect(
      redactJson({
        action_hash: "abc",
        authorization: "Bearer secret",
        nested: { api_key: "key", value: "visible" },
      }),
    ).toEqual({
      action_hash: "abc",
      authorization: "[REDACTED]",
      nested: { api_key: "[REDACTED]", value: "visible" },
    });
  });
});
