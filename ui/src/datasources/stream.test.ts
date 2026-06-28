import { describe, expect, it } from "vitest";

import { parseEventBlock } from "./stream";

describe("SOC stream parsing", () => {
  it("parses typed SSE events", () => {
    expect(
      parseEventBlock('event: approval\ndata: {"payload":{"id":"approval-1"},"ts":"2026-06-28T00:00:00Z"}'),
    ).toEqual({
      topic: "approval",
      payload: { id: "approval-1" },
      ts: "2026-06-28T00:00:00Z",
    });
  });

  it("ignores malformed and unknown events", () => {
    expect(parseEventBlock("event: unknown\ndata: {}" as string)).toBeNull();
    expect(parseEventBlock("event: alert\ndata: not-json" as string)).toBeNull();
  });
});
