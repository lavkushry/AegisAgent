import { describe, expect, it } from "vitest";

import { parseConsoleUrl, serializeConsoleUrl } from "./consoleUrl";

describe("console URL state", () => {
  it("round-trips shareable investigation context", () => {
    const search = serializeConsoleUrl({
      view: "explore",
      timeRange: "7d",
      liveMode: true,
      exploreQuery: "decision:deny",
      incidentId: "inc-1",
      receiptId: "receipt-1",
      variables: { agent: "agent-1" },
    });
    expect(parseConsoleUrl(search)).toMatchObject({
      view: "explore",
      timeRange: "7d",
      liveMode: true,
      exploreQuery: "decision:deny",
      incidentId: "inc-1",
      receiptId: "receipt-1",
      variables: { agent: "agent-1" },
    });
  });

  it("never serializes credentials or arbitrary state", () => {
    const search = serializeConsoleUrl({ view: "overview", timeRange: "24h", liveMode: false, variables: {} });
    expect(search).not.toMatch(/token|authorization|tenant_123/i);
  });
});
