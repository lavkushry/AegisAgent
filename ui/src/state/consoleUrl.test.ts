import { describe, expect, it } from "vitest";

import { DEV_HARNESS_ENABLED, DEV_HARNESS_VIEW } from "@/dev/guard";
import { parseConsoleUrl, serializeConsoleUrl, CONSOLE_VIEWS } from "./consoleUrl";

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

  it("round-trips agent detail deep links", () => {
    const search = serializeConsoleUrl({
      view: "agents",
      timeRange: "24h",
      liveMode: false,
      agentId: "agent-123",
      variables: {},
    });
    expect(parseConsoleUrl(search)).toMatchObject({
      view: "agents",
      agentId: "agent-123",
    });
  });

  it("round-trips explore entity selection", () => {
    const search = serializeConsoleUrl({
      view: "explore",
      timeRange: "24h",
      liveMode: false,
      exploreQuery: "decision:deny",
      exploreEntity: "ase",
      variables: {},
    });
    expect(parseConsoleUrl(search)).toMatchObject({
      exploreQuery: "decision:deny",
      exploreEntity: "ase",
    });
  });

  it("accepts split detections and rules console views for deep links", () => {
    expect(parseConsoleUrl("?view=detections&range=24h")).toMatchObject({ view: "detections", timeRange: "24h" });
    expect(parseConsoleUrl("?view=rules&range=7d")).toMatchObject({ view: "rules", timeRange: "7d" });
    expect(serializeConsoleUrl({ view: "rules", timeRange: "7d", liveMode: false, variables: {} })).toContain(
      "view=rules",
    );
  });

  it("accepts analytics dashboard deep links", () => {
    expect(parseConsoleUrl("?view=analytics&range=7d")).toMatchObject({ view: "analytics", timeRange: "7d" });
    expect(serializeConsoleUrl({ view: "analytics", timeRange: "24h", liveMode: false, variables: {} })).toContain(
      "view=analytics",
    );
  });

  it("accepts dashboard editor deep links", () => {
    expect(parseConsoleUrl("?view=dashboard-editor&range=24h")).toMatchObject({
      view: "dashboard-editor",
      timeRange: "24h",
    });
    expect(
      serializeConsoleUrl({ view: "dashboard-editor", timeRange: "24h", liveMode: false, variables: {} }),
    ).toContain("view=dashboard-editor");
  });

  it("guards the dev harness route behind the compile-time flag", () => {
    if (DEV_HARNESS_ENABLED) {
      expect(CONSOLE_VIEWS).toContain(DEV_HARNESS_VIEW);
      expect(parseConsoleUrl("?view=dev-harness&range=24h")).toMatchObject({
        view: "dev-harness",
        timeRange: "24h",
      });
    } else {
      expect(CONSOLE_VIEWS).not.toContain(DEV_HARNESS_VIEW);
      expect(parseConsoleUrl("?view=dev-harness&range=24h")).not.toHaveProperty("view");
    }
  });
});
