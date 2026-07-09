import { describe, expect, test } from "bun:test";

import { overviewDashboard } from "../system/overview";
import {
  parseAndValidateDashboardJson,
  validateDashboardSchema,
} from "./validate";

const SAMPLE_SCHEMA = JSON.stringify({
  uid: "team-posture",
  title: "Team posture",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 30 },
  layout: [
    {
      id: "row-1",
      title: "Vitals",
      panels: [
        {
          panel: {
            id: "stat-1",
            type: "stat",
            title: "Decisions",
            datasourceId: "gateway-entity",
            snapshot: "soc-summary",
            options: { valueField: "decisions_today" },
          },
          w: 4,
          h: 1,
        },
      ],
    },
  ],
});

describe("dashboard schema validation", () => {
  test("accepts a minimal valid schema", () => {
    const parsed = parseAndValidateDashboardJson(SAMPLE_SCHEMA);
    expect("kind" in parsed).toBe(false);
    if (!("kind" in parsed)) {
      expect(parsed.uid).toBe("team-posture");
    }
  });

  test("rejects reserved system uids", () => {
    const bad = SAMPLE_SCHEMA.replace("team-posture", "overview");
    const result = parseAndValidateDashboardJson(bad);
    expect(result).toMatchObject({ kind: "schema" });
  });

  test("rejects unknown panel types", () => {
    const schema = JSON.parse(SAMPLE_SCHEMA) as Record<string, unknown>;
    const layout = schema.layout as Array<{
      panels: Array<{ panel: { type: string } }>;
    }>;
    layout[0].panels[0].panel.type = "iframe";
    const result = validateDashboardSchema(schema as never);
    expect(result?.kind).toBe("schema");
  });

  test("rejects forbidden markup in title", () => {
    const schema = JSON.parse(SAMPLE_SCHEMA) as { title: string };
    schema.title = "Evil <script>alert(1)</script>";
    const result = validateDashboardSchema(schema as never);
    expect(result?.kind).toBe("schema");
    expect(result?.message).toContain("forbidden markup");
  });

  test("rejects invalid JSON", () => {
    const result = parseAndValidateDashboardJson("{not-json");
    expect(result).toMatchObject({ kind: "parse" });
  });

  test("round-trips a system dashboard export with tenant uid", () => {
    const exported = JSON.stringify(overviewDashboard);
    const copy = JSON.parse(exported) as typeof overviewDashboard & {
      uid: string;
      title: string;
    };
    copy.uid = "team-overview-copy";
    copy.title = "Overview copy";
    const result = validateDashboardSchema(copy);
    expect(result).toBeNull();
  });
});
