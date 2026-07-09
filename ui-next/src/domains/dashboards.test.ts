import { describe, expect, test } from "bun:test";

import {
  SYSTEM_DASHBOARD_CATALOG,
  copySystemDashboardAsTenant,
} from "@/dashboards/editor/catalog";

describe("system dashboard catalog", () => {
  test("includes overview and integrity as read-only", () => {
    expect(SYSTEM_DASHBOARD_CATALOG.length).toBeGreaterThanOrEqual(5);
    const overview = SYSTEM_DASHBOARD_CATALOG.find((d) => d.uid === "overview");
    const integrity = SYSTEM_DASHBOARD_CATALOG.find(
      (d) => d.uid === "integrity",
    );
    expect(overview?.readOnly).toBe(true);
    expect(integrity?.readOnly).toBe(true);
  });

  test("copySystemDashboardAsTenant rewrites uid and title", () => {
    const copy = copySystemDashboardAsTenant(
      "overview",
      "team-overview-copy",
      "My overview",
    );
    expect(copy).not.toBeNull();
    expect(copy?.uid).toBe("team-overview-copy");
    expect(copy?.title).toBe("My overview");
    expect(copy?.schemaVersion).toBe(1);
  });

  test("copy works for integrity template", () => {
    const copy = copySystemDashboardAsTenant("integrity", "team-integrity");
    expect(copy?.uid).toBe("team-integrity");
    expect(copy?.title).toContain("copy");
  });

  test("copySystemDashboardAsTenant returns null for unknown uid", () => {
    expect(copySystemDashboardAsTenant("nope", "x")).toBeNull();
  });
});
