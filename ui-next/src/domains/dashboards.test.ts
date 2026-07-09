import { describe, expect, test } from "bun:test";

import {
  SYSTEM_DASHBOARD_CATALOG,
  copySystemDashboardAsTenant,
} from "@/dashboards/editor/catalog";

describe("system dashboard catalog", () => {
  test("includes overview as read-only", () => {
    expect(SYSTEM_DASHBOARD_CATALOG.length).toBeGreaterThan(0);
    const overview = SYSTEM_DASHBOARD_CATALOG.find((d) => d.uid === "overview");
    expect(overview?.readOnly).toBe(true);
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

  test("copySystemDashboardAsTenant returns null for unknown uid", () => {
    expect(copySystemDashboardAsTenant("nope", "x")).toBeNull();
  });
});
