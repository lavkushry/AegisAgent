import { describe, expect, test } from "bun:test";

import { SYSTEM_DASHBOARD_CATALOG } from "../editor/catalog";
import { validateDashboardSchema } from "../editor/validate";
import {
  approvalsDashboard,
  fleetDashboard,
  incidentsDashboard,
  integrityDashboard,
  overviewDashboard,
} from "./index";

const SYSTEM = [
  overviewDashboard,
  integrityDashboard,
  fleetDashboard,
  approvalsDashboard,
  incidentsDashboard,
] as const;

describe("system dashboards", () => {
  test("catalog lists all built-in boards", () => {
    const uids = SYSTEM_DASHBOARD_CATALOG.map((e) => e.uid).sort();
    expect(uids).toEqual(
      ["approvals", "fleet", "incidents", "integrity", "overview"].sort(),
    );
    for (const entry of SYSTEM_DASHBOARD_CATALOG) {
      expect(entry.readOnly).toBe(true);
    }
  });

  test("every system schema validates after tenant uid rewrite", () => {
    for (const schema of SYSTEM) {
      const tenantCopy = {
        ...schema,
        uid: `team-${schema.uid}-copy`,
        title: `${schema.title} (copy)`,
      };
      const error = validateDashboardSchema(tenantCopy);
      expect(error).toBeNull();
    }
  });

  test("reserved system uids are rejected for tenant use", () => {
    for (const schema of SYSTEM) {
      const error = validateDashboardSchema(schema);
      expect(error?.kind).toBe("schema");
      expect(error?.message).toContain("reserved system uid");
    }
  });
});
