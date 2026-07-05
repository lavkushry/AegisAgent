import { describe, expect, it } from "vitest";

import type { AlertRecord } from "@/app/api";
import type { CatalogRule } from "@/components/rules/useRulesCatalog";
import { buildRuleHealthRows, ruleHealthLabel } from "./ruleHealth";

const now = Date.parse("2026-07-05T12:00:00Z");

const builtinRule: CatalogRule = {
  rule_key: "deny_burst",
  name: "Deny burst",
  severity: "high",
  condition: { decision: "deny" },
  summary_template: "Burst",
  source: "default",
  enabled: true,
};

const customRule: CatalogRule = {
  rule_key: "custom_rule",
  name: "Custom",
  severity: "medium",
  condition: { decision: "deny" },
  summary_template: "Custom fired",
  source: "custom",
  enabled: true,
  dbId: "db-1",
};

const disabledRule: CatalogRule = {
  rule_key: "disabled_rule",
  name: "Disabled",
  severity: "low",
  condition: { decision: "deny" },
  summary_template: "Off",
  source: "custom",
  enabled: false,
  dbId: "db-2",
};

function alertFor(ruleKey: string, at: string): AlertRecord {
  return {
    id: "1",
    alert_id: "alert-1",
    rule: ruleKey,
    severity: "high",
    summary: "test",
    agent_id: "agent-1",
    created_at: at,
    occurred_at: at,
  };
}

describe("buildRuleHealthRows", () => {
  it("marks firing when alerts match in the last 24h", () => {
    const rows = buildRuleHealthRows(
      [customRule],
      [alertFor("custom_rule", "2026-07-05T10:00:00Z")],
      now,
    );
    expect(rows[0].status).toBe("firing");
    expect(rows[0].alertCount24h).toBe(1);
  });

  it("marks disabled rules as error", () => {
    const rows = buildRuleHealthRows([disabledRule], [], now);
    expect(rows[0].status).toBe("error");
  });

  it("marks default-source rules without alerts as unsupported throughput", () => {
    const rows = buildRuleHealthRows([builtinRule], [], now);
    expect(rows[0].status).toBe("unsupported");
    expect(rows[0].throughputLabel).toContain("unavailable");
  });

  it("marks enabled custom rules with no alerts as normal", () => {
    const rows = buildRuleHealthRows([customRule], [], now);
    expect(rows[0].status).toBe("normal");
    expect(rows[0].throughputLabel).toBe("0 alerts / 24h");
  });
});

describe("ruleHealthLabel", () => {
  it("maps statuses to labels", () => {
    expect(ruleHealthLabel("firing")).toBe("Firing");
    expect(ruleHealthLabel("normal")).toBe("Normal");
    expect(ruleHealthLabel("unsupported")).toBe("Unsupported");
  });
});