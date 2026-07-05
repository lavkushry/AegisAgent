import { describe, expect, it } from "vitest";

import type { SocRuleRecord } from "@/app/api";
import { mergeRulesCatalog } from "./useRulesCatalog";

const effectiveRules: SocRuleRecord[] = [
  {
    rule_key: "builtin_rule",
    name: "Built-in",
    severity: "high",
    condition: { decision: "deny" },
    summary_template: "Built-in fired",
    source: "default",
    enabled: true,
  },
];

describe("mergeRulesCatalog", () => {
  it("maps effective rules with default source", () => {
    const catalog = mergeRulesCatalog(effectiveRules, []);
    expect(catalog).toHaveLength(1);
    expect(catalog[0]).toMatchObject({
      rule_key: "builtin_rule",
      source: "default",
      enabled: true,
      dbId: undefined,
    });
  });

  it("attaches custom rule database ids and enabled state", () => {
    const customRules: SocRuleRecord[] = [
      {
        id: "db-1",
        rule_key: "builtin_rule",
        name: "Built-in override",
        severity: "high",
        condition: { decision: "deny" },
        summary_template: "Override",
        source: "custom",
        enabled: false,
      },
    ];
    const catalog = mergeRulesCatalog(effectiveRules, customRules);
    expect(catalog[0]).toMatchObject({ dbId: "db-1", enabled: false });
  });

  it("includes disabled custom rules missing from effective catalogue", () => {
    const customRules: SocRuleRecord[] = [
      {
        id: "db-2",
        rule_key: "disabled_custom",
        name: "Disabled custom",
        severity: "medium",
        condition: "decision: deny",
        summary_template: "Disabled",
        source: "custom",
        enabled: false,
      },
    ];
    const catalog = mergeRulesCatalog(effectiveRules, customRules);
    expect(catalog).toHaveLength(2);
    expect(catalog[1]).toMatchObject({
      rule_key: "disabled_custom",
      source: "custom",
      enabled: false,
      dbId: "db-2",
    });
  });
});