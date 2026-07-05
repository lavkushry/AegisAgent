import { useMemo } from "react";
import type { SocRuleRecord } from "@/app/api";

export type CatalogRule = {
  rule_key: string;
  name: string;
  severity: string;
  condition: SocRuleRecord["condition"];
  summary_template: string;
  source: string;
  enabled: boolean;
  dbId?: string;
};

export function mergeRulesCatalog(
  effectiveRules: SocRuleRecord[] | undefined,
  customRules: SocRuleRecord[] | undefined,
): CatalogRule[] {
  if (!effectiveRules) return [];

  const list: CatalogRule[] = effectiveRules.map((rule) => ({
    rule_key: rule.rule_key,
    name: rule.name,
    severity: rule.severity,
    condition: rule.condition,
    summary_template: rule.summary_template,
    source: rule.source || "default",
    enabled: true,
    dbId: undefined,
  }));

  if (customRules) {
    for (const customRule of customRules) {
      const match = list.find((entry) => entry.rule_key === customRule.rule_key);
      if (match) {
        match.dbId = customRule.id;
        match.enabled = customRule.enabled;
      } else if (!customRule.enabled) {
        list.push({
          rule_key: customRule.rule_key,
          name: customRule.name,
          severity: customRule.severity,
          condition: customRule.condition,
          summary_template: customRule.summary_template,
          source: "custom",
          enabled: false,
          dbId: customRule.id,
        });
      }
    }
  }

  return list;
}

export function useRulesCatalog(
  effectiveRules: SocRuleRecord[] | undefined,
  customRules: SocRuleRecord[] | undefined,
): CatalogRule[] {
  return useMemo(
    () => mergeRulesCatalog(effectiveRules, customRules),
    [effectiveRules, customRules],
  );
}