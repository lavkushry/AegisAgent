import { fieldsForEntity } from "../fieldCatalog";
import type { EntityKind } from "../types";

/** Canonical field names accepted in AQL filter terms. */
export const GLOBAL_AQL_FIELDS = new Set([
  "@time",
  "event_type",
  "severity",
  "source_component",
  "agent_id",
  "decision",
  "source_trust",
  "root_trust_level",
  "tool",
  "skill",
  "action",
  "resource",
  "run_id",
  "trace_id",
  "action_hash",
  "receipt_hash",
]);

const FIELD_ALIASES: Readonly<Record<string, string>> = {
  skill: "tool",
  root_trust_level: "source_trust",
};

export function canonicalAqlField(field: string): string {
  const lower = field.toLowerCase();
  return FIELD_ALIASES[lower] ?? lower;
}

export function allowedFieldsForEntity(entity: EntityKind): Set<string> {
  const names = new Set<string>(["@time"]);
  for (const descriptor of fieldsForEntity(entity)) {
    names.add(descriptor.name);
    if (descriptor.name === "tool") names.add("skill");
    if (descriptor.name === "source_trust") names.add("root_trust_level");
  }
  return names;
}

export function isAllowedAqlField(field: string, entity?: EntityKind): boolean {
  const canonical = canonicalAqlField(field);
  if (canonical === "@time") return true;
  if (!entity) return GLOBAL_AQL_FIELDS.has(canonical);
  return allowedFieldsForEntity(entity).has(canonical) || allowedFieldsForEntity(entity).has(field.toLowerCase());
}