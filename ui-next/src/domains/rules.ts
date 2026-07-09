import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface SocRuleRecord {
  id?: string;
  rule_key: string;
  name: string;
  severity: string;
  condition: unknown;
  summary_template: string;
  source?: string;
  enabled: boolean;
}

export async function listSocRules(opts: FetchOptions): Promise<SocRuleRecord[]> {
  try {
    const raw = await fetchFromGateway<unknown>(opts, "/v1/soc/rules");
    const rows = asRecordArray(raw).map((r) => r as unknown as SocRuleRecord);
    if (rows.length) return rows;
  } catch {
    // fall through to detection_rules
  }
  const raw = await fetchFromGateway<unknown>(opts, "/v1/detection_rules");
  return asRecordArray(raw).map((r) => r as unknown as SocRuleRecord);
}

export function conditionPreview(condition: unknown): string {
  if (condition == null) return "—";
  if (typeof condition === "string") {
    return condition.length > 120 ? `${condition.slice(0, 120)}…` : condition;
  }
  try {
    const s = JSON.stringify(condition);
    return s.length > 120 ? `${s.slice(0, 120)}…` : s;
  } catch {
    return String(condition);
  }
}
