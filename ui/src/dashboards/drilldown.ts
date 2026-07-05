import type { DrilldownLink } from "@/panels/types";

/**
 * Shared drilldown helpers for panel links and cross-surface investigation navigation.
 * See docs/AegisAgent_SOC_Console_HLD_LLD.md §7.5.
 */

export type DrilldownNavigation = {
  setActiveView: (view: string) => void;
  setExploreSeed: (seed: string) => void;
  setActiveIncidentId: (id: string | null) => void;
  setActiveReceiptId: (id: string | null) => void;
  setActiveAgentId: (id: string | null) => void;
  setVariables: (vars: Record<string, string>) => void;
  getVariables: () => Record<string, string>;
};

export function applyDrilldownLink(
  nav: DrilldownNavigation,
  link: DrilldownLink,
  row?: Record<string, unknown>,
): void {
  switch (link.target.kind) {
    case "explore":
      nav.setExploreSeed(fillTemplate(link.target.aqlTemplate, row));
      nav.setActiveView("explore");
      break;
    case "verify-receipt":
    case "receipt": {
      const receiptId = row?.[link.target.receiptIdField];
      if (typeof receiptId === "string" && receiptId) {
        nav.setActiveReceiptId(receiptId);
      }
      nav.setActiveView("receipts");
      break;
    }
    case "agent": {
      const agentId = row?.[link.target.agentIdField];
      if (typeof agentId === "string" && agentId) {
        nav.setActiveAgentId(agentId);
      }
      nav.setActiveView("agents");
      break;
    }
    case "incident": {
      const incidentId = row?.[link.target.incidentIdField];
      nav.setActiveIncidentId(typeof incidentId === "string" ? incidentId : null);
      nav.setActiveView("incidents");
      break;
    }
    case "dashboard": {
      if (link.target.mapVars) {
        const mapped = mapRowToVariables(link.target.mapVars, row);
        nav.setVariables({ ...nav.getVariables(), ...mapped });
      }
      nav.setActiveView(link.target.uid);
      break;
    }
  }
}

/** Replace `${field}` tokens in a drilldown AQL template with values from a clicked row. */
export function fillTemplate(template: string, row?: Record<string, unknown>): string {
  if (!row) return template;
  return template.replace(/\$\{(\w+)\}/g, (_, key: string) => {
    const value = row[key];
    return value === null || value === undefined ? "" : String(value);
  });
}

function aqlLiteral(value: string): string {
  return value.includes(" ") || value.includes(":") ? `"${value}"` : value;
}

export function exploreAqlForAgent(agentId: string): string {
  return `agent_id:${aqlLiteral(agentId)}`;
}

export function exploreAqlForReceipt(receiptId: string): string {
  return `receipt_id:${aqlLiteral(receiptId)}`;
}

export function exploreAqlForActionHash(hash: string): string {
  return `action_hash:${aqlLiteral(hash)}`;
}

export function exploreAqlForSourceTrust(trust: string): string {
  return `source_trust:${aqlLiteral(trust)}`;
}

export function exploreAqlForDecision(decision: string): string {
  return `decision:${aqlLiteral(decision)}`;
}

/** Map dashboard variable keys to row field values for drilldown navigation. */
export function mapRowToVariables(
  mapVars: Record<string, string>,
  row?: Record<string, unknown>,
): Record<string, string> {
  if (!row) return {};
  return Object.fromEntries(
    Object.entries(mapVars).map(([varKey, field]) => [varKey, String(row[field] ?? "")]),
  );
}