import type {
  AgentRiskRecord,
  AlertRecord,
  IncidentGraph,
  IncidentNarration,
  IncidentRecord,
  McpManifestRecord,
  McpServerRecord,
  SocRuleRecord,
  TenantStats,
  SocSummary,
  EvidenceNode,
} from "../app/api";
import { frameRows, singleRowAsObject } from "./frame";
import type { DataFrame } from "./types";

function rowsWithStringField(
  rows: Array<Record<string, unknown>>,
  field: string,
): Array<Record<string, unknown>> {
  return rows.filter((row) => typeof row[field] === "string");
}

export function tenantStatsFromFrame(frame: DataFrame | undefined): TenantStats {
  return singleRowAsObject(frame) as unknown as TenantStats;
}

export function socSummaryFromFrame(frame: DataFrame | undefined): SocSummary {
  return singleRowAsObject(frame) as unknown as SocSummary;
}

export function alertRowsFromFrame(frame: DataFrame | undefined): AlertRecord[] {
  return frame ? (rowsWithStringField(frameRows(frame), "id") as unknown as AlertRecord[]) : [];
}

export function incidentRowsFromFrame(frame: DataFrame | undefined): IncidentRecord[] {
  return frame ? (rowsWithStringField(frameRows(frame), "id") as unknown as IncidentRecord[]) : [];
}

export function incidentFromFrame(frame: DataFrame | undefined): IncidentRecord | undefined {
  const rows = incidentRowsFromFrame(frame);
  return rows[0];
}

export function agentScoreboardFromFrame(frame: DataFrame | undefined): AgentRiskRecord[] {
  return frame ? (frameRows(frame) as unknown as AgentRiskRecord[]) : [];
}

export function mcpServerRowsFromFrame(frame: DataFrame | undefined): McpServerRecord[] {
  return frame ? (rowsWithStringField(frameRows(frame), "server_key") as unknown as McpServerRecord[]) : [];
}

export function mcpManifestRowsFromFrame(frame: DataFrame | undefined): McpManifestRecord[] {
  return frame ? (frameRows(frame) as unknown as McpManifestRecord[]) : [];
}

export function socRuleRowsFromFrame(frame: DataFrame | undefined): SocRuleRecord[] {
  return frame ? (frameRows(frame) as unknown as SocRuleRecord[]) : [];
}

export function incidentGraphFromFrame(frame: DataFrame | undefined): IncidentGraph {
  const obj = singleRowAsObject(frame);
  const nodes = Array.isArray(obj.nodes) ? (obj.nodes as EvidenceNode[]) : [];
  return { nodes };
}

export function incidentNarrationFromFrame(frame: DataFrame | undefined): IncidentNarration {
  const obj = singleRowAsObject(frame);
  return {
    narrative: typeof obj.narrative === "string" ? obj.narrative : undefined,
    summary: typeof obj.summary === "string" ? obj.summary : undefined,
  };
}