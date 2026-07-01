/**
 * AQL — a deliberately small, safe filter syntax for Explore.
 *
 *   field:value [AND|OR field:value] [free terms]
 *
 * It compiles to the gateway's existing PARAMETERIZED /v1/decisions filters
 * (agent_id, decision, q). Known fields map to typed params; everything else
 * becomes FTS5 keyword terms (q), which the gateway sanitizes server-side.
 * Nothing here is ever interpolated into SQL — the gateway binds it.
 *
 * The richer typed pipeline (POST /v1/soc/query with an AST) lands when the
 * gateway exposes that endpoint; this maps to what exists today.
 */

export interface ParsedQuery {
  eventType?: string;
  severity?: string;
  sourceComponent?: string;
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  /** The tool / integration name (stored as `skill` on the gateway). */
  skill?: string;
  action?: string;
  resource?: string;
  runId?: string;
  traceId?: string;
  actionHash?: string;
  receiptHash?: string;
  q?: string;
}

const BOOLEANS = new Set(["AND", "OR"]);
const FIELD_TERM = /^(\w+):(.+)$/;

export function parseAql(input: string): ParsedQuery {
  const raw = (input ?? "").trim();
  if (!raw) return {};

  const tokens = raw.split(/\s+/).filter((t) => t && !BOOLEANS.has(t.toUpperCase()));

  let agentId: string | undefined;
  let eventType: string | undefined;
  let severity: string | undefined;
  let sourceComponent: string | undefined;
  let decision: string | undefined;
  let sourceTrust: string | undefined;
  let skill: string | undefined;
  let action: string | undefined;
  let resource: string | undefined;
  let runId: string | undefined;
  let traceId: string | undefined;
  let actionHash: string | undefined;
  let receiptHash: string | undefined;
  const qTerms: string[] = [];

  for (const token of tokens) {
    const match = FIELD_TERM.exec(token);
    if (match) {
      const field = match[1].toLowerCase();
      const value = match[2];
      if (field === "event_type" && !eventType) {
        eventType = value;
      } else if (field === "severity" && !severity) {
        severity = value;
      } else if (field === "source_component" && !sourceComponent) {
        sourceComponent = value;
      } else if (field === "agent_id" && !agentId) {
        agentId = value;
      } else if (field === "decision" && !decision) {
        decision = value;
      } else if ((field === "source_trust" || field === "root_trust_level") && !sourceTrust) {
        sourceTrust = value;
      } else if ((field === "tool" || field === "skill") && !skill) {
        skill = value;
      } else if (field === "action" && !action) {
        action = value;
      } else if (field === "resource" && !resource) {
        resource = value;
      } else if (field === "run_id" && !runId) {
        runId = value;
      } else if (field === "trace_id" && !traceId) {
        traceId = value;
      } else if (field === "action_hash" && !actionHash) {
        actionHash = value;
      } else if (field === "receipt_hash" && !receiptHash) {
        receiptHash = value;
      } else {
        // Unknown/unsupported field filter — search its value as a keyword.
        qTerms.push(value);
      }
    } else {
      qTerms.push(token);
    }
  }

  return {
    eventType,
    severity,
    sourceComponent,
    agentId,
    decision,
    sourceTrust,
    skill,
    action,
    resource,
    runId,
    traceId,
    actionHash,
    receiptHash,
    q: qTerms.length > 0 ? qTerms.join(" ") : undefined,
  };
}
