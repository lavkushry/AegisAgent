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
  agentId?: string;
  decision?: string;
  sourceTrust?: string;
  q?: string;
}

const BOOLEANS = new Set(["AND", "OR"]);
const FIELD_TERM = /^(\w+):(.+)$/;

export function parseAql(input: string): ParsedQuery {
  const raw = (input ?? "").trim();
  if (!raw) return {};

  const tokens = raw.split(/\s+/).filter((t) => t && !BOOLEANS.has(t.toUpperCase()));

  let agentId: string | undefined;
  let decision: string | undefined;
  let sourceTrust: string | undefined;
  const qTerms: string[] = [];

  for (const token of tokens) {
    const match = FIELD_TERM.exec(token);
    if (match) {
      const field = match[1].toLowerCase();
      const value = match[2];
      if (field === "agent_id" && !agentId) {
        agentId = value;
      } else if (field === "decision" && !decision) {
        decision = value;
      } else if ((field === "source_trust" || field === "root_trust_level") && !sourceTrust) {
        sourceTrust = value;
      } else {
        // Unknown/unsupported field filter — search its value as a keyword.
        qTerms.push(value);
      }
    } else {
      qTerms.push(token);
    }
  }

  return {
    agentId,
    decision,
    sourceTrust,
    q: qTerms.length > 0 ? qTerms.join(" ") : undefined,
  };
}
