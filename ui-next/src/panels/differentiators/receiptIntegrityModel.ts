export interface ChainSummary {
  readonly count: number;
  readonly headId: string | null;
  readonly headHash: string | null;
  readonly genesisLinks: number;
  readonly uniqueAgents: number;
}

/** Summarize a receipt list frame for the integrity control surface. */
export function summarizeChain(
  rows: Array<Record<string, unknown>>,
): ChainSummary {
  if (rows.length === 0) {
    return {
      count: 0,
      headId: null,
      headHash: null,
      genesisLinks: 0,
      uniqueAgents: 0,
    };
  }
  const head = rows[0];
  const agents = new Set<string>();
  let genesisLinks = 0;
  for (const row of rows) {
    const agent = row.agent_id;
    if (agent !== undefined && agent !== null && String(agent).trim()) {
      agents.add(String(agent));
    }
    const prev = row.prev_receipt_hash;
    if (
      prev === "genesis" ||
      prev === null ||
      prev === undefined ||
      prev === ""
    ) {
      genesisLinks += 1;
    }
  }
  const headId = head.id ?? head.receipt_id;
  const headHash = head.receipt_hash;
  return {
    count: rows.length,
    headId: headId !== undefined && headId !== null ? String(headId) : null,
    headHash:
      headHash !== undefined && headHash !== null ? String(headHash) : null,
    genesisLinks,
    uniqueAgents: agents.size,
  };
}
