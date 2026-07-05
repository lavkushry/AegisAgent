import { describe, expect, it } from "vitest";

import { frameRows, rowsToFrame } from "./frame";
import { fieldsForEntity } from "./fieldCatalog";
import { receiptRowsFromFrame } from "./receiptData";
import { socSummaryFromFrame, tenantStatsFromFrame } from "./entityData";
import { decisionRowsFromFrame } from "../components/exploreData";
import { objectToSingleRowFrame } from "./frame";

/** Representative gateway shapes used to guard datasource normalization contracts. */
const FIXTURES = {
  decision: {
    id: "decision-1",
    decision: "deny",
    agent_id: "agent-1",
    action_hash: "abc123",
    created_at: "2026-06-28T10:00:00Z",
  },
  alert: {
    id: "alert-1",
    severity: "high",
    status: "open",
    first_seen: "2026-06-28T10:00:00Z",
  },
  incident: {
    id: "incident-1",
    severity: "critical",
    status: "open",
    opened_at: "2026-06-28T10:00:00Z",
  },
  approval: {
    id: "approval-1",
    status: "pending",
    action_hash: "deadbeef",
    expires_at: "2026-06-28T12:00:00Z",
  },
  agent: {
    id: "agent-1",
    name: "coding-agent",
    root_trust_level: "verified",
  },
  mcp_server: {
    server_key: "github",
    status: "active",
  },
  receipt: {
    id: "receipt-1",
    receipt_hash: "hash-1",
    prev_receipt_hash: "",
    ts: "2026-06-28T10:00:00Z",
  },
  rule: {
    id: "rule-1",
    name: "deny-storm",
    enabled: true,
  },
} as const;

describe("datasource contract fixtures", () => {
  it("round-trips representative entity rows through DataFrame normalization", () => {
    for (const [entity, row] of Object.entries(FIXTURES)) {
      const frame = rowsToFrame([row]);
      const restored = frameRows(frame);
      expect(restored[0]).toEqual(row);
      expect(fieldsForEntity(entity as keyof typeof FIXTURES).length).toBeGreaterThan(0);
    }
  });

  it("extracts typed decision and receipt rows from frames", () => {
    const decisions = decisionRowsFromFrame(rowsToFrame([FIXTURES.decision]));
    const receipts = receiptRowsFromFrame(rowsToFrame([FIXTURES.receipt]));
    expect(decisions[0]?.id).toBe("decision-1");
    expect(receipts[0]?.receipt_hash).toBe("hash-1");
  });

  it("round-trips snapshot objects through single-row frame extractors", () => {
    const stats = {
      total_decisions: 128,
      decisions_allow: 121,
      decisions_deny: 7,
      total_receipts: 64,
      receipt_chain_verified: true,
    };
    const summary = {
      approvals_pending: 3,
      incidents_open: 1,
      hourly_decisions_24h: [1, 2, 3],
    };

    expect(tenantStatsFromFrame(objectToSingleRowFrame(stats))).toMatchObject(stats);
    expect(socSummaryFromFrame(objectToSingleRowFrame(summary))).toMatchObject(summary);
  });
});