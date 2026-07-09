import { describe, expect, test } from "bun:test";
import { rowsToFrame } from "@/datasources/frame";
import { normalizeVerification } from "@/domains/receipts";
import ProvableTimelinePanel from "./ProvableTimelinePanel";
import type { PanelDefinition } from "../types";

describe("ProvableTimelinePanel data path", () => {
  test("receipt frame carries hash-chain fields", () => {
    const frame = rowsToFrame(
      [
        {
          id: "receipt-e2e-001",
          receipt_hash: "sha256:good",
          prev_receipt_hash: "genesis",
          decision: "allow",
          agent_id: "agent-1",
          source_trust: "trusted_internal_signed",
          ts: "2026-06-28T12:00:00.000Z",
        },
        {
          id: "receipt-e2e-broken",
          receipt_hash: "sha256:bad",
          prev_receipt_hash: "sha256:good",
          decision: "allow",
          agent_id: "agent-1",
          source_trust: "trusted_internal_signed",
          ts: "2026-06-28T12:01:00.000Z",
        },
      ],
      [
        "id",
        "receipt_hash",
        "prev_receipt_hash",
        "decision",
        "agent_id",
        "source_trust",
        "ts",
      ],
    );
    expect(frame.length).toBe(2);
    expect(frame.fields.find((f) => f.name === "receipt_hash")?.values).toEqual(
      ["sha256:good", "sha256:bad"],
    );
  });

  test("fail-closed verify normalize used by timeline", () => {
    expect(normalizeVerification({ verified: true }).ok).toBe(true);
    expect(normalizeVerification({ verified: false }).ok).toBe(false);
    expect(normalizeVerification({}).ok).toBe(false);
  });

  test("component is registered as provable-timeline shape", () => {
    expect(typeof ProvableTimelinePanel).toBe("function");
    const def: PanelDefinition = {
      id: "timeline-receipts",
      type: "provable-timeline",
      title: "Provable timeline",
      datasourceId: "gateway-entity",
      entity: "receipt",
      limit: 25,
      options: { maxRows: 25, showRangeVerify: true },
    };
    void def;
  });
});
