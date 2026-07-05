import { describe, expect, it } from "vitest";

import {
  applyRangeVerificationResult,
  pickTimelineTime,
  timelineRowsForVerify,
} from "./provableTimelineState";

const opts = {
  timeField: "timestamp",
  labelField: "tool",
  agentField: "agent_id",
  decisionField: "decision",
  receiptIdField: "receipt_id",
  receiptHashField: "receipt_hash",
  prevHashField: "prev_receipt_hash",
};

describe("provableTimelineState", () => {
  it("sorts timeline rows chronologically before range verification", () => {
    const payload = timelineRowsForVerify(
      [
        {
          id: "decision-2",
          timestamp: "2026-06-28T12:00:00Z",
          receipt_hash: "hash-2",
          prev_receipt_hash: "hash-1",
        },
        {
          id: "decision-1",
          timestamp: "2026-06-28T10:00:00Z",
          receipt_hash: "hash-1",
          prev_receipt_hash: "",
        },
      ],
      opts,
    );

    expect(payload.map((row) => row.receipt_hash)).toEqual(["hash-1", "hash-2"]);
    expect(payload[0]?.ts).toBe("2026-06-28T10:00:00Z");
    expect(payload[1]?.prev_receipt_hash).toBe("hash-1");
  });

  it("falls back to created_at and receipt_id when explicit timeline fields are absent", () => {
    expect(
      pickTimelineTime({ created_at: "2026-06-28T09:00:00Z" }, "timestamp"),
    ).toBe("2026-06-28T09:00:00Z");

    const payload = timelineRowsForVerify(
      [{ id: "decision-1", created_at: "2026-06-28T09:00:00Z", receipt_hash: "hash-1" }],
      opts,
    );

    expect(payload[0]?.id).toBe("decision-1");
    expect(payload[0]?.receipt_id).toBe("decision-1");
  });

  it("maps verified range results to an all-green chain state", () => {
    const applied = applyRangeVerificationResult(
      { status: "verified", ok: true, message: "Chain intact." },
      3,
    );

    expect(applied.chain).toMatchObject({ status: "verified", total: 3 });
    expect(Object.keys(applied.rowStates)).toHaveLength(3);
    expect(applied.rowStates[2]?.status).toBe("verified");
  });

  it("maps broken range results to a distinct tamper row and never marks success", () => {
    const applied = applyRangeVerificationResult(
      { status: "failed", ok: false, brokenAtRow: 2, message: "Hash mismatch." },
      4,
    );

    expect(applied.chain).toMatchObject({ status: "failed", brokenAt: 2 });
    expect(applied.rowStates).toEqual({
      1: { status: "failed", message: "Hash mismatch." },
    });
  });

  it("keeps unknown verification fail-closed without green row markers", () => {
    const applied = applyRangeVerificationResult(
      { status: "unknown", ok: false, message: "Gateway did not confirm verification." },
      2,
    );

    expect(applied.chain).toMatchObject({ status: "unknown" });
    expect(applied.rowStates).toEqual({});
  });
});