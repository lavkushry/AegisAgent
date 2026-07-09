import { describe, expect, test } from "bun:test";
import ReceiptIntegrityPanel from "./ReceiptIntegrityPanel";
import { summarizeChain } from "./receiptIntegrityModel";
import type { PanelDefinition } from "../types";

describe("ReceiptIntegrityPanel chain summary", () => {
  test("summarizes empty chain", () => {
    const s = summarizeChain([]);
    expect(s.count).toBe(0);
    expect(s.headId).toBeNull();
    expect(s.headHash).toBeNull();
    expect(s.genesisLinks).toBe(0);
    expect(s.uniqueAgents).toBe(0);
  });

  test("counts genesis links and unique agents", () => {
    const s = summarizeChain([
      {
        id: "r1",
        receipt_hash: "sha256:head",
        prev_receipt_hash: "sha256:prev",
        agent_id: "agent-a",
      },
      {
        id: "r2",
        receipt_hash: "sha256:mid",
        prev_receipt_hash: "genesis",
        agent_id: "agent-a",
      },
      {
        id: "r3",
        receipt_hash: "sha256:other",
        prev_receipt_hash: "",
        agent_id: "agent-b",
      },
    ]);
    expect(s.count).toBe(3);
    expect(s.headId).toBe("r1");
    expect(s.headHash).toBe("sha256:head");
    expect(s.genesisLinks).toBe(2);
    expect(s.uniqueAgents).toBe(2);
  });

  test("component is registered as receipt-integrity shape", () => {
    expect(typeof ReceiptIntegrityPanel).toBe("function");
    const def: PanelDefinition = {
      id: "integrity-controls",
      type: "receipt-integrity",
      title: "Chain integrity",
      datasourceId: "gateway-entity",
      entity: "receipt",
      limit: 50,
      options: { showExports: true, showRangeVerify: true },
    };
    void def;
  });
});
