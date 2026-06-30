import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

function readUiSource(relativePath: string): string {
  return readFileSync(join(root, relativePath), "utf8");
}

describe("dangerous console action confirmation inventory", () => {
  it("does not use browser-native confirm dialogs in React SOC console components", () => {
    const componentSources = [
      "src/components/ApprovalsTab.tsx",
      "src/components/DetectionsTab.tsx",
      "src/components/IncidentsTab.tsx",
      "src/components/McpTab.tsx",
      "src/panels/standard/AgentTablePanel.tsx",
      "src/panels/differentiators/ApprovalCard.tsx",
      "src/panels/differentiators/ReceiptIntegrity.tsx",
    ].map(readUiSource);

    for (const source of componentSources) {
      expect(source).not.toMatch(/\bconfirm\s*\(/);
    }
  });

  it.each([
    ["src/components/ApprovalsTab.tsx", ["approveApproval", "rejectApproval", "editApproval"]],
    ["src/components/DetectionsTab.tsx", ["deleteDetectionRule"]],
    ["src/components/IncidentsTab.tsx", ["/close", "evidence-pack"]],
    ["src/components/McpTab.tsx", ["quarantineMcpServer", "restoreMcpServer"]],
    ["src/panels/standard/AgentTablePanel.tsx", ["freezeAgent", "unfreezeAgent"]],
  ])("%s routes implemented dangerous actions through ConfirmDialog", (relativePath, expectedMarkers) => {
    const source = readUiSource(relativePath);

    expect(source).toContain("ConfirmDialog");
    expect(source).toContain("onReasonChange");
    for (const marker of expectedMarkers) {
      expect(source).toContain(marker);
    }
  });
});
