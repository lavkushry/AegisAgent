import { test, expect } from "../fixtures/guardedTest";
import {
  AGENT_ID,
  AGENT_KEY,
  FAKE_SECRET,
  MCP_SERVER_KEY,
  MOCK_TENANT_A,
  MOCK_TENANT_B,
  RULE_KEY,
} from "../fixtures/gatewayFixtures";
import { installMockGateway, openMockedConsole } from "../fixtures/installMockGateway";
import { assertNoSecrets, confirmDangerousAction } from "./helpers";

test.describe("mocked SOC console workflows (#1638)", () => {
  test("Overview loads tenant posture from fixtures", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    const protectedPanel = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Protected actions" }),
    });
    await expect(protectedPanel.locator(".tabular-nums")).toHaveText("42", { timeout: 10_000 });

    const blockedPanel = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Blocked actions" }),
    });
    await expect(blockedPanel.locator(".tabular-nums")).toHaveText("7");

    const receiptPanel = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Receipt chain" }),
    });
    await expect(receiptPanel.getByText(/unknown/i)).toBeVisible();

    const untrustedPanel = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Untrusted source decisions" }),
    });
    await expect(untrustedPanel.locator(".tabular-nums")).toHaveText("4");

    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("tenant switch shows isolated fixture data", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page, { tenantId: MOCK_TENANT_A });
    const panelA = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Protected actions" }),
    });
    await expect(panelA.locator(".tabular-nums")).toHaveText("42", { timeout: 10_000 });

    await page.getByLabel("Tenant ID").fill(MOCK_TENANT_B);
    await page.getByRole("button", { name: "Apply Config" }).click();
    await page.getByText(MOCK_TENANT_B, { exact: true }).first().waitFor();
    const panelB = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: "Protected actions" }),
    });
    await expect(panelB.locator(".tabular-nums")).toHaveText("3", { timeout: 10_000 });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("approver can approve and reject with confirmation", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "approver", operatorId: "approver-e2e" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Approvals" }).click();
    await expect(page.getByText("Canonical action bytes · aegis-jcs-1").first()).toBeVisible();
    await page.getByRole("button", { name: "Approve" }).first().click();
    await confirmDangerousAction(page, "Approved after evidence review", "Approve exact action");
    await expect(page.getByText(/Approval recorded/i)).toBeVisible({ timeout: 10_000 });

    await page.reload();
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Approvals" }).click();
    await page.getByRole("button", { name: "Reject" }).first().click();
    await confirmDangerousAction(page, "Rejected unsafe merge", "Reject action");
    await expect(page.getByText(/Action rejected/i)).toBeVisible({ timeout: 10_000 });
    // No assertNoSecrets here: this panel deliberately renders the
    // unredacted canonical action bytes (asserted visible above) so the
    // approver can verify the exact frozen bytes they're approving against
    // the bound action_hash -- redacting them would defeat that guarantee.
    // Secret redaction is covered where it's actually expected: the Explore
    // decision detail and Detections alert record tests in this suite.
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("receipt verify surfaces verified, broken, and unknown states", async ({ page }) => {
    const verified = await installMockGateway(page, { role: "viewer", receiptVerifyMode: "verified" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Receipts Log" }).click();
    await expect(page.getByText("Chain not yet verified")).toBeVisible();
    await page.getByRole("button", { name: "Verify range" }).click();
    await expect(page.getByText(/Chain tamper-free/i)).toBeVisible({ timeout: 10_000 });
    await verified.dispose();

    const broken = await installMockGateway(page, { role: "viewer", receiptVerifyMode: "failed" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Receipts Log" }).click();
    await page.getByRole("button", { name: "Verify range" }).click();
    await expect(page.getByText(/Broken at receipt/i)).toBeVisible({ timeout: 10_000 });
    await broken.dispose();

    const unknown = await installMockGateway(page, { role: "viewer", receiptVerifyMode: "unknown" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Receipts Log" }).click();
    // "Verification unknown" is the chain-wide ("Verify range") result
    // label (ReceiptIntegrity.tsx renderRangeStatus) -- the per-row "Verify
    // receipt" button only ever shows an icon with a tooltip, never this
    // visible text, matching the "verified"/"failed" stages above.
    await page.getByRole("button", { name: "Verify range" }).click();
    await expect(page.getByText(/Verification unknown/i)).toBeVisible({ timeout: 10_000 });
    await unknown.dispose();
  });

  test("Explore filters, expands rows, and verifies linked receipts", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst", receiptVerifyMode: "verified" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Explore" }).click();
    await page.getByPlaceholder(/AQL:/).fill(`agent_id:${AGENT_ID}`);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.getByText(`Agent: ${AGENT_ID}`)).toBeVisible({ timeout: 10_000 });

    // Scoped to "Agent: ..." (unique to the result row's own label), not
    // "github" -- the Fields sidebar's facet filter button is also labeled
    // "github" and, being first in DOM order, would otherwise get clicked
    // instead of the actual result row, silently adding a tool:github facet
    // filter rather than expanding the row's detail panel.
    const row = page.locator("button").filter({ hasText: `Agent: ${AGENT_ID}` }).first();
    await row.click();
    await expect(page.getByText("Redacted event document")).toBeVisible();
    await expect(page.locator("pre").filter({ hasText: "[REDACTED]" })).toBeVisible();
    await page.getByRole("button", { name: "Verify receipt" }).click();
    await expect(page.getByText(/verified|matches the hash chain/i)).toBeVisible({ timeout: 10_000 });
    await assertNoSecrets(page, [FAKE_SECRET]);
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("incident timeline verify reports tamper-free chain", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst", receiptVerifyMode: "verified" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Incidents" }).click();
    await page.getByText("receipt-chain-broken").click();
    await page.getByRole("button", { name: "Verify receipt chain" }).click();
    await expect(page.getByText(/Tamper-free/i)).toBeVisible({ timeout: 10_000 });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("analyst freeze and unfreeze agent through detail page", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    await page.getByRole("row").filter({ hasText: AGENT_KEY }).click();
    await page.getByRole("button", { name: "Freeze", exact: true }).click();
    await confirmDangerousAction(page, "Containment during investigation", "Freeze agent");
    await expect(page.getByText("Frozen", { exact: true })).toBeVisible({ timeout: 10_000 });

    await page.getByRole("button", { name: "Unfreeze" }).click();
    await confirmDangerousAction(page, "Investigation complete", "Restore agent");
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("MCP quarantine and restore require audit reason", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "MCP Servers" }).click();
    await page.getByRole("button", { name: `Select MCP server ${MCP_SERVER_KEY}` }).click();
    await page.getByRole("button", { name: "Quarantine" }).click();
    await confirmDangerousAction(page, "Manifest drift detected", "Quarantine server");
    await expect(page.getByText(/quarantined/i).first()).toBeVisible({ timeout: 10_000 });

    await page.getByRole("button", { name: "Restore" }).click();
    await confirmDangerousAction(page, "Manifest re-pinned", "Restore server");
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("rules backtest renders deterministic simulator output", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "admin" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Rules" }).click();
    await page.getByText(RULE_KEY).click();
    await page.getByRole("button", { name: "Run Simulator" }).click();
    await expect(page.getByText("Decisions Scanned")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("12", { exact: true })).toBeVisible();
    await expect(page.getByText("2", { exact: true })).toBeVisible();
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("detections expand redacts secret-shaped alert fields", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Detections" }).click();
    await page.getByText("Mock high-risk merge detected").click();
    await expect(page.getByText("Redacted Alert Record", { exact: true })).toBeVisible();
    await expect(page.locator("pre").filter({ hasText: "[REDACTED]" })).toBeVisible();
    await assertNoSecrets(page, [FAKE_SECRET]);
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });
});