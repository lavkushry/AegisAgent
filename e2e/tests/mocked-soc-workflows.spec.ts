import { test, expect } from "../fixtures/guardedTest";
import {
  AGENT_KEY,
  FAKE_SECRET,
  MCP_SERVER_KEY,
  MOCK_TENANT_A,
  MOCK_TENANT_B,
} from "../fixtures/gatewayFixtures";
import {
  installMockGateway,
  openMockedConsole,
} from "../fixtures/installMockGateway";
import {
  agentControlButton,
  assertNoSecrets,
  confirmDangerousAction,
  openNav,
} from "./helpers";

/**
 * Mocked SOC workflows (#1638) re-ported for the Bun SPA (ui-next).
 * Uses Playwright route interception — no live gateway required.
 */
test.describe("mocked SOC console workflows (#1638)", () => {
  test("Overview loads tenant posture from fixtures", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await openNav(page, "Overview");
    const panel = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: /Protected actions/i }),
    });
    await expect(panel.locator(".tabular-nums")).toHaveText("42", {
      timeout: 15_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("tenant switch shows isolated fixture data", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page, { tenantId: MOCK_TENANT_A });
    await openNav(page, "Overview");
    const panelA = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: /Protected actions/i }),
    });
    await expect(panelA.locator(".tabular-nums")).toHaveText("42", {
      timeout: 15_000,
    });

    await openNav(page, "Settings");
    await page.getByLabel(/Tenant ID/i).fill(MOCK_TENANT_B);
    await page.getByLabel(/Bearer token/i).fill("fake-bearer-e2e-only");
    await page.getByRole("button", { name: /Apply Config/i }).click();
    await page.getByText(MOCK_TENANT_B, { exact: true }).first().waitFor();
    await openNav(page, "Overview");
    const panelB = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: /Protected actions/i }),
    });
    await expect(panelB.locator(".tabular-nums")).toHaveText("3", {
      timeout: 15_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("approver can approve with confirmation and secrets stay redacted", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, {
      role: "approver",
      operatorId: "approver-e2e",
    });
    await openMockedConsole(page, { operatorId: "approver-e2e" });
    await openNav(page, "Approvals");
    await expect(
      page.getByRole("heading", { name: "Approvals" }),
    ).toBeVisible();
    // Tool call JSON is display-redacted (api_key → [REDACTED])
    await expect(page.getByText("[REDACTED]").first()).toBeVisible({
      timeout: 10_000,
    });
    await assertNoSecrets(page, [FAKE_SECRET]);

    await page.getByRole("button", { name: /Approve/i }).first().click();
    await confirmDangerousAction(
      page,
      "Approved after evidence review",
      /Confirm approve/i,
    );
    await expect(page.getByText(/Approval recorded/i)).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Integrity verify range surfaces verified chain", async ({ page }) => {
    const mock = await installMockGateway(page, {
      role: "viewer",
      receiptVerifyMode: "verified",
    });
    await openMockedConsole(page);
    await openNav(page, "Integrity");
    await page.getByRole("button", { name: "Verify range" }).click();
    await expect(
      page.getByText(/tamper-free|matches recomputed|verified/i).first(),
    ).toBeVisible({ timeout: 10_000 });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Integrity verify range surfaces broken chain", async ({ page }) => {
    const mock = await installMockGateway(page, {
      role: "viewer",
      receiptVerifyMode: "failed",
    });
    await openMockedConsole(page);
    await openNav(page, "Integrity");
    await page.getByRole("button", { name: "Verify range" }).click();
    await expect(
      page.getByText(/Tamper detected|chain is broken|failed/i).first(),
    ).toBeVisible({ timeout: 10_000 });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Explore searches decisions against mock fixtures", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Explore");
    await page.getByLabel("Explore query").fill("decision:allow");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.getByRole("table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("github").first()).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("analyst freeze agent through fleet controls", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: AGENT_KEY });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await agentControlButton(row, "freeze").click();
    await confirmDangerousAction(
      page,
      "Containment during investigation",
      /Confirm freeze/i,
    );
    await expect(
      page.getByText(/freeze completed|frozen|Agent freeze/i).first(),
    ).toBeVisible({ timeout: 10_000 });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("MCP quarantine requires audit reason", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "MCP");
    const card = page.getByRole("button").filter({ hasText: MCP_SERVER_KEY });
    await expect(card).toBeVisible({ timeout: 10_000 });
    await card.click();
    await page.getByRole("button", { name: /Quarantine/i }).click();
    await confirmDangerousAction(
      page,
      "Manifest drift detected",
      /Confirm quarantine|Quarantine/i,
    );
    await expect(page.getByText(/quarantined/i).first()).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Detections lists mock alert without leaking fixture secrets", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await openNav(page, "Detections");
    await expect(
      page.getByText("Mock high-risk merge detected"),
    ).toBeVisible({ timeout: 10_000 });
    await assertNoSecrets(page, [FAKE_SECRET]);
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Dashboard editor validates draft without gateway dashboards", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "admin" });
    await openMockedConsole(page);
    await openNav(page, "Dashboards");
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(page.getByText(/Schema is valid/i)).toBeVisible({
      timeout: 5_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });
});
