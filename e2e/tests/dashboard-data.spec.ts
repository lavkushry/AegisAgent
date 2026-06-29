import { test, expect } from "@playwright/test";
import {
  createAllowedDecision, createPendingApproval, openConfiguredConsole,
  registerTestAgent, registerTestMcpServer, TENANT_ID,
} from "./helpers";

test.describe("production SOC console data workflows", () => {
  test("Agents Fleet renders a gateway agent and role-gates Active Response", async ({ page, request, baseURL }) => {
    const agent = await registerTestAgent(request, baseURL!, `console-e2e-agent-${Date.now()}`);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    const row = page.getByRole("row").filter({ hasText: agent.id });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row.getByRole("button", { name: "Freeze" })).toBeDisabled();
  });

  test("Detections & Rules loads deterministic rule operations", async ({ page }) => {
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Detections & Rules" }).click();
    await expect(page.getByText("Detection Rules & Backtesting")).toBeVisible();
    await page.getByRole("button", { name: "Detection Rules & Backtesting" }).click();
    await expect(page.getByText("Rules Catalogue")).toBeVisible({ timeout: 10_000 });
  });

  test("MCP registry renders a newly registered server", async ({ page, request, baseURL }) => {
    const serverKey = `console-e2e-mcp-${Date.now()}`;
    await registerTestMcpServer(request, baseURL!, serverKey);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "MCP Servers" }).click();
    const serverCard = page.getByRole("button", { name: new RegExp(serverKey) });
    await expect(serverCard).toBeVisible({ timeout: 10_000 });
    await serverCard.click();
    await expect(page.getByText(/Manifest Drift History/)).toBeVisible();
  });

  test("Explore executes AQL and renders the matching decision", async ({ page, request, baseURL }) => {
    const agentKey = `console-e2e-explore-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Explore" }).click();
    await page.getByPlaceholder(/AQL:/).fill(`agent_id:${agent.id}`);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.getByText(`Agent: ${agent.id}`, { exact: true })).toBeVisible({ timeout: 10_000 });
  });

  test("Receipts Log exposes gateway receipt verification", async ({ page, request, baseURL }) => {
    const agentKey = `console-e2e-receipt-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Receipts Log" }).click();
    await expect(page.getByText("Cryptographic Receipts Integrity Log")).toBeVisible();
    const link = page.getByText(/link:/).first();
    await expect(link).toBeVisible({ timeout: 10_000 });
    await link.locator("../..").click();
    await expect(page.getByRole("button", { name: "Verify Signature Link" }).first()).toBeVisible();
  });

  test("ApprovalCard shows canonical bytes and denies viewer actions", async ({ page, request, baseURL }) => {
    const agentKey = `console-e2e-approval-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createPendingApproval(request, baseURL!, agent.agentToken, agentKey);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Approvals" }).click();
    await expect(page.getByText("Canonical action bytes · aegis-jcs-1").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(agent.id, { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve" }).first()).toBeDisabled();
    await expect(page.getByText(/Read-only as viewer/)).toBeVisible();
  });

  test("Overview Protected Actions reflects the gateway total", async ({ page, request, baseURL }) => {
    const agentKey = `console-e2e-stats-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    const response = await request.get(`${baseURL}/v1/stats`, {
      headers: { Authorization: `Bearer ${TENANT_ID}`, "X-Aegis-Tenant-ID": TENANT_ID },
    });
    expect(response.ok()).toBe(true);
    const stats = await response.json();
    await openConfiguredConsole(page);
    const tile = page.getByText("PROTECTED ACTIONS").locator("../..");
    await expect.poll(async () => Number((await tile.locator(".text-3xl").textContent()) ?? 0), { timeout: 10_000 })
      .toBeGreaterThanOrEqual(stats.total_decisions);
  });
});
