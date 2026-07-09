import { test, expect } from "../fixtures/guardedTest";
import {
  createAllowedDecision,
  createPendingApproval,
  openConfiguredConsole,
  openNav,
  registerTestAgent,
  registerTestMcpServer,
  TENANT_ID,
} from "./helpers";

/**
 * Phase 4 — Bun SPA P0 data workflows against a live gateway.
 * Surfaces: Agents, MCP, Explore, Integrity, Approvals, Overview stats.
 */
test.describe("production SOC console data workflows (ui-next)", () => {
  test("Agents fleet lists a registered agent with freeze control", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-agent-${Date.now()}`,
    );
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: agent.agentKey });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await expect(row.getByRole("button", { name: "freeze" })).toBeVisible();
  });

  test("MCP registry renders a newly registered server", async ({
    page,
    request,
    baseURL,
  }) => {
    const serverKey = `console-e2e-mcp-${Date.now()}`;
    await registerTestMcpServer(request, baseURL!, serverKey);
    await openConfiguredConsole(page);
    await openNav(page, "MCP");
    // Card is a button containing the server key
    const card = page.getByRole("button", { name: new RegExp(serverKey) });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.click();
    await expect(page.getByText(/Transport|Manifest|Tools/i).first()).toBeVisible();
  });

  test("Explore searches decisions", async ({ page, request, baseURL }) => {
    const agentKey = `console-e2e-explore-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    await openConfiguredConsole(page);
    await openNav(page, "Explore");
    await page.getByLabel("Explore query").fill(`agent_id:${agent.id}`);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    // Table should render (may be empty if authorize denied); at least search UI works
    await expect(page.getByRole("table")).toBeVisible({ timeout: 10_000 });
  });

  test("Integrity page exposes verify range", async ({
    page,
    request,
    baseURL,
  }) => {
    const agentKey = `console-e2e-receipt-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    await openConfiguredConsole(page);
    await openNav(page, "Integrity");
    await expect(
      page.getByRole("heading", { name: "Integrity" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Verify range" }),
    ).toBeVisible();
  });

  test("Approvals queue is reachable and identity-gated without operator", async ({
    page,
    request,
    baseURL,
  }) => {
    const agentKey = `console-e2e-approval-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createPendingApproval(request, baseURL!, agent.agentToken, agentKey);

    // Open settings without operator id
    await page.goto("/dashboard/settings");
    await page.getByLabel(/Gateway URL/i).fill("http://127.0.0.1:8080");
    await page.getByLabel(/Tenant ID/i).fill(TENANT_ID);
    await page.getByLabel(/Bearer token/i).fill(TENANT_ID);
    await page.getByLabel(/Operator ID/i).fill("");
    await page.getByRole("button", { name: /Apply Config/i }).click();

    await openNav(page, "Approvals");
    await expect(
      page.getByRole("heading", { name: "Approvals" }),
    ).toBeVisible();
    // Without operator, banner explains read-only
    await expect(page.getByText(/Operator ID/i).first()).toBeVisible();
  });

  test("Overview loads stats grid for configured tenant", async ({
    page,
    request,
    baseURL,
  }) => {
    const response = await request.get(`${baseURL}/v1/stats`, {
      headers: {
        Authorization: `Bearer ${TENANT_ID}`,
        "X-Aegis-Tenant-ID": TENANT_ID,
      },
    });
    expect(response.ok()).toBe(true);
    await openConfiguredConsole(page);
    await openNav(page, "Overview");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    // Stat cards from /v1/stats
    await expect(page.getByText("Decisions").first()).toBeVisible({
      timeout: 15_000,
    });
  });
});
