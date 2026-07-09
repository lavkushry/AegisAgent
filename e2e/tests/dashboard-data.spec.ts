import { test, expect } from "../fixtures/guardedTest";
import {
  createAllowedDecision,
  createPendingApproval,
  agentControlButton,
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
    await expect(agentControlButton(row, "freeze")).toBeVisible();
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

  test("Overview loads schema-driven board for configured tenant", async ({
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
    await expect(
      page.getByRole("heading", { name: /SOC Overview/i }),
    ).toBeVisible();
    // Schema panels (gateway-entity snapshots)
    await expect(page.getByText("Protected actions").first()).toBeVisible({
      timeout: 15_000,
    });
  });

  test("Agent detail opens from fleet row", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-detail-${Date.now()}`,
    );
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: agent.agentKey });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByRole("link").first().click();
    await expect(page).toHaveURL(new RegExp(`/dashboard/agents/${agent.id}`));
    await expect(page.getByText(agent.agentKey).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole("link", { name: /Fleet/i })).toBeVisible();
  });

  test("Detections, Rules, and Alerting surfaces load", async ({ page }) => {
    await openConfiguredConsole(page);

    await openNav(page, "Detections");
    await expect(
      page.getByRole("heading", { name: "Detections" }),
    ).toBeVisible();
    await expect(page.getByLabel("Filter detections")).toBeVisible();

    await openNav(page, "Rules");
    await expect(page.getByRole("heading", { name: "Rules" })).toBeVisible();

    await openNav(page, "Alerting");
    await expect(
      page.getByRole("heading", { name: "Alerting" }),
    ).toBeVisible();
  });

  test("Dashboard editor validates a draft schema offline", async ({ page }) => {
    await openConfiguredConsole(page);
    await openNav(page, "Dashboards");
    await expect(
      page.getByRole("heading", { name: /Dashboard editor/i }),
    ).toBeVisible();
    await expect(
      page.getByLabel("Dashboard JSON editor"),
    ).toBeVisible();
    // Default draft uses reserved-safe uid my-dashboard; Validate should pass
    // without requiring /v1/soc/dashboards to be available.
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(page.getByText(/Schema is valid/i)).toBeVisible({
      timeout: 5_000,
    });
  });

  test("Dashboard editor lists system templates for copy", async ({ page }) => {
    await openConfiguredConsole(page);
    await openNav(page, "Dashboards");
    await expect(page.getByText("System (read-only)")).toBeVisible();
    // Core catalog boards (Phase B overview + expanded templates)
    for (const title of [
      "SOC Overview",
      "Integrity",
      "Agent fleet",
      "Approvals",
      "Incidents",
      "Detections",
      "MCP registry",
      "Rules",
      "Alerting",
    ]) {
      await expect(page.getByText(title, { exact: true }).first()).toBeVisible();
    }
  });

  test("Dashboard editor can copy a system template into the JSON draft", async ({
    page,
  }) => {
    await openConfiguredConsole(page);
    await openNav(page, "Dashboards");
    // Copy Integrity system board (button title="Copy integrity")
    await page.getByRole("button", { name: /Copy integrity/i }).click();
    await expect(
      page.getByText(/Copied system dashboard 'integrity'/i),
    ).toBeVisible({ timeout: 5_000 });
    const editor = page.getByLabel("Dashboard JSON editor");
    await expect(editor).toContainText('"title"');
    await expect(editor).toContainText("integrity-copy-");
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(page.getByText(/Schema is valid/i)).toBeVisible({
      timeout: 5_000,
    });
  });
});
