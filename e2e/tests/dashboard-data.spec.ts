import { test, expect } from "@playwright/test";
import {
  createAllowedDecision,
  createPendingApproval,
  registerTestAgent,
  TENANT_ID,
} from "./helpers";

// These tests assume `scripts/seed-demo.sh` has already run against the
// target gateway (CI does this before the Playwright job; for local runs,
// start the gateway and run the seed script first — see CLAUDE.md).

test.describe("dashboard data views", () => {
  test("Agents Fleet table renders the seeded demo agent", async ({ page }) => {
    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="agents"]').click();
    await expect(page.locator("#agents-tbody tr.empty-row")).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.locator("#agents-tbody")).toContainText("coding-agent-prod");
    await expect(page.locator("#error-banner")).toBeHidden();
  });

  test("Alerts view loads without raising the error banner", async ({ page }) => {
    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="alerts"]').click();
    // Either real rows or the documented empty state — never left on "Loading...".
    await expect(page.locator("#alerts-view-tbody")).not.toContainText("Loading alerts...", {
      timeout: 10_000,
    });
    await expect(page.locator("#error-banner")).toBeHidden();
  });

  test("MCP Servers view renders the seeded demo MCP server", async ({ page }) => {
    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="mcp"]').click();
    await expect(page.locator("#mcp-servers-tbody tr.empty-row")).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.locator("#mcp-servers-tbody")).toContainText("github-mcp-demo");
  });

  test("Explore view executes a search and renders the decisions table", async ({ page }) => {
    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="explore"]').click();
    await page.locator("#execute-search-btn").click();
    await expect(page.locator("#search-results-count")).not.toContainText(
      "Showing 0 decisions",
      { timeout: 10_000 },
    );
    await expect(page.locator("#explore-tbody tr.empty-row")).toHaveCount(0);
  });

  test("Integrity Logs view renders the receipt chain with verify actions", async ({ page }) => {
    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="receipts"]').click();
    await expect(page.locator("#receipts-tbody tr.empty-row")).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(
      page.locator("#receipts-tbody .verify-single-receipt").first(),
    ).toBeVisible();
  });

  test("Approvals workflow: a pending approval appears and can be approved", async ({
    page,
    request,
    baseURL,
  }) => {
    const agentKey = `dashboard-e2e-agent-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createPendingApproval(request, baseURL!, agent.agentToken, agentKey);

    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="approvals"]').click();

    // The card renders `approval.agent_id`, which is the agent's UUID, not
    // the human-readable agent_key — filter on the UUID we got back from
    // registration.
    const card = page.locator(".approval-card").filter({ hasText: agent.id });
    await expect(card).toBeVisible({ timeout: 10_000 });
    await expect(card).toContainText("merge_pull_request");

    page.once("dialog", (dialog) => dialog.accept());
    await card.locator(".approve-btn").click();

    // Approving removes it from the *pending* queue, so the card disappears.
    await expect(
      page.locator(".approval-card").filter({ hasText: agent.id }),
    ).toHaveCount(0, { timeout: 10_000 });
  });

  test("overview 'Protected Actions' stat reflects the real /v1/stats total_decisions count", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained: don't rely on another (possibly parallel) test having
    // already produced a decision row — guarantee at least one ourselves.
    const agentKey = `dashboard-e2e-stats-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);

    const resp = await request.get(`${baseURL}/v1/stats`, {
      headers: {
        Authorization: `Bearer ${TENANT_ID}`,
        "X-Aegis-Tenant-ID": TENANT_ID,
      },
    });
    expect(resp.ok()).toBe(true);
    const stats = await resp.json();
    expect(stats).toHaveProperty("total_decisions");
    expect(stats.total_decisions).toBeGreaterThan(0);

    // `total_decisions` is a monotonically increasing, append-only counter
    // shared across the whole suite (tests run in parallel against one
    // gateway), so the dashboard's later read can only be >= this snapshot —
    // an exact-equality assertion here would be flaky by construction.
    await page.goto("/dashboard/");
    await expect
      .poll(
        async () => {
          const text = await page.locator("#stat-protected").textContent();
          return Number(text);
        },
        { timeout: 10_000 },
      )
      .toBeGreaterThanOrEqual(stats.total_decisions);
  });
});
