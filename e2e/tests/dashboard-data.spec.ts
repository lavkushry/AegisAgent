import { test, expect } from "@playwright/test";
import {
  createAllowedDecision,
  createPendingApproval,
  registerTestAgent,
  registerTestMcpServer,
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

  test("MCP server detail view: tool allowlist approve/disable and quarantine/restore (#1334)", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained: a dedicated server/tool, not the shared seeded
    // github-mcp-demo, since this test mutates tool and quarantine status.
    const serverKey = `dashboard-e2e-mcp-${Date.now()}`;
    await registerTestMcpServer(request, baseURL!, serverKey);

    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="mcp"]').click();
    const row = page.locator("#mcp-servers-tbody tr", { hasText: serverKey });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await row.click();

    // Detail view replaces the list view.
    await expect(page.locator("#mcp-detail-container")).toBeVisible();
    await expect(page.locator("#mcp-list-container")).toBeHidden();
    await expect(page.locator("#mcp-detail-server-key")).toContainText(serverKey);
    await expect(page.locator("#mcp-detail-manifest-hash")).toContainText("sha256:");
    await expect(page.locator("#mcp-detail-history-tbody")).toContainText("sha256:");

    // Tool starts "pending" (discover_mcp_tools default) — approve it.
    const toolRow = page.locator("#mcp-detail-tools-tbody tr", {
      hasText: "create_issue",
    });
    await expect(toolRow).toContainText("pending");
    page.once("dialog", (dialog) => dialog.accept());
    await toolRow.locator(".approve-tool-btn").click();
    await expect(toolRow).toContainText("approved", { timeout: 10_000 });
    await expect(toolRow.locator(".approve-tool-btn")).toBeDisabled();

    // Disable it.
    page.once("dialog", (dialog) => dialog.accept());
    await toolRow.locator(".disable-tool-btn").click();
    await expect(toolRow).toContainText("disabled", { timeout: 10_000 });
    await expect(toolRow.locator(".disable-tool-btn")).toBeDisabled();

    // Server-level quarantine/restore (separate from per-tool status).
    await expect(page.locator("#mcp-detail-quarantine-status")).toContainText("Active");
    page.once("dialog", (dialog) => dialog.accept());
    await page.locator("#mcp-quarantine-btn").click();
    await expect(page.locator("#mcp-detail-quarantine-status")).toContainText(
      "Quarantined",
      { timeout: 10_000 },
    );

    page.once("dialog", (dialog) => dialog.accept());
    await page.locator("#mcp-restore-btn").click();
    await expect(page.locator("#mcp-detail-quarantine-status")).toContainText(
      "Active",
      { timeout: 10_000 },
    );

    // Back to the registry list.
    await page.locator("#back-to-mcp-btn").click();
    await expect(page.locator("#mcp-list-container")).toBeVisible();
    await expect(page.locator("#mcp-detail-container")).toBeHidden();
  });

  test("Trust Level Distribution: color-coded badges, overview chart, and untrusted-sources stat (#1294)", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained: a dedicated agent with one decision at each of two
    // trust levels, so this test doesn't depend on what trust levels other
    // (possibly parallel) tests have produced.
    const agentKey = `dashboard-e2e-trust-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey, "trusted_internal_signed");
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey, "untrusted_external");

    // Overview: the Trust Level Distribution chart and "Untrusted Sources"
    // stat are tenant-wide aggregates shared with parallel tests, so assert
    // only on what's true regardless of what else is running: the bar for
    // each level we just created becomes visible (decisions are append-only,
    // so once a level appears it stays — no flaky exact-count assertion),
    // and the stat renders a well-formed percentage.
    await page.goto("/dashboard/");
    await expect(page.locator("#trust-level-distribution")).toContainText(
      "untrusted_external",
      { timeout: 10_000 },
    );
    await expect(page.locator("#trust-level-distribution")).toContainText(
      "trusted_internal_signed",
    );
    await expect(page.locator("#stat-untrusted-pct")).toHaveText(/^\d+%$/);

    // Explore: our two decisions render with color-coded trust badges, not
    // the old flat badge-dark for every level.
    await page.locator('.menu-item[data-view="explore"]').click();
    await page.locator("#execute-search-btn").click();

    // Column 5 is "Source Trust" — scope to it so the decision badge
    // ("allow", also badge-success) isn't matched too.
    const trustedRow = page.locator("#explore-tbody tr", {
      hasText: agent.id,
    }).filter({ hasText: "trusted_internal_signed" });
    await expect(trustedRow.locator("td:nth-child(5) .badge-success")).toBeVisible({
      timeout: 10_000,
    });

    const untrustedRow = page.locator("#explore-tbody tr", {
      hasText: agent.id,
    }).filter({ hasText: "untrusted_external" });
    await expect(untrustedRow.locator("td:nth-child(5) .badge-error")).toBeVisible();

    // Trust facet sidebar is filterable (pre-existing capability, #1294 AC).
    const facetEntry = page.locator("#facet-trust .facet-item", {
      hasText: "untrusted_external",
    });
    await facetEntry.click();
    await expect(page.locator("#active-filters-container")).toContainText(
      "trust",
    );
    await expect(page.locator("#explore-tbody")).not.toContainText(
      "trusted_internal_signed",
    );
  });

  test("Agent Risk Scoreboard: ranks agents, exports CSV, and links to Explore (#1290)", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained: a dedicated agent with 2 decisions, so the
    // decision_count_24h assertion below is exact regardless of what other
    // (possibly parallel) tests are doing to the tenant-wide scoreboard.
    const agentKey = `dashboard-e2e-risk-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);

    await page.goto("/dashboard/");

    // Overview: Top 5 Riskiest Agents renders real content, not stuck on
    // "Loading..." or erroring — which specific 5 agents show up is a
    // tenant-wide ranking shared with parallel tests, so that's all that's
    // safe to assert here.
    await expect(page.locator("#top-risk-agents-container")).not.toContainText(
      "Loading",
      { timeout: 10_000 },
    );

    await page.locator('.menu-item[data-view="risk-scoreboard"]').click();
    const row = page.locator("#risk-scoreboard-tbody tr", { hasText: agentKey });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText("2"); // decision_count_24h
    await expect(row.locator("td", { hasText: /↑|↓|→/ })).toBeVisible();

    // CSV export.
    const downloadPromise = page.waitForEvent("download");
    await page.locator("#export-risk-scoreboard-csv-btn").click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("agent-risk-scoreboard.csv");
    const csvPath = await download.path();
    const csvContent = require("fs").readFileSync(csvPath, "utf-8");
    expect(csvContent.split("\n")[0]).toBe(
      "agent_id,agent_key,current_avg_risk_score,decision_count_24h,trend",
    );
    expect(csvContent).toContain(agentKey);

    // "View in Explore" navigates and filters by this agent's UUID.
    await row.locator(".view-agent-explore-btn").click();
    await expect(page.locator("#view-explore")).toBeVisible();
    await expect(page.locator("#active-filters-container")).toContainText(agent.id);
    await expect(page.locator("#explore-tbody")).toContainText(agent.id, {
      timeout: 10_000,
    });
  });

  test("Explore view executes a search and renders the decisions table", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained: don't rely on another (possibly parallel) test having
    // already produced a decision row — every /v1/authorize call also writes
    // a receipt, so this covers the Integrity Logs test below too.
    const agentKey = `dashboard-e2e-explore-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);

    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="explore"]').click();
    await page.locator("#execute-search-btn").click();
    await expect(page.locator("#search-results-count")).not.toContainText(
      "Showing 0 decisions",
      { timeout: 10_000 },
    );
    await expect(page.locator("#explore-tbody tr.empty-row")).toHaveCount(0);
  });

  test("Integrity Logs view renders the receipt chain with verify actions", async ({
    page,
    request,
    baseURL,
  }) => {
    // Self-contained for the same reason as the Explore test above — every
    // decision (`/v1/authorize` call) emits a receipt (#1326 #1271).
    const agentKey = `dashboard-e2e-receipts-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);

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
