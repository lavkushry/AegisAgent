import type { APIRequestContext } from "@playwright/test";

export const TENANT_ID = "tenant_123";

export interface TestAgent {
  /** The agent's gateway-assigned UUID — this is what `approvals.agent_id` renders in the UI. */
  id: string;
  agentToken: string;
}

/**
 * Registers (or re-registers) a dedicated E2E test agent. Re-registering an
 * existing `agent_key` rotates the token server-side and returns the new
 * one, so this is safe to call on every run.
 */
export async function registerTestAgent(
  request: APIRequestContext,
  baseURL: string,
  agentKey: string,
): Promise<TestAgent> {
  const resp = await request.post(`${baseURL}/v1/agents/register`, {
    headers: {
      Authorization: `Bearer ${TENANT_ID}`,
      "Content-Type": "application/json",
    },
    data: {
      agent_key: agentKey,
      name: "Dashboard E2E Test Agent",
      owner_team: "platform",
      environment: "production",
      framework: "playwright",
      model_provider: "mock",
      model_name: "mock-agent",
      risk_tier: "medium",
      purpose: "Dashboard E2E test fixture (#1326)",
    },
  });
  if (!resp.ok()) {
    throw new Error(`Failed to register test agent: HTTP ${resp.status()}`);
  }
  const body = await resp.json();
  return { id: body.id as string, agentToken: body.agent_token as string };
}

/**
 * Triggers a `merge_pull_request` call under `semi_trusted_customer` trust,
 * which the default Cedar policy pack routes to `require_approval` — giving
 * tests a real pending approval row to exercise the Approvals queue against.
 * Requires `github`/`merge_pull_request` to already be a registered tool
 * action (seeded by scripts/seed-demo.sh).
 */
export async function createPendingApproval(
  request: APIRequestContext,
  baseURL: string,
  agentToken: string,
  agentKey: string,
): Promise<void> {
  const resp = await request.post(`${baseURL}/v1/authorize`, {
    headers: {
      Authorization: `Bearer ${agentToken}`,
      "X-Aegis-Tenant-ID": TENANT_ID,
      "Content-Type": "application/json",
    },
    data: {
      agent: { id: agentKey, environment: "production" },
      tool_call: {
        tool: "github",
        action: "merge_pull_request",
        resource: "octocat/demo-repo#42",
        mutates_state: true,
        parameters: { base_branch: "main" },
      },
      context: {
        source_trust: "semi_trusted_customer",
        contains_sensitive_data: false,
      },
    },
  });
  if (!resp.ok()) {
    throw new Error(`Failed to seed pending approval: HTTP ${resp.status()}`);
  }
  const body = await resp.json();
  if (body.decision !== "require_approval") {
    throw new Error(
      `Expected require_approval, got decision=${body.decision}`,
    );
  }
}

/**
 * Triggers a non-mutating `read_issue` call, which the default Cedar policy
 * pack always allows regardless of trust level — guarantees at least one row
 * lands in `decisions` (and thus `total_decisions` >= 1 in `/v1/stats`)
 * without depending on any other test having already run. Requires
 * `github`/`read_issue` to already be a registered tool action (seeded by
 * scripts/seed-demo.sh).
 */
export async function createAllowedDecision(
  request: APIRequestContext,
  baseURL: string,
  agentToken: string,
  agentKey: string,
): Promise<void> {
  const resp = await request.post(`${baseURL}/v1/authorize`, {
    headers: {
      Authorization: `Bearer ${agentToken}`,
      "X-Aegis-Tenant-ID": TENANT_ID,
      "Content-Type": "application/json",
    },
    data: {
      agent: { id: agentKey, environment: "production" },
      tool_call: {
        tool: "github",
        action: "read_issue",
        resource: "octocat/demo-repo#1",
        mutates_state: false,
        parameters: {},
      },
      context: {
        source_trust: "trusted_internal_signed",
        contains_sensitive_data: false,
      },
    },
  });
  if (!resp.ok()) {
    throw new Error(`Failed to seed an allowed decision: HTTP ${resp.status()}`);
  }
}

/**
 * Registers a dedicated E2E test MCP server and runs one discovery call
 * (one tool, `pending` status), so the #1334 MCP server detail view test is
 * self-contained — it doesn't depend on or mutate the shared
 * `github-mcp-demo` server seeded by scripts/seed-demo.sh, which other
 * (possibly parallel) tests also read.
 */
export async function registerTestMcpServer(
  request: APIRequestContext,
  baseURL: string,
  serverKey: string,
): Promise<void> {
  const registerResp = await request.post(`${baseURL}/v1/mcp/servers`, {
    headers: {
      Authorization: `Bearer ${TENANT_ID}`,
      "X-Aegis-Tenant-ID": TENANT_ID,
      "Content-Type": "application/json",
    },
    data: {
      server_key: serverKey,
      name: "Dashboard E2E Test MCP Server",
      owner_team: "platform",
      transport: "http",
      source: "playwright-e2e",
      trust_level: "trusted_internal_signed",
      endpoint: "http://127.0.0.1:9001/mcp",
    },
  });
  if (!registerResp.ok()) {
    throw new Error(`Failed to register test MCP server: HTTP ${registerResp.status()}`);
  }

  const discoverResp = await request.post(
    `${baseURL}/v1/mcp/servers/${serverKey}/tools`,
    {
      headers: {
        Authorization: `Bearer ${TENANT_ID}`,
        "X-Aegis-Tenant-ID": TENANT_ID,
        "Content-Type": "application/json",
      },
      data: {
        tools: [
          {
            tool_key: "create_issue",
            name: "Create issue",
            description: "Create a GitHub issue through MCP",
            input_schema: { type: "object" },
            risk: "medium",
            mutates_state: true,
            approval_required: false,
          },
        ],
      },
    },
  );
  if (!discoverResp.ok()) {
    throw new Error(`Failed to discover tools for test MCP server: HTTP ${discoverResp.status()}`);
  }
}
