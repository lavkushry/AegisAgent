import { afterEach, describe, expect, it, vi } from "vitest";

import {
  approveApproval,
  buildGatewayHeaders,
  editApproval,
  fetchFromGateway,
  freezeAgent,
  getMcpManifestHistory,
  quarantineMcpServer,
  normalizeMcpManifestHistory,
  rejectApproval,
  restoreMcpServer,
  unfreezeAgent,
  type AuthorizeToolCall,
} from "./api";

const options = {
  gatewayUrl: "http://127.0.0.1:8080",
  bearerToken: "secret-token",
  tenantId: "tenant-a",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("gateway transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("binds authentication and tenant context to every request", () => {
    expect(
      buildGatewayHeaders(
        {
          gatewayUrl: "http://127.0.0.1:8080",
          bearerToken: "secret-token",
          tenantId: "tenant-a",
        },
        true,
      ),
    ).toEqual({
      Accept: "application/json",
      Authorization: "Bearer secret-token",
      "Content-Type": "application/json",
      "X-Aegis-Tenant-ID": "tenant-a",
    });
  });

  it("fails before network access when tenant context is missing", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchFromGateway(
        {
          gatewayUrl: "http://127.0.0.1:8080",
          bearerToken: "secret-token",
          tenantId: "",
        },
        "/v1/stats",
      ),
    ).rejects.toThrow("tenant");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["approve", approveApproval],
    ["reject", rejectApproval],
  ] as const)("sends the gateway snake_case approver payload for %s", async (action, helper) => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ status: "success" }));
    vi.stubGlobal("fetch", fetchMock);

    await helper(options, "approval/id", "reviewer-42", "Reviewed evidence");

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0]).toBe(
      `http://127.0.0.1:8080/v1/approvals/approval%2Fid/${action}`,
    );
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      approver_user_id: "reviewer-42",
      reason: "Reviewed evidence",
    });
  });

  it("edits through the re-hash endpoint with the complete frozen tool call", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ status: "success", effective_action_hash: "new-hash" }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const editedToolCall: AuthorizeToolCall = {
      tool: "github",
      action: "merge_pull_request",
      resource: "repo/example/pull/42",
      mutates_state: true,
      parameters: { base_branch: "release" },
    };

    await editApproval(options, "approval/id", "reviewer-42", editedToolCall, "Safer target");

    expect(fetchMock.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8080/v1/approvals/approval%2Fid/edit",
    );
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      approver_user_id: "reviewer-42",
      edited_tool_call: editedToolCall,
      reason: "Safer target",
    });
  });

  it("normalizes MCP manifest history envelopes from the gateway", () => {
    expect(
      normalizeMcpManifestHistory({
        server_key: "github-mcp",
        snapshots: [{ manifest_hash: "sha256:abc", created_at: "2026-06-29T00:00:00Z" }],
      }),
    ).toEqual([{ manifest_hash: "sha256:abc", created_at: "2026-06-29T00:00:00Z" }]);
    expect(normalizeMcpManifestHistory([{ manifest_hash: "sha256:def" }])).toEqual([
      { manifest_hash: "sha256:def" },
    ]);
    expect(normalizeMcpManifestHistory({ server_key: "missing-snapshots" })).toEqual([]);
  });

  it("fetches encoded MCP manifest history and returns snapshots", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        server_key: "server/key",
        snapshots: [{ manifest_hash: "sha256:abc" }],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(getMcpManifestHistory(options, "server/key")).resolves.toEqual([
      { manifest_hash: "sha256:abc" },
    ]);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8080/v1/mcp/servers/server%2Fkey/manifest-history",
    );
  });

  it("sends freeze reason and encodes active-response path parameters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: "agent/id", status: "frozen" }));
    vi.stubGlobal("fetch", fetchMock);

    await freezeAgent(options, "agent/id", "Suspected compromised token");

    expect(fetchMock.mock.calls[0][0]).toBe("http://127.0.0.1:8080/v1/agents/agent%2Fid/freeze");
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      reason: "Suspected compromised token",
    });
  });

  it("sends unfreeze reason to preserve active-response audit context", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: "agent/id", status: "active" }));
    vi.stubGlobal("fetch", fetchMock);

    await unfreezeAgent(options, "agent/id", "Investigation cleared");

    expect(fetchMock.mock.calls[0][0]).toBe("http://127.0.0.1:8080/v1/agents/agent%2Fid/unfreeze");
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      reason: "Investigation cleared",
    });
  });

  it.each([
    ["quarantine", quarantineMcpServer, "/quarantine"],
    ["restore", restoreMcpServer, "/restore"],
  ] as const)("sends MCP reason and encodes server keys for %s controls", async (_action, helper, suffix) => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ server_key: "server/key" }));
    vi.stubGlobal("fetch", fetchMock);

    await helper(options, "server/key", "Manifest drift response");

    expect(fetchMock.mock.calls[0][0]).toBe(
      `http://127.0.0.1:8080/v1/mcp/servers/server%2Fkey${suffix}`,
    );
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      reason: "Manifest drift response",
    });
  });
});
