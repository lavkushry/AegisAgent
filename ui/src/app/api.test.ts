import { afterEach, describe, expect, it, vi } from "vitest";

import {
  approveApproval,
  buildGatewayHeaders,
  editApproval,
  fetchFromGateway,
  rejectApproval,
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
});
