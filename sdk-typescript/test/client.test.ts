/**
 * Tests for AegisAgent TypeScript SDK — Client (client.ts)
 *
 * Uses node:test + node:http (no external deps) matching canon.test.ts style.
 * Each test spins up a real loopback HTTP server so no fetch-stubbing is needed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHmac } from "node:crypto";
import { AegisClient, AegisGatewayError } from "../src/client.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Start an HTTP server. Returns base URL and a close function. */
function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => srv.close(),
      });
    });
  });
}

function serveJSON(res: http.ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function newClient(baseUrl: string): AegisClient {
  return new AegisClient({
    baseUrl,
    agentToken: "test-token",
    tenantId: "tenant-test",
  });
}

// ---------------------------------------------------------------------------
// authorize()
// ---------------------------------------------------------------------------

test("AegisClient.authorize — 200 allow returns parsed response", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/authorize");
    assert.equal(req.headers["authorization"], "Bearer test-token");
    assert.equal(req.headers["x-aegis-tenant-id"], "tenant-test");
    serveJSON(res, 200, {
      decision: "allow",
      action_hash: "abc123",
    });
  });

  try {
    const client = newClient(url);
    const resp = await client.authorize({
      tool: "github",
      action: "list_prs",
      mutatesState: false,
      parameters: { repo: "aegis" },
    });
    assert.equal(resp.decision, "allow");
    assert.equal(resp.actionHash, "abc123");
  } finally {
    close();
  }
});

test("AegisClient.authorize — non-200 throws AegisGatewayError", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 403, { error: "forbidden" });
  });

  try {
    const client = newClient(url);
    await assert.rejects(
      () =>
        client.authorize({
          tool: "github",
          action: "force_push",
          mutatesState: true,
          parameters: {},
        }),
      (err: unknown) => {
        assert.ok(err instanceof AegisGatewayError, `expected AegisGatewayError, got ${err}`);
        assert.equal((err as AegisGatewayError).statusCode, 403);
        return true;
      }
    );
  } finally {
    close();
  }
});

test("AegisClient.authorize — network error rejects with Error", async () => {
  const client = new AegisClient({
    baseUrl: "http://127.0.0.1:1", // nothing listening
    agentToken: "tok",
    tenantId: "tid",
    timeoutMs: 500,
  });
  await assert.rejects(() =>
    client.authorize({
      tool: "fs",
      action: "delete",
      mutatesState: true,
      parameters: {},
    })
  );
});

// ---------------------------------------------------------------------------
// getApproval()
// ---------------------------------------------------------------------------

test("AegisClient.getApproval — 200 returns parsed status", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.method, "GET");
    assert.equal(req.url, "/v1/approvals/appr-42");
    serveJSON(res, 200, {
      status: "PENDING",
      action_hash: "deadbeef",
    });
  });

  try {
    const client = newClient(url);
    const status = await client.getApproval("appr-42");
    assert.equal(status.status, "PENDING");
    assert.equal(status.actionHash, "deadbeef");
  } finally {
    close();
  }
});

test("AegisClient.getApproval — non-200 throws AegisGatewayError", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 404, { error: "not found" });
  });

  try {
    const client = newClient(url);
    await assert.rejects(
      () => client.getApproval("missing-id"),
      (err: unknown) => {
        assert.ok(err instanceof AegisGatewayError);
        assert.equal((err as AegisGatewayError).statusCode, 404);
        return true;
      }
    );
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// consumeApproval()
// ---------------------------------------------------------------------------

test("AegisClient.consumeApproval — 200 returns action_hash", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/approvals/appr-99/consume");
    serveJSON(res, 200, { action_hash: "consumed-hash" });
  });

  try {
    const client = newClient(url);
    const result = await client.consumeApproval("appr-99");
    assert.equal(result.actionHash, "consumed-hash");
  } finally {
    close();
  }
});

test("AegisClient.consumeApproval — 409 throws AegisGatewayError", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 409, { error: "already consumed" });
  });

  try {
    const client = newClient(url);
    await assert.rejects(
      () => client.consumeApproval("appr-replay"),
      (err: unknown) => {
        assert.ok(err instanceof AegisGatewayError);
        assert.equal((err as AegisGatewayError).statusCode, 409);
        return true;
      }
    );
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// Request signing (#1403)
// ---------------------------------------------------------------------------

test("AegisClient.authorize — signingKey sends X-Aegis-Request-Signature header", async () => {
  let capturedSig = "";
  const { url, close } = await startServer((req, res) => {
    capturedSig = req.headers["x-aegis-request-signature"] as string ?? "";
    serveJSON(res, 200, { decision: "allow", action_hash: "abc" });
  });

  try {
    const client = new AegisClient({
      baseUrl: url,
      agentToken: "tok",
      tenantId: "tid",
      signingKey: "secret-key",
    });
    await client.authorize({ tool: "github", action: "list_prs", mutatesState: false, parameters: {} });
    assert.ok(capturedSig.startsWith("sha256="), `expected sha256= prefix, got: ${capturedSig}`);
  } finally {
    close();
  }
});

test("AegisClient.authorize — signingKey signature is correct HMAC-SHA256", async () => {
  const signingKey = "my-hmac-key";
  let capturedBody = "";
  let capturedSig = "";

  const { url, close } = await startServer((req, res) => {
    capturedSig = req.headers["x-aegis-request-signature"] as string ?? "";
    req.setEncoding("utf-8");
    const chunks: string[] = [];
    req.on("data", (c: string) => chunks.push(c));
    req.on("end", () => {
      capturedBody = chunks.join("");
      serveJSON(res, 200, { decision: "allow", action_hash: "x" });
    });
  });

  try {
    const client = new AegisClient({ baseUrl: url, agentToken: "tok", tenantId: "tid", signingKey });
    await client.authorize({ tool: "s3", action: "delete", mutatesState: true, parameters: { bucket: "prod" } });

    const expected = "sha256=" + createHmac("sha256", signingKey).update(capturedBody).digest("hex");
    assert.equal(capturedSig, expected);
  } finally {
    close();
  }
});

test("AegisClient.authorize — no signingKey sends no signature header", async () => {
  let capturedSig: string | undefined;
  const { url, close } = await startServer((req, res) => {
    capturedSig = req.headers["x-aegis-request-signature"] as string | undefined;
    serveJSON(res, 200, { decision: "allow", action_hash: "y" });
  });

  try {
    const client = newClient(url);
    await client.authorize({ tool: "github", action: "list_prs", mutatesState: false, parameters: {} });
    assert.equal(capturedSig, undefined);
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// approve() / reject() (#1182)
// ---------------------------------------------------------------------------

test("AegisClient.approve — 200 returns parsed decision response", async () => {
  let capturedBody = "";
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/approvals/appr-1/approve");
    req.setEncoding("utf-8");
    const chunks: string[] = [];
    req.on("data", (c: string) => chunks.push(c));
    req.on("end", () => {
      capturedBody = chunks.join("");
      serveJSON(res, 200, { status: "success", approval_id: "appr-1" });
    });
  });

  try {
    const client = newClient(url);
    const result = await client.approve("appr-1", "user-42", "looks safe");
    assert.equal(result.status, "success");
    assert.equal(result.approvalId, "appr-1");
    assert.deepEqual(JSON.parse(capturedBody), {
      approver_user_id: "user-42",
      reason: "looks safe",
    });
  } finally {
    close();
  }
});

test("AegisClient.approve — non-200 throws AegisGatewayError", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 409, { error: "Approval already decided" });
  });

  try {
    const client = newClient(url);
    await assert.rejects(
      () => client.approve("appr-decided", "user-1"),
      (err: unknown) => {
        assert.ok(err instanceof AegisGatewayError);
        assert.equal((err as AegisGatewayError).statusCode, 409);
        return true;
      }
    );
  } finally {
    close();
  }
});

test("AegisClient.reject — 200 returns parsed decision response", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/approvals/appr-2/reject");
    serveJSON(res, 200, { status: "success", approval_id: "appr-2" });
  });

  try {
    const client = newClient(url);
    const result = await client.reject("appr-2", "user-7");
    assert.equal(result.status, "success");
    assert.equal(result.approvalId, "appr-2");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// listAlerts() / listIncidents() / getSocSummary() (#1182)
// ---------------------------------------------------------------------------

test("AegisClient.listAlerts — 200 returns parsed alerts with query params", async () => {
  let capturedUrl = "";
  const { url, close } = await startServer((req, res) => {
    capturedUrl = req.url ?? "";
    serveJSON(res, 200, [
      {
        id: "alert-1",
        tenant_id: "tenant-test",
        rule: "deny_storm",
        severity: "high",
        agent_id: "agent-1",
        source_event_id: "evt-1",
        summary: "5 denies in 60s",
        created_at: "2026-01-01T00:00:00Z",
      },
    ]);
  });

  try {
    const client = newClient(url);
    const alerts = await client.listAlerts({ severity: "high", agentId: "agent-1" });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].id, "alert-1");
    assert.equal(alerts[0].agentId, "agent-1");
    assert.equal(alerts[0].sourceEventId, "evt-1");
    assert.ok(capturedUrl.includes("severity=high"));
    assert.ok(capturedUrl.includes("agent_id=agent-1"));
  } finally {
    close();
  }
});

test("AegisClient.listIncidents — 200 returns parsed incidents", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.url, "/v1/incidents");
    serveJSON(res, 200, [
      {
        id: "inc-1",
        tenant_id: "tenant-test",
        kind: "runaway",
        severity: "high",
        agent_id: "agent-1",
        summary: "20 calls in 10s",
        source_event_ids: "[]",
        opened_at: "2026-01-01T00:00:00Z",
        status: "open",
        closed_at: null,
      },
    ]);
  });

  try {
    const client = newClient(url);
    const incidents = await client.listIncidents();
    assert.equal(incidents.length, 1);
    assert.equal(incidents[0].kind, "runaway");
    assert.equal(incidents[0].openedAt, "2026-01-01T00:00:00Z");
    assert.equal(incidents[0].closedAt, undefined);
  } finally {
    close();
  }
});

test("AegisClient.getSocSummary — 200 returns parsed summary", async () => {
  const { url, close } = await startServer((req, res) => {
    assert.equal(req.url, "/v1/soc/summary");
    serveJSON(res, 200, {
      alerts_total: 10,
      alerts_high: 3,
      incidents_total: 2,
      incidents_open: 1,
      incidents_closed: 1,
    });
  });

  try {
    const client = newClient(url);
    const summary = await client.getSocSummary();
    assert.equal(summary.alertsTotal, 10);
    assert.equal(summary.alertsHigh, 3);
    assert.equal(summary.incidentsOpen, 1);
  } finally {
    close();
  }
});
