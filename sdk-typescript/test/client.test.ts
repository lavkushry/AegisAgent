/**
 * Tests for AegisAgent TypeScript SDK — Client (client.ts)
 *
 * Uses node:test + node:http (no external deps) matching canon.test.ts style.
 * Each test spins up a real loopback HTTP server so no fetch-stubbing is needed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
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
