/**
 * Tests for AegisAgent TypeScript SDK — protect() (protect.ts)
 *
 * Uses node:test + node:http (no external deps) matching canon.test.ts style.
 * Mock gateway is a real loopback HTTP server so routing logic is exercised.
 *
 * Coverage:
 *   1. allow  → tool executes
 *   2. deny   → AegisDenied thrown, tool NOT run
 *   3. require_approval: pending→approved → poll, verify hash, consume, execute
 *   4. hash mismatch on authorize response → AegisHashMismatch, tool NOT run
 *   5. hash mismatch on poll status → AegisHashMismatch, tool NOT run
 *   6. consume fails 409 → error, tool NOT run
 *   7. gateway unreachable on mutating action → error, tool NOT run
 *   8. unknown decision → error (fail closed), tool NOT run
 *   9. approval rejected → error, tool NOT run
 *  10. missing approval info in require_approval → error (fail closed)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AegisClient } from "../src/client.ts";
import { protect, AegisDenied, AegisHashMismatch } from "../src/protect.ts";
import type { ProtectOptions } from "../src/protect.ts";
import { canonicalHash } from "../src/canon.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ServerHandle {
  url: string;
  close: () => void;
}

function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<ServerHandle> {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => srv.close() });
    });
  });
}

function serveJSON(res: http.ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function newClient(baseUrl: string): AegisClient {
  return new AegisClient({ baseUrl, agentToken: "tok", tenantId: "tid" });
}

/** Compute the action_hash the same way protect() does, for use in mock responses. */
function hashAction(
  tool: string,
  action: string,
  mutatesState: boolean,
  parameters: Record<string, unknown>,
  resource?: string
): string {
  return canonicalHash({
    tool,
    action,
    resource: resource ?? null,
    mutates_state: mutatesState,
    parameters,
  });
}

// Polling options with zero delay so tests run fast.
const fastOpts: ProtectOptions = { pollIntervalMs: 0, maxPolls: 5 };

// ---------------------------------------------------------------------------
// 1. allow → tool executes
// ---------------------------------------------------------------------------

test("protect — allow: tool is executed and return value forwarded", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 200, { decision: "allow", action_hash: "any" });
  });
  try {
    const client = newClient(url);
    let called = false;
    const result = await protect(
      client,
      { tool: "github", action: "list_prs", mutatesState: false, parameters: { repo: "x" } },
      async () => {
        called = true;
        return "ok";
      },
      fastOpts
    );
    assert.ok(called, "tool must be called on allow");
    assert.equal(result, "ok");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 2. deny → AegisDenied thrown, tool NOT run
// ---------------------------------------------------------------------------

test("protect — deny: throws AegisDenied, tool NOT executed", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 200, { decision: "deny", reason: "forbidden by policy" });
  });
  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool: "github", action: "force_push", mutatesState: true, parameters: { branch: "main" } },
          async () => {
            called = true;
            return "should not run";
          },
          fastOpts
        ),
      (err: unknown) => {
        assert.ok(err instanceof AegisDenied, `expected AegisDenied, got ${err}`);
        return true;
      }
    );
    assert.ok(!called, "tool must NOT be called on deny");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 3. require_approval: pending→approved → executes after consume
// ---------------------------------------------------------------------------

test("protect — approval: pending→approved polls, verifies hash, consumes, executes", async () => {
  const tool = "github";
  const action = "merge_pr";
  const params = { pr: 42 };
  const mutates = true;
  const approvalId = "appr-poll-001";
  const actionHash = hashAction(tool, action, mutates, params);

  let pollCount = 0;

  const { url, close } = await startServer((req, res) => {
    if (req.method === "POST" && req.url === "/v1/authorize") {
      serveJSON(res, 200, {
        decision: "require_approval",
        action_hash: actionHash,
        approval: { approval_id: approvalId, action_hash: actionHash },
      });
    } else if (req.method === "GET" && req.url === `/v1/approvals/${approvalId}`) {
      pollCount++;
      if (pollCount < 2) {
        serveJSON(res, 200, { status: "PENDING", action_hash: actionHash });
      } else {
        serveJSON(res, 200, { status: "APPROVED", action_hash: actionHash });
      }
    } else if (req.method === "POST" && req.url === `/v1/approvals/${approvalId}/consume`) {
      serveJSON(res, 200, { action_hash: actionHash });
    } else {
      res.writeHead(404);
      res.end("unexpected");
    }
  });

  try {
    const client = newClient(url);
    let called = false;
    await protect(
      client,
      { tool, action, mutatesState: mutates, parameters: params },
      async () => {
        called = true;
        return "done";
      },
      fastOpts
    );
    assert.ok(called, "tool must be called after approval");
    assert.ok(pollCount >= 2, "must have polled at least twice (pending then approved)");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 4. hash mismatch on authorize approval info → AegisHashMismatch, tool NOT run
// ---------------------------------------------------------------------------

test("protect — hash mismatch on authorize: throws AegisHashMismatch, tool NOT run", async () => {
  const badHash = "0".repeat(64);
  const approvalId = "appr-mismatch-001";

  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 200, {
      decision: "require_approval",
      action_hash: badHash,
      approval: { approval_id: approvalId, action_hash: badHash }, // wrong hash
    });
  });

  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool: "github", action: "delete_branch", mutatesState: true, parameters: { branch: "x" } },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        ),
      (err: unknown) => {
        assert.ok(err instanceof AegisHashMismatch, `expected AegisHashMismatch, got ${err}`);
        return true;
      }
    );
    assert.ok(!called, "tool must NOT be called on hash mismatch");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 5. hash mismatch on poll status (approve-then-swap attack) → refuse
// ---------------------------------------------------------------------------

test("protect — hash mismatch on poll APPROVED status: throws AegisHashMismatch, tool NOT run", async () => {
  const tool = "github";
  const action = "deploy";
  const params = { env: "prod" };
  const mutates = true;
  const approvalId = "appr-pollmismatch";
  const correctHash = hashAction(tool, action, mutates, params);
  const tamperedHash = "a".repeat(64);

  const { url, close } = await startServer((req, res) => {
    if (req.method === "POST" && req.url === "/v1/authorize") {
      serveJSON(res, 200, {
        decision: "require_approval",
        action_hash: correctHash,
        approval: { approval_id: approvalId, action_hash: correctHash },
      });
    } else if (req.method === "GET" && req.url === `/v1/approvals/${approvalId}`) {
      // Simulate approve-then-swap: gateway returns APPROVED with tampered hash
      serveJSON(res, 200, { status: "APPROVED", action_hash: tamperedHash });
    } else {
      res.writeHead(404);
      res.end("unexpected");
    }
  });

  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool, action, mutatesState: mutates, parameters: params },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        ),
      (err: unknown) => {
        assert.ok(err instanceof AegisHashMismatch, `expected AegisHashMismatch, got ${err}`);
        return true;
      }
    );
    assert.ok(!called, "tool must NOT be called when poll action_hash mismatches");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 6. consume fails 409 → error, tool NOT run (replay defence)
// ---------------------------------------------------------------------------

test("protect — consume 409: refuses and does NOT execute tool", async () => {
  const tool = "github";
  const action = "push";
  const params = { branch: "main" };
  const mutates = true;
  const approvalId = "appr-replay-001";
  const actionHash = hashAction(tool, action, mutates, params);

  const { url, close } = await startServer((req, res) => {
    if (req.method === "POST" && req.url === "/v1/authorize") {
      serveJSON(res, 200, {
        decision: "require_approval",
        action_hash: actionHash,
        approval: { approval_id: approvalId, action_hash: actionHash },
      });
    } else if (req.method === "GET" && req.url === `/v1/approvals/${approvalId}`) {
      serveJSON(res, 200, { status: "APPROVED", action_hash: actionHash });
    } else if (req.method === "POST" && req.url === `/v1/approvals/${approvalId}/consume`) {
      serveJSON(res, 409, { error: "already consumed" });
    } else {
      res.writeHead(404);
      res.end("unexpected");
    }
  });

  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool, action, mutatesState: mutates, parameters: params },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        )
    );
    assert.ok(!called, "tool must NOT be called when consume fails (409)");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 7. gateway unreachable on mutating action → error, tool NOT run
// ---------------------------------------------------------------------------

test("protect — unreachable gateway on mutating action: refuses and does NOT execute tool", async () => {
  const client = new AegisClient({
    baseUrl: "http://127.0.0.1:1", // nothing listening
    agentToken: "tok",
    tenantId: "tid",
    timeoutMs: 500,
  });
  let called = false;
  await assert.rejects(
    () =>
      protect(
        client,
        { tool: "fs", action: "delete_file", mutatesState: true, parameters: { path: "/etc/passwd" } },
        async () => {
          called = true;
          return "";
        },
        fastOpts
      )
  );
  assert.ok(!called, "tool must NOT be called when gateway is unreachable");
});

// ---------------------------------------------------------------------------
// 8. unknown decision → error (fail closed), tool NOT run
// ---------------------------------------------------------------------------

test("protect — unknown decision: fails closed, tool NOT run", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 200, { decision: "maybe" });
  });
  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool: "github", action: "list_prs", mutatesState: false, parameters: {} },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        )
    );
    assert.ok(!called, "tool must NOT be called on unknown decision");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 9. approval rejected → error, tool NOT run
// ---------------------------------------------------------------------------

test("protect — approval rejected: throws error, tool NOT run", async () => {
  const tool = "github";
  const action = "close_issue";
  const params = { issue: 99 };
  const mutates = true;
  const approvalId = "appr-rejected-001";
  const actionHash = hashAction(tool, action, mutates, params);

  const { url, close } = await startServer((req, res) => {
    if (req.method === "POST" && req.url === "/v1/authorize") {
      serveJSON(res, 200, {
        decision: "require_approval",
        action_hash: actionHash,
        approval: { approval_id: approvalId, action_hash: actionHash },
      });
    } else if (req.method === "GET" && req.url === `/v1/approvals/${approvalId}`) {
      serveJSON(res, 200, { status: "REJECTED", action_hash: actionHash, reason: "reviewer declined" });
    } else {
      res.writeHead(404);
      res.end("unexpected");
    }
  });

  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool, action, mutatesState: mutates, parameters: params },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        )
    );
    assert.ok(!called, "tool must NOT be called when approval is rejected");
  } finally {
    close();
  }
});

// ---------------------------------------------------------------------------
// 10. missing approval info in require_approval → fail closed
// ---------------------------------------------------------------------------

test("protect — require_approval without approval info: fails closed, tool NOT run", async () => {
  const { url, close } = await startServer((_req, res) => {
    serveJSON(res, 200, { decision: "require_approval" }); // no approval object
  });
  try {
    const client = newClient(url);
    let called = false;
    await assert.rejects(
      () =>
        protect(
          client,
          { tool: "github", action: "merge_pr", mutatesState: true, parameters: { pr: 7 } },
          async () => {
            called = true;
            return "";
          },
          fastOpts
        )
    );
    assert.ok(!called, "tool must NOT be called when approval info is missing");
  } finally {
    close();
  }
});
