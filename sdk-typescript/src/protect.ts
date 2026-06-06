/**
 * AegisAgent TypeScript SDK — fail-closed protect() wrapper.
 *
 * Intercepts a tool function and enforces the gateway's decision:
 *
 *   allow            → execute the tool function; forward its return value.
 *   deny             → throw AegisDenied; tool NOT called.
 *   require_approval → poll until terminal status, verify action_hash at every
 *                      step (approve-then-swap defence), atomically consume
 *                      the single-use approval (replay defence), THEN execute.
 *   any error path   → throw; tool NOT called (fail closed).
 *
 * Mirrors the Python decorator (sdk-python/aegisagent/decorator.py) and the
 * Go wrapper (sdk-go/aegis/protect.go) in logic and terminology.
 *
 * Canonicalization uses scheme aegis-jcs-1 via src/canon.ts — byte-identical
 * with the gateway and both other SDKs. DO NOT alter canon.ts hashing.
 */
import { AegisClient } from "./client.ts";
import type { AuthorizeRequest } from "./client.ts";
import { canonicalHash } from "./canon.ts";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/** Gateway decision was "deny". The tool was NOT executed. */
export class AegisDenied extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`aegis: action denied by gateway: ${reason}`);
    this.name = "AegisDenied";
    this.reason = reason;
  }
}

/**
 * The approval's bound action_hash does not match the hash of the action the
 * SDK is about to execute. This detects approve-then-swap attacks. The tool
 * was NOT executed.
 */
export class AegisHashMismatch extends Error {
  readonly phase: string;
  readonly got: string;
  readonly expected: string;
  constructor(phase: string, got: string, expected: string) {
    super(
      `aegis: action_hash mismatch at ${phase} phase (got ${got}, expected ${expected}) — failing closed`
    );
    this.name = "AegisHashMismatch";
    this.phase = phase;
    this.got = got;
    this.expected = expected;
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ProtectOptions {
  /**
   * Milliseconds to wait between approval status polls.
   * 0 means no delay (useful in tests).
   * Default: 2000.
   */
  pollIntervalMs?: number;
  /**
   * Maximum number of approval polls before timing out.
   * Default: 150 (≈ 5 minutes at 2-second intervals).
   */
  maxPolls?: number;
}

const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_MAX_POLLS = 150;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Compute the canonical action_hash for req using scheme aegis-jcs-1.
 * The map shape MUST match what the gateway hashes:
 *   { tool, action, resource, mutates_state, parameters }
 * resource is null when absent (JSON null ≡ Python None ≡ Go nil).
 */
function computeActionHash(req: AuthorizeRequest): string {
  return canonicalHash({
    tool: req.tool,
    action: req.action,
    resource: req.resource ?? null,
    mutates_state: req.mutatesState,
    parameters: req.parameters,
  });
}

/**
 * Assert that `got` equals `expected`. Throws AegisHashMismatch when they
 * differ or when `got` is empty (the gateway omitted the field).
 */
function assertHash(phase: string, got: string, expected: string): void {
  if (!got) {
    throw new AegisHashMismatch(phase, "(empty)", expected);
  }
  if (got !== expected) {
    throw new AegisHashMismatch(phase, got, expected);
  }
}

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// protect()
// ---------------------------------------------------------------------------

/**
 * Intercept `toolFn` and enforce the AegisAgent gateway decision for `req`.
 *
 * @param client  Configured AegisClient pointing at the running gateway.
 * @param req     Authorization request describing the tool call.
 * @param toolFn  The actual tool function to run — called only when safe.
 * @param opts    Optional polling tuning (defaults work for production).
 * @returns       The value returned by `toolFn` when execution is permitted.
 * @throws        AegisDenied | AegisHashMismatch | AegisGatewayError | Error
 */
export async function protect<T>(
  client: AegisClient,
  req: AuthorizeRequest,
  toolFn: () => Promise<T>,
  opts?: ProtectOptions
): Promise<T> {
  const pollIntervalMs = opts?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxPolls = opts?.maxPolls ?? DEFAULT_MAX_POLLS;

  // Compute the expected action_hash from the exact action the caller intends
  // to execute. Any deviation in what the gateway approved is caught below.
  const expectedHash = computeActionHash(req);

  // ── 1. Authorize ──────────────────────────────────────────────────────────
  // Network errors and non-2xx responses propagate as-is. The caller (this
  // function) fails closed by NOT calling toolFn.
  let authResp;
  try {
    authResp = await client.authorize(req);
  } catch (err) {
    // Re-throw — toolFn is never called.
    throw err;
  }

  // ── 2. Branch on decision ─────────────────────────────────────────────────
  switch (authResp.decision) {
    case "allow":
      return toolFn();

    case "deny":
      throw new AegisDenied(authResp.reason ?? "no reason provided");

    case "require_approval":
      return handleApproval(client, req, toolFn, authResp, expectedHash, pollIntervalMs, maxPolls);

    default:
      throw new Error(
        `aegis: unexpected gateway decision "${authResp.decision}" — failing closed`
      );
  }
}

// ---------------------------------------------------------------------------
// Approval polling loop
// ---------------------------------------------------------------------------

async function handleApproval<T>(
  client: AegisClient,
  req: AuthorizeRequest,
  toolFn: () => Promise<T>,
  authResp: Awaited<ReturnType<AegisClient["authorize"]>>,
  expectedHash: string,
  pollIntervalMs: number,
  maxPolls: number
): Promise<T> {
  // Approval object must be present — without it we cannot poll or verify.
  if (!authResp.approval) {
    throw new Error(
      "aegis: decision is require_approval but no approval info returned — failing closed"
    );
  }

  const approval = authResp.approval;

  // Verify the gateway bound this approval to the correct action
  // (approve-then-swap defence at the authorize phase).
  assertHash("authorize", approval.actionHash, expectedHash);

  const approvalId = approval.approvalId;

  // ── Poll until terminal status ────────────────────────────────────────────
  for (let i = 0; i < maxPolls; i++) {
    await sleep(pollIntervalMs);

    let status;
    try {
      status = await client.getApproval(approvalId);
    } catch {
      // Transient network error — keep polling (mirrors Python SDK behaviour).
      continue;
    }

    switch (status.status) {
      case "APPROVED": {
        // Verify the approval still refers to the same action (approve-then-swap
        // at the poll phase — the action could have been swapped after authorize).
        assertHash("poll", status.actionHash, expectedHash);

        // Atomically consume the approval before executing (replay defence).
        // A 409 or any error means we must refuse — the approval is already
        // used or expired.
        let consumed: Awaited<ReturnType<AegisClient["consumeApproval"]>>;
        try {
          consumed = await client.consumeApproval(approvalId);
        } catch (err) {
          throw new Error(
            `aegis: approval consume failed (already used / expired) — failing closed: ${err}`
          );
        }

        // Final hash check on the consume response.
        assertHash("consume", consumed.actionHash, expectedHash);

        // All integrity checks passed — execute the tool.
        return toolFn();
      }

      case "REJECTED":
        throw new Error(`aegis: action rejected by reviewer: ${status.reason ?? "no reason"}`);

      case "EXPIRED":
        throw new Error("aegis: approval expired — failing closed");

      case "PENDING":
        // Keep polling.
        break;

      default:
        // Unknown status — keep polling for forward-compatibility.
        break;
    }
  }

  throw new Error(`aegis: approval timed out after ${maxPolls} polls — failing closed`);
}

// AegisGatewayError is re-exported from src/index.ts via "export * from ./client.ts".
