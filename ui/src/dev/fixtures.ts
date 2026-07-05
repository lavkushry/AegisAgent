import { objectToSingleRowFrame, rowsToFrame } from "@/datasources/frame";
import type { DataFrame } from "@/datasources/types";

/** Synthetic tenant and operator identifiers — never real customer data. */
export const SYNTHETIC_TENANT = "tenant_harness_demo";
export const SYNTHETIC_OPERATOR = "operator_harness";

const ACTION_HASH = "sha256:a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef";
const RECEIPT_HASH_1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const RECEIPT_HASH_2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const BROKEN_RECEIPT_HASH = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

export const syntheticApproval = {
  id: "approval-harness-1",
  status: "pending",
  agent_id: "agent-harness-a",
  source_trust: "semi_trusted_customer",
  action_hash: ACTION_HASH,
  original_action_hash: ACTION_HASH,
  effective_action_hash: ACTION_HASH,
  expires_at: "2099-01-01T00:00:00Z",
  tool_call: {
    tool: "github",
    action: "merge_pr",
    parameters: { repo: "acme/widgets", pr: 42, branch: "main" },
  },
};

export const syntheticEditedApproval = {
  ...syntheticApproval,
  id: "approval-harness-edited",
  is_edited: true,
  edited_action_hash: "sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
  effective_action_hash: "sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
  edited_tool_call: {
    tool: "github",
    action: "merge_pr",
    parameters: { repo: "acme/widgets", pr: 42, branch: "feature/harness" },
  },
};

export const syntheticReceiptRows = [
  {
    id: "receipt-harness-1",
    ts: "2026-06-28T10:00:00Z",
    agent_id: "agent-harness-a",
    decision: "allow",
    source_trust: "trusted_internal_signed",
    action_hash: ACTION_HASH,
    prev_receipt_hash: "",
    receipt_hash: RECEIPT_HASH_1,
  },
  {
    id: "receipt-harness-2",
    ts: "2026-06-28T11:00:00Z",
    agent_id: "agent-harness-a",
    decision: "require_approval",
    source_trust: "semi_trusted_customer",
    action_hash: ACTION_HASH,
    prev_receipt_hash: RECEIPT_HASH_1,
    receipt_hash: RECEIPT_HASH_2,
  },
];

export const syntheticBrokenReceiptRows = [
  {
    ...syntheticReceiptRows[0],
    id: "receipt-harness-broken",
    prev_receipt_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    receipt_hash: BROKEN_RECEIPT_HASH,
  },
];

export const syntheticTimelineEvents = [
  {
    id: "decision-harness-1",
    timestamp: "2026-06-28T10:00:00Z",
    tool: "github.create_issue",
    agent_id: "agent-harness-a",
    decision: "allow",
    receipt_hash: RECEIPT_HASH_1,
    prev_receipt_hash: "",
  },
  {
    id: "decision-harness-2",
    timestamp: "2026-06-28T11:00:00Z",
    tool: "github.merge_pr",
    agent_id: "agent-harness-a",
    decision: "deny",
    receipt_hash: RECEIPT_HASH_2,
    prev_receipt_hash: RECEIPT_HASH_1,
  },
];

export const syntheticTableRows = [
  {
    id: "decision-harness-1",
    agent_id: "agent-harness-a",
    tool: "github",
    action: "merge_pr",
    decision: "require_approval",
    action_hash: ACTION_HASH,
    receipt_hash: RECEIPT_HASH_2,
    created_at: "2026-06-28T11:00:00Z",
  },
  {
    id: "decision-harness-2",
    agent_id: "agent-harness-b",
    tool: "slack",
    action: "post_message",
    decision: "deny",
    action_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    receipt_hash: BROKEN_RECEIPT_HASH,
    created_at: "2026-06-28T12:00:00Z",
  },
];

export const syntheticTimeSeriesFrame = rowsToFrame([
  { bucket: "2026-06-28 10:00:00", count: 12 },
  { bucket: "2026-06-28 11:00:00", count: 8 },
  { bucket: "2026-06-28 12:00:00", count: 21 },
  { bucket: "2026-06-28 13:00:00", count: 5 },
]);

export const syntheticStatFrame = objectToSingleRowFrame({
  total_decisions: 128,
  approvals_pending: 3,
  receipt_verify_state: "verified",
});

export const syntheticUnknownStatFrame = objectToSingleRowFrame({
  total_decisions: null,
  receipt_verify_state: "unknown",
});

export const syntheticRedactedPayload = {
  agent_id: "agent-harness-a",
  tool: "github",
  action: "merge_pr",
  api_token: "sk-harness-redacted-not-real",
  parameters: {
    repo: "acme/widgets",
    authorization: "Bearer not-a-real-token",
  },
};

export const emptyFrame: DataFrame = { fields: [], length: 0, meta: { total: 0 } };

/** Visual stale/disconnected states are driven by harness scenario metadata, not frame meta. */
export function staleMetaFrame(frame: DataFrame): DataFrame {
  return frame;
}