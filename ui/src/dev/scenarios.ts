import { objectToSingleRowFrame, rowsToFrame } from "@/datasources/frame";
import type { DataFrame } from "@/datasources/types";
import type { PanelDefinition } from "@/panels/types";
import {
  emptyFrame,
  syntheticApproval,
  syntheticBrokenReceiptRows,
  syntheticEditedApproval,
  syntheticReceiptRows,
  syntheticRedactedPayload,
  syntheticStatFrame,
  syntheticTableRows,
  syntheticTimeSeriesFrame,
  syntheticTimelineEvents,
  syntheticUnknownStatFrame,
  staleMetaFrame,
} from "./fixtures";

export type HarnessState =
  | "success"
  | "loading"
  | "empty"
  | "stale"
  | "error"
  | "tampered"
  | "broken-row"
  | "unknown-verification"
  | "disconnected-stream"
  | "rbac-disabled"
  | "redacted";

export type HarnessTarget =
  | "stat"
  | "table"
  | "timeseries"
  | "approval-card"
  | "provable-timeline"
  | "receipt-integrity"
  | "severity-badge"
  | "hash-text"
  | "hash-chip"
  | "json-viewer"
  | "confirm-dialog";

export interface HarnessScenario {
  readonly id: string;
  readonly target: HarnessTarget;
  readonly state: HarnessState;
  readonly label: string;
  readonly description: string;
  readonly role?: "viewer" | "analyst" | "approver" | "admin";
  readonly frame?: DataFrame;
  readonly definition?: PanelDefinition;
  readonly primitiveProps?: Record<string, unknown>;
}

const TIME_RANGE = { from: "now-24h", to: "now" } as const;

export const HARNESS_TIME_RANGE = TIME_RANGE;

export const HARNESS_SCENARIOS: ReadonlyArray<HarnessScenario> = [
  {
    id: "stat-success",
    target: "stat",
    state: "success",
    label: "Stat · success",
    description: "Numeric counter with threshold-safe presentation.",
    frame: syntheticStatFrame,
    definition: {
      id: "harness-stat",
      type: "stat",
      title: "Protected actions",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions", thresholds: [50, 100] },
    },
  },
  {
    id: "stat-empty",
    target: "stat",
    state: "empty",
    label: "Stat · empty",
    description: "Missing numeric field renders an em dash, not zero.",
    frame: objectToSingleRowFrame({}),
    definition: {
      id: "harness-stat-empty",
      type: "stat",
      title: "Protected actions",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions" },
    },
  },
  {
    id: "stat-unknown",
    target: "stat",
    state: "unknown-verification",
    label: "Stat · unknown verification",
    description: "Unknown receipt verification must not read as healthy.",
    frame: syntheticUnknownStatFrame,
    definition: {
      id: "harness-stat-unknown",
      type: "stat",
      title: "Receipt verify state",
      datasourceId: "gateway-entity",
      options: { valueField: "receipt_verify_state" },
    },
  },
  {
    id: "table-success",
    target: "table",
    state: "success",
    label: "Table · success",
    description: "Decision rows with typed hash chips.",
    frame: rowsToFrame(syntheticTableRows),
    definition: {
      id: "harness-table",
      type: "table",
      title: "Recent decisions",
      datasourceId: "gateway-entity",
      entity: "decision",
      options: { pageSize: 10 },
    },
  },
  {
    id: "table-broken-row",
    target: "table",
    state: "broken-row",
    label: "Table · broken row",
    description: "Tampered receipt hash remains visible and typed.",
    frame: rowsToFrame(syntheticTableRows.slice(1)),
    definition: {
      id: "harness-table-broken",
      type: "table",
      title: "Broken chain row",
      datasourceId: "gateway-entity",
      entity: "decision",
    },
  },
  {
    id: "table-empty",
    target: "table",
    state: "empty",
    label: "Table · empty",
    description: "Zero-length frame shows empty table chrome.",
    frame: emptyFrame,
    definition: {
      id: "harness-table-empty",
      type: "table",
      title: "No decisions",
      datasourceId: "gateway-entity",
      entity: "decision",
    },
  },
  {
    id: "timeseries-success",
    target: "timeseries",
    state: "success",
    label: "Time series · success",
    description: "Bucketed authorize counts over time.",
    frame: syntheticTimeSeriesFrame,
    definition: {
      id: "harness-timeseries",
      type: "timeseries",
      title: "Authorize volume",
      datasourceId: "gateway-entity",
      aggregate: "count_over_time",
      options: { timeField: "bucket", valueField: "count" },
    },
  },
  {
    id: "timeseries-empty",
    target: "timeseries",
    state: "empty",
    label: "Time series · empty",
    description: "No buckets yields an empty chart area.",
    frame: emptyFrame,
    definition: {
      id: "harness-timeseries-empty",
      type: "timeseries",
      title: "Authorize volume",
      datasourceId: "gateway-entity",
      options: { timeField: "bucket", valueField: "count" },
    },
  },
  {
    id: "approval-success",
    target: "approval-card",
    state: "success",
    label: "Approval card · pending",
    description: "Frozen canonical action with hash binding.",
    role: "approver",
    frame: rowsToFrame([syntheticApproval]),
    definition: {
      id: "harness-approval",
      type: "approval-card",
      title: "Approval queue",
      datasourceId: "gateway-entity",
      entity: "approval",
    },
  },
  {
    id: "approval-rbac-disabled",
    target: "approval-card",
    state: "rbac-disabled",
    label: "Approval card · RBAC disabled",
    description: "Viewer role disables approve/reject with reason text.",
    role: "viewer",
    frame: rowsToFrame([syntheticApproval]),
    definition: {
      id: "harness-approval-rbac",
      type: "approval-card",
      title: "Approval queue",
      datasourceId: "gateway-entity",
      entity: "approval",
    },
  },
  {
    id: "approval-tampered",
    target: "approval-card",
    state: "tampered",
    label: "Approval card · edited hash",
    description: "Edited approval shows both original and effective hashes.",
    role: "approver",
    frame: rowsToFrame([syntheticEditedApproval]),
    definition: {
      id: "harness-approval-tampered",
      type: "approval-card",
      title: "Edited approval",
      datasourceId: "gateway-entity",
      entity: "approval",
    },
  },
  {
    id: "timeline-success",
    target: "provable-timeline",
    state: "success",
    label: "Provable timeline · linked chain",
    description: "Ordered events with genesis and receipt linkage.",
    frame: rowsToFrame(syntheticTimelineEvents),
    definition: {
      id: "harness-timeline",
      type: "provable-timeline",
      title: "Decision timeline",
      datasourceId: "gateway-entity",
      entity: "decision",
      options: {
        labelField: "tool",
        timeField: "timestamp",
        receiptHashField: "receipt_hash",
        prevHashField: "prev_receipt_hash",
      },
    },
  },
  {
    id: "timeline-unknown",
    target: "provable-timeline",
    state: "unknown-verification",
    label: "Provable timeline · unverified",
    description: "Chain not yet verified — warning, never green success.",
    frame: rowsToFrame(syntheticTimelineEvents),
    definition: {
      id: "harness-timeline-unknown",
      type: "provable-timeline",
      title: "Decision timeline",
      datasourceId: "gateway-entity",
      entity: "decision",
      options: {
        labelField: "tool",
        timeField: "timestamp",
        receiptHashField: "receipt_hash",
        prevHashField: "prev_receipt_hash",
      },
    },
  },
  {
    id: "receipt-success",
    target: "receipt-integrity",
    state: "success",
    label: "Receipt integrity · chain rows",
    description: "Per-tenant hash chain with verify controls.",
    frame: { ...rowsToFrame(syntheticReceiptRows), meta: { cursor: "cursor-harness", total: 2 } },
    definition: {
      id: "harness-receipt",
      type: "receipt-integrity",
      title: "Receipt chain",
      datasourceId: "receipt",
      entity: "receipt",
      limit: 50,
    },
  },
  {
    id: "receipt-broken",
    target: "receipt-integrity",
    state: "broken-row",
    label: "Receipt integrity · broken link",
    description: "Broken prev hash must not present as verified.",
    frame: { ...rowsToFrame(syntheticBrokenReceiptRows), meta: { total: 1 } },
    definition: {
      id: "harness-receipt-broken",
      type: "receipt-integrity",
      title: "Broken receipt chain",
      datasourceId: "receipt",
      entity: "receipt",
      limit: 50,
    },
  },
  {
    id: "receipt-stale",
    target: "receipt-integrity",
    state: "stale",
    label: "Receipt integrity · stale snapshot",
    description: "Stale metadata banner for aged fixture data.",
    frame: staleMetaFrame(rowsToFrame(syntheticReceiptRows)),
    definition: {
      id: "harness-receipt-stale",
      type: "receipt-integrity",
      title: "Stale receipt snapshot",
      datasourceId: "receipt",
      entity: "receipt",
      limit: 50,
    },
  },
  {
    id: "severity-high",
    target: "severity-badge",
    state: "success",
    label: "Severity badge · high",
    description: "High severity uses critical tint, not success green.",
    primitiveProps: { severity: "high" },
  },
  {
    id: "severity-unknown",
    target: "severity-badge",
    state: "unknown-verification",
    label: "Severity badge · unknown",
    description: "Unknown severity falls back to neutral slate styling.",
    primitiveProps: { severity: "unknown" },
  },
  {
    id: "hash-text-success",
    target: "hash-text",
    state: "success",
    label: "Hash text · typed hash",
    description: "Monospace truncated hash with copy affordance.",
    primitiveProps: {
      value: "sha256:a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef",
    },
  },
  {
    id: "hash-text-empty",
    target: "hash-text",
    state: "empty",
    label: "Hash text · missing",
    description: "Missing hash renders unknown, not an empty success state.",
    primitiveProps: { value: undefined },
  },
  {
    id: "hash-chip-action",
    target: "hash-chip",
    state: "success",
    label: "Hash chip · action",
    description: "Action hash chip with typed label.",
    primitiveProps: {
      hash: "sha256:a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef",
      kind: "action",
    },
  },
  {
    id: "hash-chip-receipt-tampered",
    target: "hash-chip",
    state: "tampered",
    label: "Hash chip · broken receipt",
    description: "Broken receipt hash remains visible for investigation.",
    primitiveProps: {
      hash: "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      kind: "receipt",
    },
  },
  {
    id: "json-redacted",
    target: "json-viewer",
    state: "redacted",
    label: "JSON viewer · redacted secrets",
    description: "Secret-shaped keys are redacted by default.",
    primitiveProps: { value: syntheticRedactedPayload },
  },
  {
    id: "json-success",
    target: "json-viewer",
    state: "success",
    label: "JSON viewer · safe payload",
    description: "Non-sensitive structured context.",
    primitiveProps: {
      value: { agent_id: "agent-harness-a", tool: "github", action: "merge_pr", pr: 42 },
    },
  },
  {
    id: "confirm-dangerous",
    target: "confirm-dialog",
    state: "success",
    label: "Confirm dialog · dangerous action",
    description: "Human confirmation gate with required audit reason.",
    primitiveProps: {
      open: true,
      title: "Approve frozen action",
      impact: "This binds human approval to the exact canonical action bytes.",
      target: "github.merge_pr on acme/widgets#42",
      reason: "",
      confirmLabel: "Approve",
    },
  },
  {
    id: "confirm-rbac-disabled",
    target: "confirm-dialog",
    state: "rbac-disabled",
    label: "Confirm dialog · confirm disabled",
    description: "Confirm stays disabled until audit reason is supplied.",
    primitiveProps: {
      open: true,
      title: "Freeze agent",
      impact: "Freezing blocks all tool execution for the agent until thawed.",
      target: "agent-harness-a",
      reason: "",
      confirmDisabled: true,
      confirmLabel: "Freeze agent",
    },
  },
  {
    id: "shell-loading",
    target: "stat",
    state: "loading",
    label: "Shell · loading skeleton",
    description: "Shared loading skeleton used while queries resolve.",
    frame: syntheticStatFrame,
    definition: {
      id: "harness-shell-loading",
      type: "stat",
      title: "Loading placeholder",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions" },
    },
  },
  {
    id: "shell-error",
    target: "stat",
    state: "error",
    label: "Shell · query error",
    description: "Shared error state for failed datasource queries.",
    frame: syntheticStatFrame,
    definition: {
      id: "harness-shell-error",
      type: "stat",
      title: "Query failed",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions" },
    },
  },
  {
    id: "shell-disconnected",
    target: "stat",
    state: "disconnected-stream",
    label: "Shell · disconnected stream",
    description: "Polling fallback when live SSE is unavailable.",
    frame: staleMetaFrame(syntheticStatFrame),
    definition: {
      id: "harness-shell-disconnected",
      type: "stat",
      title: "Stream disconnected",
      datasourceId: "gateway-entity",
      options: { valueField: "total_decisions" },
    },
  },
];

export function scenariosForTarget(target: HarnessTarget): ReadonlyArray<HarnessScenario> {
  return HARNESS_SCENARIOS.filter((scenario) => scenario.target === target);
}

export const HARNESS_TARGETS: ReadonlyArray<HarnessTarget> = [
  "stat",
  "table",
  "timeseries",
  "approval-card",
  "provable-timeline",
  "receipt-integrity",
  "severity-badge",
  "hash-text",
  "hash-chip",
  "json-viewer",
  "confirm-dialog",
];