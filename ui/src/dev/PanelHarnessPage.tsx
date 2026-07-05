"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Beaker, Monitor, Smartphone, Tablet } from "lucide-react";
import { useAppStore, type Density, type Theme } from "@/app/store";
import SeverityBadge from "@/components/detections/SeverityBadge";
import HashChip from "@/components/security/HashChip";
import {
  ConfirmDialog,
  EmptyState,
  ErrorState,
  HashText,
  JsonViewer,
  LoadingSkeleton,
} from "@/components/primitives";
import ApprovalCard from "@/panels/differentiators/ApprovalCard";
import ProvableTimeline from "@/panels/differentiators/ProvableTimeline";
import ReceiptIntegrity from "@/panels/differentiators/ReceiptIntegrity";
import StatPanel from "@/panels/standard/StatPanel";
import TablePanel from "@/panels/standard/TablePanel";
import TimeSeriesPanel from "@/panels/standard/TimeSeriesPanel";
import { DEV_HARNESS_ENABLED } from "./guard";
import { SYNTHETIC_OPERATOR, SYNTHETIC_TENANT } from "./fixtures";
import {
  HARNESS_SCENARIOS,
  HARNESS_TARGETS,
  HARNESS_TIME_RANGE,
  type HarnessScenario,
  type HarnessState,
  type HarnessTarget,
} from "./scenarios";

type ViewportPreset = "desktop" | "tablet" | "mobile";

const VIEWPORT_WIDTH: Record<ViewportPreset, string> = {
  desktop: "100%",
  tablet: "768px",
  mobile: "390px",
};

const STATE_LABELS: Record<HarnessState, string> = {
  success: "Success",
  loading: "Loading",
  empty: "Empty",
  stale: "Stale",
  error: "Error",
  tampered: "Tampered",
  "broken-row": "Broken row",
  "unknown-verification": "Unknown verification",
  "disconnected-stream": "Disconnected stream",
  "rbac-disabled": "RBAC disabled",
  redacted: "Redacted",
};

function HarnessChrome({
  scenario,
  children,
}: {
  scenario: HarnessScenario;
  children: React.ReactNode;
}) {
  const showLoading = scenario.state === "loading";
  const showError = scenario.state === "error";
  const showEmpty = scenario.state === "empty" && scenario.target !== "stat";
  const showStale =
    scenario.state === "stale" || scenario.state === "disconnected-stream";
  const staleLabel =
    scenario.state === "disconnected-stream"
      ? "Live stream disconnected — polling fallback"
      : "Stale snapshot — refresh recommended";

  return (
    <section
      className="flex min-h-[220px] flex-col rounded-lg border border-[var(--border-default)] bg-[var(--surface-panel)]"
      aria-label={scenario.label}
    >
      <header className="border-b border-[var(--border-default)] px-4 py-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">{scenario.label}</h3>
        <p className="mt-1 text-xs text-[var(--text-secondary)]">{scenario.description}</p>
        {showStale ? (
          <p className="mt-2 text-[11px] font-semibold text-[var(--state-pending)]" role="status">
            {staleLabel}
          </p>
        ) : null}
      </header>
      <div className="relative flex-1 p-4">
        {showLoading ? (
          <LoadingSkeleton label="Harness loading state" />
        ) : showError ? (
          <ErrorState message="Synthetic datasource query failed (harness fixture)." />
        ) : showEmpty ? (
          <EmptyState title="No records" detail="Synthetic empty frame for visual review." />
        ) : (
          children
        )}
      </div>
    </section>
  );
}

function ConfirmDialogHarness({
  scenario,
  props,
}: {
  scenario: HarnessScenario;
  props: Record<string, unknown>;
}) {
  const noop = () => {};
  const [reason, setReason] = useState(String(props.reason ?? ""));
  const requiresReason = !props.confirmDisabled;
  return (
    <HarnessChrome scenario={scenario}>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Dialog is rendered inline for keyboard and focus review. Tab to Cancel / Confirm.
      </p>
      <ConfirmDialog
        open={Boolean(props.open)}
        title={String(props.title ?? "Confirm")}
        impact={String(props.impact ?? "")}
        target={String(props.target ?? "")}
        reason={reason}
        onReasonChange={requiresReason ? setReason : undefined}
        confirmLabel={String(props.confirmLabel ?? "Confirm")}
        confirmDisabled={Boolean(props.confirmDisabled) || (requiresReason && !reason.trim())}
        onConfirm={noop}
        onCancel={noop}
      />
    </HarnessChrome>
  );
}

function ScenarioPreview({ scenario }: { scenario: HarnessScenario }) {
  const noop = () => {};
  const frame = scenario.frame ?? { fields: [], length: 0 };
  const definition = scenario.definition;
  const props = scenario.primitiveProps ?? {};

  if (scenario.target === "stat" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <StatPanel
          definition={definition}
          data={frame}
          timeRange={HARNESS_TIME_RANGE}
          variables={{}}
          onDrilldown={noop}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "table" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <TablePanel
          definition={definition}
          data={frame}
          timeRange={HARNESS_TIME_RANGE}
          variables={{}}
          onDrilldown={noop}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "timeseries" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <div className="h-48">
          <TimeSeriesPanel
            definition={definition}
            data={frame}
            timeRange={HARNESS_TIME_RANGE}
            variables={{}}
            onDrilldown={noop}
          />
        </div>
      </HarnessChrome>
    );
  }

  if (scenario.target === "approval-card" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <ApprovalCard
          definition={definition}
          data={frame}
          timeRange={HARNESS_TIME_RANGE}
          variables={{}}
          onDrilldown={noop}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "provable-timeline" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <ProvableTimeline
          definition={definition}
          data={frame}
          timeRange={HARNESS_TIME_RANGE}
          variables={{}}
          onDrilldown={noop}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "receipt-integrity" && definition) {
    return (
      <HarnessChrome scenario={scenario}>
        <ReceiptIntegrity
          definition={definition}
          data={frame}
          timeRange={HARNESS_TIME_RANGE}
          variables={{}}
          onDrilldown={noop}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "severity-badge") {
    return (
      <HarnessChrome scenario={scenario}>
        <SeverityBadge severity={String(props.severity ?? "unknown")} />
      </HarnessChrome>
    );
  }

  if (scenario.target === "hash-text") {
    return (
      <HarnessChrome scenario={scenario}>
        <HashText value={props.value as string | undefined} />
      </HarnessChrome>
    );
  }

  if (scenario.target === "hash-chip") {
    return (
      <HarnessChrome scenario={scenario}>
        <HashChip
          hash={String(props.hash ?? "")}
          kind={(props.kind as "action" | "receipt") ?? "action"}
        />
      </HarnessChrome>
    );
  }

  if (scenario.target === "json-viewer") {
    return (
      <HarnessChrome scenario={scenario}>
        <JsonViewer value={props.value} />
      </HarnessChrome>
    );
  }

  if (scenario.target === "confirm-dialog") {
    return <ConfirmDialogHarness scenario={scenario} props={props} />;
  }

  return (
    <HarnessChrome scenario={scenario}>
      <ErrorState message="Scenario is missing render bindings." />
    </HarnessChrome>
  );
}

export default function PanelHarnessPage() {
  const theme = useAppStore((s) => s.theme);
  const density = useAppStore((s) => s.density);
  const setTheme = useAppStore((s) => s.setTheme);
  const setDensity = useAppStore((s) => s.setDensity);
  const setRole = useAppStore((s) => s.setRole);
  const setActiveTenant = useAppStore((s) => s.setActiveTenant);
  const setGatewayUrl = useAppStore((s) => s.setGatewayUrl);

  const [target, setTarget] = useState<HarnessTarget>("stat");
  const [selectedId, setSelectedId] = useState(HARNESS_SCENARIOS[0]?.id ?? "");
  const [viewport, setViewport] = useState<ViewportPreset>("desktop");

  const filtered = useMemo(
    () => HARNESS_SCENARIOS.filter((scenario) => scenario.target === target),
    [target],
  );

  const selected =
    HARNESS_SCENARIOS.find((scenario) => scenario.id === selectedId) ?? filtered[0] ?? HARNESS_SCENARIOS[0];

  useEffect(() => {
    if (!filtered.some((scenario) => scenario.id === selectedId) && filtered[0]) {
      setSelectedId(filtered[0].id);
    }
  }, [filtered, selectedId]);

  useEffect(() => {
    setActiveTenant(SYNTHETIC_TENANT);
    setGatewayUrl("http://127.0.0.1:0");
    if (selected?.role) {
      setRole(selected.role);
    }
  }, [selected, setActiveTenant, setGatewayUrl, setRole]);

  if (!DEV_HARNESS_ENABLED) {
    return (
      <div className="p-6 text-sm text-[var(--text-secondary)]" role="alert">
        The component harness is disabled in production builds.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-screen flex-col gap-4 p-4 md:p-6">
      <header className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-panel)] p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-bold text-[var(--text-primary)]">
              <Beaker size={20} aria-hidden="true" />
              Panel harness
            </h2>
            <p className="mt-1 max-w-3xl text-xs text-[var(--text-secondary)]">
              Synthetic fixtures for SOC panels and primitives. No live gateway required. Tenant context:{" "}
              <span className="font-mono text-[var(--text-primary)]">{SYNTHETIC_TENANT}</span> · operator:{" "}
              <span className="font-mono text-[var(--text-primary)]">{SYNTHETIC_OPERATOR}</span>
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="flex items-center gap-1">
              Theme
              <select
                value={theme}
                onChange={(e) => setTheme(e.target.value as Theme)}
                className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1"
                aria-label="Harness theme"
              >
                <option value="dark-soc">dark-soc</option>
                <option value="light">light</option>
                <option value="oled">oled</option>
              </select>
            </label>
            <label className="flex items-center gap-1">
              Density
              <select
                value={density}
                onChange={(e) => setDensity(e.target.value as Density)}
                className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1"
                aria-label="Harness density"
              >
                <option value="compact">compact</option>
                <option value="cozy">cozy</option>
              </select>
            </label>
            <div className="flex items-center gap-1" role="group" aria-label="Viewport width">
              {(
                [
                  ["desktop", Monitor],
                  ["tablet", Tablet],
                  ["mobile", Smartphone],
                ] as const
              ).map(([preset, Icon]) => (
                <button
                  key={preset}
                  type="button"
                  aria-pressed={viewport === preset}
                  onClick={() => setViewport(preset)}
                  className={`rounded border px-2 py-1 ${
                    viewport === preset
                      ? "border-[var(--brand)] bg-[var(--brand)] text-[var(--text-on-brand)]"
                      : "border-[var(--border-default)] text-[var(--text-secondary)]"
                  }`}
                >
                  <Icon size={14} aria-hidden="true" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </header>

      <div className="flex flex-1 flex-col gap-4 lg:flex-row">
        <aside className="w-full shrink-0 space-y-3 lg:w-72">
          <label className="block text-xs font-semibold text-[var(--text-muted)]">
            Component
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value as HarnessTarget)}
              className="mt-1 w-full rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-2 text-sm"
            >
              {HARNESS_TARGETS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>
          <nav aria-label="Harness scenarios" className="space-y-1">
            {filtered.map((scenario) => (
              <button
                key={scenario.id}
                type="button"
                onClick={() => setSelectedId(scenario.id)}
                className={`block w-full rounded border px-3 py-2 text-left text-xs ${
                  selected?.id === scenario.id
                    ? "border-[var(--brand)] bg-[var(--brand)]/10 text-[var(--text-primary)]"
                    : "border-[var(--border-default)] text-[var(--text-secondary)] hover:bg-[var(--surface-panel)]"
                }`}
              >
                <span className="font-semibold">{scenario.label}</span>
                <span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">
                  {STATE_LABELS[scenario.state]}
                </span>
              </button>
            ))}
          </nav>
        </aside>

        <main className="min-w-0 flex-1">
          <div className="mx-auto transition-all" style={{ maxWidth: VIEWPORT_WIDTH[viewport] }}>
            {selected ? <ScenarioPreview key={selected.id} scenario={selected} /> : null}
          </div>
          <p className="mt-4 text-[11px] text-[var(--text-muted)]">
            Accessibility: verify focus order on ConfirmDialog, hash copy buttons, and scenario navigation with
            keyboard only. Unknown and tampered states must never use success-green styling.
          </p>
        </main>
      </div>
    </div>
  );
}