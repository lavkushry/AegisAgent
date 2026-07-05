"use client";

import React, { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Download, Eye, EyeOff, FileUp, LayoutDashboard, RefreshCw, Save, Trash2 } from "lucide-react";

import { useAppStore } from "@/app/store";
import {
  createSocDashboard,
  deleteSocDashboard,
  listSocDashboards,
  probeGatewayEndpoint,
  updateSocDashboard,
  type SocDashboardRecord,
} from "@/app/api";
import DashboardLoader from "@/dashboards/DashboardLoader";
import { SYSTEM_DASHBOARD_CATALOG, copySystemDashboardAsTenant } from "@/dashboards/editor/catalog";
import { parseAndValidateDashboardJson } from "@/dashboards/editor/validate";
import type { DashboardSchema } from "@/dashboards/schema";
import { errorMessage } from "@/lib/format";
import { ConfirmDialog } from "@/components/primitives";

const EMPTY_DRAFT = `{
  "uid": "my-dashboard",
  "title": "My dashboard",
  "schemaVersion": 1,
  "variables": [],
  "time": { "defaultRange": { "from": "now-24h", "to": "now" } },
  "layout": []
}`;

function recordToEditorText(record: SocDashboardRecord): string {
  try {
    const parsed = JSON.parse(record.schema_json) as DashboardSchema;
    return JSON.stringify(parsed, null, 2);
  } catch {
    return record.schema_json;
  }
}

export default function DashboardEditorPage() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [editorText, setEditorText] = useState(EMPTY_DRAFT);
  const [selectedUid, setSelectedUid] = useState<string | null>(null);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SocDashboardRecord | null>(null);

  const { data: backendReady } = useQuery({
    queryKey: ["dashboardEditorSupport", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) => probeGatewayEndpoint({ ...apiOpts, signal }, "/v1/soc/dashboards"),
    enabled: Boolean(activeTenant && bearerToken),
  });

  const { data: savedDashboards = [], isFetching, refetch } = useQuery({
    queryKey: ["socDashboards", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) => listSocDashboards({ ...apiOpts, signal }),
    enabled: Boolean(activeTenant && bearerToken && backendReady),
  });

  const previewSchema = useMemo(() => {
    const parsed = parseAndValidateDashboardJson(editorText);
    if ("kind" in parsed) return null;
    return parsed;
  }, [editorText]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const parsed = parseAndValidateDashboardJson(editorText);
      if ("kind" in parsed) {
        throw new Error(parsed.message);
      }
      if (selectedUid) {
        return updateSocDashboard(apiOpts, selectedUid, parsed);
      }
      return createSocDashboard(apiOpts, parsed);
    },
    onSuccess: (record) => {
      setSelectedUid(record.uid);
      setEditorText(recordToEditorText(record));
      setValidationMessage(`Saved dashboard '${record.uid}'.`);
      void queryClient.invalidateQueries({ queryKey: ["socDashboards"] });
    },
    onError: (error) => setValidationMessage(errorMessage(error)),
  });

  const deleteMutation = useMutation({
    mutationFn: (uid: string) => deleteSocDashboard(apiOpts, uid),
    onSuccess: () => {
      setSelectedUid(null);
      setEditorText(EMPTY_DRAFT);
      setValidationMessage("Dashboard deleted.");
      void queryClient.invalidateQueries({ queryKey: ["socDashboards"] });
    },
    onError: (error) => setValidationMessage(errorMessage(error)),
  });

  const validateDraft = () => {
    const parsed = parseAndValidateDashboardJson(editorText);
    if ("kind" in parsed) {
      setValidationMessage(parsed.message);
      return;
    }
    setValidationMessage("Schema is valid.");
  };

  const loadRecord = (record: SocDashboardRecord) => {
    setSelectedUid(record.uid);
    setEditorText(recordToEditorText(record));
    setValidationMessage(null);
    setShowPreview(false);
  };

  const copyFromSystem = (uid: string) => {
    const suffix = Date.now().toString(36).slice(-4);
    const newUid = `${uid}-copy-${suffix}`;
    const copied = copySystemDashboardAsTenant(uid, newUid);
    if (!copied) return;
    setSelectedUid(null);
    setEditorText(JSON.stringify(copied, null, 2));
    setValidationMessage(`Copied system dashboard '${uid}' — assign a tenant uid before saving.`);
  };

  const exportJson = () => {
    const blob = new Blob([editorText], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${selectedUid ?? "dashboard-draft"}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const importJson = async (file: File) => {
    const text = await file.text();
    setEditorText(text);
    setSelectedUid(null);
    setValidationMessage(`Imported ${file.name}. Validate before saving.`);
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-[var(--text-primary)]">Dashboard editor</h1>
          <p className="text-xs text-[var(--text-secondary)]">
            Edit tenant dashboards using the same <code className="font-mono">DashboardSchema</code> as system pages.
            System dashboards are read-only — copy them to customize.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-3 py-1.5 text-xs font-semibold"
            onClick={() => validateDraft()}
          >
            Validate
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-3 py-1.5 text-xs font-semibold"
            onClick={() => setShowPreview((v) => !v)}
          >
            {showPreview ? <EyeOff size={14} /> : <Eye size={14} />}
            {showPreview ? "Hide preview" : "Preview"}
          </button>
          <button
            type="button"
            disabled={!backendReady || saveMutation.isPending}
            className="inline-flex items-center gap-1 rounded bg-[var(--brand)] px-3 py-1.5 text-xs font-semibold text-[var(--text-on-brand)] disabled:opacity-50"
            onClick={() => saveMutation.mutate()}
          >
            <Save size={14} />
            {selectedUid ? "Update" : "Create"}
          </button>
        </div>
      </header>

      {!backendReady ? (
        <p className="rounded border border-[var(--border-default)] bg-[var(--surface-panel)] px-3 py-2 text-xs text-[var(--text-secondary)]">
          Gateway endpoint <code className="font-mono">/v1/soc/dashboards</code> is unavailable on this tenant.
          Upgrade the gateway to persist dashboards; you can still validate and export JSON locally.
        </p>
      ) : null}

      {validationMessage ? (
        <p className="rounded border border-[var(--border-default)] bg-[var(--surface-panel)] px-3 py-2 text-xs text-[var(--text-secondary)]">
          {validationMessage}
        </p>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="space-y-4 rounded border border-[var(--border-default)] bg-[var(--surface-panel)] p-3">
          <section>
            <h2 className="mb-2 flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
              <LayoutDashboard size={12} />
              System (read-only)
            </h2>
            <ul className="space-y-1">
              {SYSTEM_DASHBOARD_CATALOG.map((entry) => (
                <li key={entry.uid} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate">{entry.title}</span>
                  <button
                    type="button"
                    title={`Copy ${entry.uid}`}
                    className="shrink-0 rounded border border-[var(--border-default)] p-1"
                    onClick={() => copyFromSystem(entry.uid)}
                  >
                    <Copy size={12} />
                  </button>
                </li>
              ))}
            </ul>
          </section>

          <section>
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Saved</h2>
              <button type="button" className="text-[var(--text-muted)]" onClick={() => void refetch()} aria-label="Refresh">
                <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
              </button>
            </div>
            {savedDashboards.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No tenant dashboards yet.</p>
            ) : (
              <ul className="space-y-1">
                {savedDashboards.map((record) => (
                  <li key={record.id}>
                    <button
                      type="button"
                      className={`w-full rounded px-2 py-1 text-left text-xs ${
                        selectedUid === record.uid ? "bg-[var(--brand)] text-[var(--text-on-brand)]" : "hover:bg-[var(--surface-app)]"
                      }`}
                      onClick={() => loadRecord(record)}
                    >
                      <span className="block truncate font-semibold">{record.title}</span>
                      <span className="block truncate font-mono text-[10px] opacity-80">{record.uid}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>

        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-2 py-1 text-xs"
              onClick={() => fileInputRef.current?.click()}
            >
              <FileUp size={12} />
              Import JSON
            </button>
            <button
              type="button"
              className="inline-flex items-center gap-1 rounded border border-[var(--border-default)] px-2 py-1 text-xs"
              onClick={exportJson}
            >
              <Download size={12} />
              Export JSON
            </button>
            {selectedUid ? (
              <button
                type="button"
                className="inline-flex items-center gap-1 rounded border border-[var(--sev-critical)] px-2 py-1 text-xs text-[var(--sev-critical)]"
                onClick={() => {
                  const record = savedDashboards.find((d) => d.uid === selectedUid);
                  if (record) setDeleteTarget(record);
                }}
              >
                <Trash2 size={12} />
                Delete
              </button>
            ) : null}
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void importJson(file);
                event.target.value = "";
              }}
            />
          </div>

          <textarea
            value={editorText}
            onChange={(event) => setEditorText(event.target.value)}
            spellCheck={false}
            className="min-h-[360px] w-full rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-3 font-mono text-xs text-[var(--text-primary)]"
            aria-label="Dashboard JSON editor"
          />

          {showPreview && previewSchema ? (
            <section className="rounded border border-[var(--border-default)] bg-[var(--surface-panel)] p-4">
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                Preview — {previewSchema.title}
              </h2>
              <DashboardLoader schema={previewSchema} />
            </section>
          ) : null}

          {showPreview && !previewSchema ? (
            <p className="text-xs text-[var(--sev-critical)]">Fix validation errors before previewing.</p>
          ) : null}
        </div>
      </div>

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete dashboard?"
        impact="Permanently removes this tenant dashboard schema. System dashboards are unaffected."
        target={deleteTarget ? `${deleteTarget.title} (${deleteTarget.uid})` : "—"}
        confirmLabel="Delete"
        onConfirm={() => {
          if (deleteTarget) deleteMutation.mutate(deleteTarget.uid);
          setDeleteTarget(null);
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}