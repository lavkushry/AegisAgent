import type { DashboardSchema } from "../schema";
import {
  ALLOWED_AGGREGATES,
  ALLOWED_DATASOURCE_IDS,
  ALLOWED_DRILLDOWN_KINDS,
  ALLOWED_ENTITIES,
  ALLOWED_GROUP_BY,
  ALLOWED_PANEL_TYPES,
  ALLOWED_SNAPSHOTS,
  RESERVED_SYSTEM_UIDS,
} from "./catalog";

const MAX_TITLE_LEN = 120;
const MAX_UID_LEN = 64;
const MAX_PANELS = 64;
const MAX_ROWS = 32;
const MAX_VARIABLES = 16;
const FORBIDDEN_TEXT_PATTERN = ["<script", "javascript:", "data:text/html"];

export type DashboardValidationError =
  | { kind: "parse"; message: string }
  | { kind: "schema"; message: string };

export function parseDashboardJson(
  raw: string,
): DashboardSchema | DashboardValidationError {
  try {
    return JSON.parse(raw) as DashboardSchema;
  } catch (error) {
    return {
      kind: "parse",
      message: error instanceof Error ? error.message : "invalid JSON",
    };
  }
}

export function validateDashboardSchema(
  schema: DashboardSchema,
): DashboardValidationError | null {
  if (schema.schemaVersion !== 1) {
    return {
      kind: "schema",
      message: `unsupported schemaVersion '${schema.schemaVersion}' (supported: 1)`,
    };
  }

  const uidError = validateUid(schema.uid);
  if (uidError) return uidError;

  const titleError = validateTextField("title", schema.title, MAX_TITLE_LEN);
  if (titleError) return titleError;

  if (!Array.isArray(schema.layout) || schema.layout.length > MAX_ROWS) {
    return {
      kind: "schema",
      message: `layout exceeds maximum rows (${MAX_ROWS})`,
    };
  }

  if (
    !Array.isArray(schema.variables) ||
    schema.variables.length > MAX_VARIABLES
  ) {
    return {
      kind: "schema",
      message: `variables exceed maximum (${MAX_VARIABLES})`,
    };
  }

  const seenPanelIds = new Set<string>();
  let panelCount = 0;

  for (const row of schema.layout) {
    const rowIdError = validateTextField("row.id", row.id, 64);
    if (rowIdError) return rowIdError;
    if (row.title) {
      const rowTitleError = validateTextField(
        "row.title",
        row.title,
        MAX_TITLE_LEN,
      );
      if (rowTitleError) return rowTitleError;
    }
    for (const item of row.panels) {
      panelCount += 1;
      if (panelCount > MAX_PANELS) {
        return {
          kind: "schema",
          message: `dashboard exceeds maximum panels (${MAX_PANELS})`,
        };
      }
      if (seenPanelIds.has(item.panel.id)) {
        return {
          kind: "schema",
          message: `duplicate panel id '${item.panel.id}'`,
        };
      }
      seenPanelIds.add(item.panel.id);

      const panelError = validatePanel(item.panel);
      if (panelError) return panelError;

      if (item.w < 1 || item.w > 12 || item.h < 1 || item.h > 12) {
        return {
          kind: "schema",
          message: `panel '${item.panel.id}': w and h must be between 1 and 12`,
        };
      }
    }
  }

  for (const variable of schema.variables) {
    const variableError = validateVariable(variable);
    if (variableError) return variableError;
  }

  const fromError = validateTextField(
    "time.from",
    schema.time.defaultRange.from,
    64,
  );
  if (fromError) return fromError;
  const toError = validateTextField("time.to", schema.time.defaultRange.to, 64);
  if (toError) return toError;

  return null;
}

export function parseAndValidateDashboardJson(
  raw: string,
): DashboardSchema | DashboardValidationError {
  const parsed = parseDashboardJson(raw);
  if ("kind" in parsed) return parsed;
  const error = validateDashboardSchema(parsed);
  return error ?? parsed;
}

function validateUid(uid: string): DashboardValidationError | null {
  const trimmed = uid.trim();
  if (!trimmed || trimmed.length > MAX_UID_LEN) {
    return { kind: "schema", message: "uid must be 1-64 characters" };
  }
  if (!/^[a-z0-9_-]+$/.test(trimmed)) {
    return {
      kind: "schema",
      message:
        "uid may only contain lowercase letters, digits, hyphen, underscore",
    };
  }
  if ((RESERVED_SYSTEM_UIDS as readonly string[]).includes(trimmed)) {
    return {
      kind: "schema",
      message: `reserved system uid '${trimmed}' cannot be used for tenant dashboards`,
    };
  }
  return null;
}

function validatePanel(
  panel: DashboardSchema["layout"][number]["panels"][number]["panel"],
): DashboardValidationError | null {
  const idError = validateTextField("panel.id", panel.id, 64);
  if (idError) return idError;
  const titleError = validateTextField("panel.title", panel.title, MAX_TITLE_LEN);
  if (titleError) return titleError;

  if (!ALLOWED_PANEL_TYPES.includes(panel.type)) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown panel type '${panel.type}'`,
    };
  }
  if (!(ALLOWED_DATASOURCE_IDS as readonly string[]).includes(panel.datasourceId)) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown datasourceId '${panel.datasourceId}'`,
    };
  }
  if (
    panel.entity &&
    !(ALLOWED_ENTITIES as readonly string[]).includes(panel.entity)
  ) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown entity '${panel.entity}'`,
    };
  }
  if (
    panel.snapshot &&
    !(ALLOWED_SNAPSHOTS as readonly string[]).includes(panel.snapshot)
  ) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown snapshot '${panel.snapshot}'`,
    };
  }
  if (
    panel.aggregate &&
    !(ALLOWED_AGGREGATES as readonly string[]).includes(panel.aggregate)
  ) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown aggregate '${panel.aggregate}'`,
    };
  }
  if (
    panel.groupBy &&
    !(ALLOWED_GROUP_BY as readonly string[]).includes(panel.groupBy)
  ) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': unknown groupBy '${panel.groupBy}'`,
    };
  }
  if (
    panel.rulesCatalog &&
    panel.rulesCatalog !== "soc" &&
    panel.rulesCatalog !== "detection"
  ) {
    return {
      kind: "schema",
      message: `panel '${panel.id}': rulesCatalog must be 'soc' or 'detection'`,
    };
  }
  if (panel.query) {
    const queryError = validateTextField("panel.query", panel.query, 512);
    if (queryError) return queryError;
  }
  const noteBody =
    panel.options && typeof panel.options.body === "string"
      ? panel.options.body
      : null;
  if (noteBody) {
    const bodyError = validateTextField("panel.options.body", noteBody, 4096);
    if (bodyError) return bodyError;
  }
  if (panel.drilldowns) {
    for (const link of panel.drilldowns) {
      const drilldownError = validateDrilldown(panel.id, link);
      if (drilldownError) return drilldownError;
    }
  }
  return null;
}

function validateDrilldown(
  panelId: string,
  link: NonNullable<
    DashboardSchema["layout"][number]["panels"][number]["panel"]["drilldowns"]
  >[number],
): DashboardValidationError | null {
  const labelError = validateTextField("drilldown.label", link.label, 80);
  if (labelError) return labelError;
  const kind = link.target.kind;
  if (!(ALLOWED_DRILLDOWN_KINDS as readonly string[]).includes(kind)) {
    return {
      kind: "schema",
      message: `panel '${panelId}': unknown drilldown kind '${kind}'`,
    };
  }
  if (kind === "explore") {
    const template =
      "aqlTemplate" in link.target ? link.target.aqlTemplate : "";
    const templateError = validateTextField(
      "drilldown.aqlTemplate",
      template,
      512,
    );
    if (templateError) return templateError;
  }
  if (kind === "dashboard") {
    const uid = "uid" in link.target ? link.target.uid : "";
    const uidError = validateTextField("drilldown.uid", uid, MAX_UID_LEN);
    if (uidError) return uidError;
  }
  return null;
}

function validateVariable(
  variable: DashboardSchema["variables"][number],
): DashboardValidationError | null {
  const nameError = validateTextField("variable.name", variable.name, 40);
  if (nameError) return nameError;
  if (!["constant", "query", "interval"].includes(variable.kind)) {
    return {
      kind: "schema",
      message: `variable '${variable.name}': kind must be constant, query, or interval`,
    };
  }
  if (variable.query) {
    const queryError = validateTextField("variable.query", variable.query, 256);
    if (queryError) return queryError;
  }
  return null;
}

function validateTextField(
  field: string,
  value: string,
  maxLen: number,
): DashboardValidationError | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return { kind: "schema", message: `${field} must not be empty` };
  }
  if (trimmed.length > maxLen) {
    return {
      kind: "schema",
      message: `${field} exceeds ${maxLen} characters`,
    };
  }
  const lower = trimmed.toLowerCase();
  for (const pattern of FORBIDDEN_TEXT_PATTERN) {
    if (lower.includes(pattern)) {
      return {
        kind: "schema",
        message: `${field}: forbidden markup in text field`,
      };
    }
  }
  return null;
}
