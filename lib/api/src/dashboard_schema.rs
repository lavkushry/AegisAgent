//! DashboardSchema validation shared by REST handlers and the SOC console editor (#1634).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

const MAX_TITLE_LEN: usize = 120;
const MAX_UID_LEN: usize = 64;
const MAX_PANELS: usize = 64;
const MAX_ROWS: usize = 32;
const MAX_VARIABLES: usize = 16;

/// UIDs reserved for version-controlled system dashboards — tenants cannot claim them.
pub const RESERVED_SYSTEM_UIDS: &[&str] = &[
    "overview",
    "dashboards",
    "integrity",
    "explore",
    "incidents",
    "detections",
    "rules",
    "alerting",
    "approvals",
    "agents",
    "mcp",
    "receipts",
    "analytics",
    "settings",
    "fleet",
];

const ALLOWED_PANEL_TYPES: &[&str] = &[
    "stat",
    "timeseries",
    "table",
    "agent-table",
    "heatmap",
    "status",
    "feed",
    "note",
    "provable-timeline",
    "approval-card",
    "receipt-integrity",
];

const ALLOWED_DATASOURCE_IDS: &[&str] = &["gateway-entity", "soc-query", "receipt"];

const ALLOWED_ENTITIES: &[&str] = &[
    "ase",
    "incident",
    "alert",
    "approval",
    "agent",
    "mcp_server",
    "receipt",
    "decision",
    "rule",
];

const ALLOWED_SNAPSHOTS: &[&str] = &[
    "tenant-stats",
    "soc-summary",
    "agent-scoreboard",
    "trust-breakdown",
];

const ALLOWED_AGGREGATES: &[&str] = &["count_over_time", "count_by"];

const ALLOWED_GROUP_BY: &[&str] = &["agent_id", "decision", "source_trust", "tool", "action"];

const ALLOWED_DRILLDOWN_KINDS: &[&str] = &[
    "explore",
    "dashboard",
    "incident",
    "receipt",
    "verify-receipt",
    "agent",
];

const FORBIDDEN_TEXT_PATTERN: &[&str] = &["<script", "javascript:", "data:text/html"];

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardTimeConfig {
    pub default_range: DashboardTimeRange,
    #[serde(default)]
    pub refresh_sec: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DashboardTimeRange {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardVariableDefinition {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub multi: Option<bool>,
    #[serde(default)]
    pub include_all: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardPanelDefinition {
    pub id: String,
    #[serde(rename = "type")]
    pub panel_type: String,
    pub title: String,
    pub datasource_id: String,
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub snapshot: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub aggregate: Option<String>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub rules_catalog: Option<String>,
    #[serde(default)]
    pub options: Option<Value>,
    #[serde(default)]
    pub drilldowns: Option<Vec<DashboardDrilldownLink>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DashboardDrilldownLink {
    pub label: String,
    pub target: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardLayoutItem {
    pub panel: DashboardPanelDefinition,
    pub w: u8,
    pub h: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardRow {
    pub id: String,
    #[serde(default)]
    pub tab: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    pub panels: Vec<DashboardLayoutItem>,
}

/// Versioned dashboard document persisted by `POST/PUT /v1/soc/dashboards`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DashboardSchemaPayload {
    pub uid: String,
    pub title: String,
    pub schema_version: u32,
    #[serde(default)]
    pub variables: Vec<DashboardVariableDefinition>,
    pub time: DashboardTimeConfig,
    pub layout: Vec<DashboardRow>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DashboardSchemaError {
    #[error("unsupported schema_version '{0}' (supported: 1)")]
    UnsupportedVersion(u32),
    #[error("invalid uid: {0}")]
    InvalidUid(String),
    #[error("reserved system uid '{0}' cannot be used for tenant dashboards")]
    ReservedUid(String),
    #[error("invalid title: {0}")]
    InvalidTitle(String),
    #[error("layout exceeds maximum rows ({MAX_ROWS})")]
    TooManyRows,
    #[error("dashboard exceeds maximum panels ({MAX_PANELS})")]
    TooManyPanels,
    #[error("variables exceed maximum ({MAX_VARIABLES})")]
    TooManyVariables,
    #[error("invalid panel '{panel_id}': {reason}")]
    InvalidPanel { panel_id: String, reason: String },
    #[error("invalid variable '{name}': {reason}")]
    InvalidVariable { name: String, reason: String },
    #[error("invalid drilldown in panel '{panel_id}': {reason}")]
    InvalidDrilldown { panel_id: String, reason: String },
}

pub fn validate_dashboard_schema(
    payload: &DashboardSchemaPayload,
) -> Result<(), DashboardSchemaError> {
    if payload.schema_version != 1 {
        return Err(DashboardSchemaError::UnsupportedVersion(
            payload.schema_version,
        ));
    }
    validate_uid(&payload.uid)?;
    validate_text_field("title", &payload.title, MAX_TITLE_LEN)?;
    if payload.layout.len() > MAX_ROWS {
        return Err(DashboardSchemaError::TooManyRows);
    }
    if payload.variables.len() > MAX_VARIABLES {
        return Err(DashboardSchemaError::TooManyVariables);
    }
    let mut panel_count = 0usize;
    let mut seen_panel_ids = std::collections::HashSet::new();
    for row in &payload.layout {
        validate_text_field("row.id", &row.id, 64)?;
        if let Some(title) = &row.title {
            validate_text_field("row.title", title, MAX_TITLE_LEN)?;
        }
        for item in &row.panels {
            panel_count += 1;
            if panel_count > MAX_PANELS {
                return Err(DashboardSchemaError::TooManyPanels);
            }
            if !seen_panel_ids.insert(item.panel.id.clone()) {
                return Err(DashboardSchemaError::InvalidPanel {
                    panel_id: item.panel.id.clone(),
                    reason: "duplicate panel id".to_string(),
                });
            }
            validate_panel(&item.panel)?;
            if !(1..=12).contains(&item.w) || !(1..=12).contains(&item.h) {
                return Err(DashboardSchemaError::InvalidPanel {
                    panel_id: item.panel.id.clone(),
                    reason: "w and h must be between 1 and 12".to_string(),
                });
            }
        }
    }
    for variable in &payload.variables {
        validate_variable(variable)?;
    }
    validate_text_field("time.from", &payload.time.default_range.from, 64)?;
    validate_text_field("time.to", &payload.time.default_range.to, 64)?;
    Ok(())
}

pub fn validate_uid(uid: &str) -> Result<(), DashboardSchemaError> {
    let trimmed = uid.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_UID_LEN {
        return Err(DashboardSchemaError::InvalidUid(
            "uid must be 1-64 characters".to_string(),
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(DashboardSchemaError::InvalidUid(
            "uid may only contain lowercase letters, digits, hyphen, underscore".to_string(),
        ));
    }
    if RESERVED_SYSTEM_UIDS.contains(&trimmed) {
        return Err(DashboardSchemaError::ReservedUid(trimmed.to_string()));
    }
    Ok(())
}

fn validate_panel(panel: &DashboardPanelDefinition) -> Result<(), DashboardSchemaError> {
    validate_text_field("panel.id", &panel.id, 64)?;
    validate_text_field("panel.title", &panel.title, MAX_TITLE_LEN)?;
    if !ALLOWED_PANEL_TYPES.contains(&panel.panel_type.as_str()) {
        return Err(DashboardSchemaError::InvalidPanel {
            panel_id: panel.id.clone(),
            reason: format!("unknown panel type '{}'", panel.panel_type),
        });
    }
    if !ALLOWED_DATASOURCE_IDS.contains(&panel.datasource_id.as_str()) {
        return Err(DashboardSchemaError::InvalidPanel {
            panel_id: panel.id.clone(),
            reason: format!("unknown datasource_id '{}'", panel.datasource_id),
        });
    }
    if let Some(entity) = &panel.entity {
        if !ALLOWED_ENTITIES.contains(&entity.as_str()) {
            return Err(DashboardSchemaError::InvalidPanel {
                panel_id: panel.id.clone(),
                reason: format!("unknown entity '{}'", entity),
            });
        }
    }
    if let Some(snapshot) = &panel.snapshot {
        if !ALLOWED_SNAPSHOTS.contains(&snapshot.as_str()) {
            return Err(DashboardSchemaError::InvalidPanel {
                panel_id: panel.id.clone(),
                reason: format!("unknown snapshot '{}'", snapshot),
            });
        }
    }
    if let Some(aggregate) = &panel.aggregate {
        if !ALLOWED_AGGREGATES.contains(&aggregate.as_str()) {
            return Err(DashboardSchemaError::InvalidPanel {
                panel_id: panel.id.clone(),
                reason: format!("unknown aggregate '{}'", aggregate),
            });
        }
    }
    if let Some(group_by) = &panel.group_by {
        if !ALLOWED_GROUP_BY.contains(&group_by.as_str()) {
            return Err(DashboardSchemaError::InvalidPanel {
                panel_id: panel.id.clone(),
                reason: format!("unknown group_by '{}'", group_by),
            });
        }
    }
    if let Some(rules_catalog) = &panel.rules_catalog {
        if rules_catalog != "soc" && rules_catalog != "detection" {
            return Err(DashboardSchemaError::InvalidPanel {
                panel_id: panel.id.clone(),
                reason: "rules_catalog must be 'soc' or 'detection'".to_string(),
            });
        }
    }
    if let Some(query) = &panel.query {
        validate_text_field("panel.query", query, 512)?;
    }
    if let Some(note_body) = panel
        .options
        .as_ref()
        .and_then(|o| o.get("body"))
        .and_then(|v| v.as_str())
    {
        validate_text_field("panel.options.body", note_body, 4096)?;
    }
    if let Some(drilldowns) = &panel.drilldowns {
        for link in drilldowns {
            validate_drilldown(&panel.id, link)?;
        }
    }
    Ok(())
}

fn validate_drilldown(
    panel_id: &str,
    link: &DashboardDrilldownLink,
) -> Result<(), DashboardSchemaError> {
    validate_text_field("drilldown.label", &link.label, 80)?;
    let kind = link
        .target
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DashboardSchemaError::InvalidDrilldown {
            panel_id: panel_id.to_string(),
            reason: "target.kind is required".to_string(),
        })?;
    if !ALLOWED_DRILLDOWN_KINDS.contains(&kind) {
        return Err(DashboardSchemaError::InvalidDrilldown {
            panel_id: panel_id.to_string(),
            reason: format!("unknown drilldown kind '{kind}'"),
        });
    }
    if kind == "explore" {
        let template = link
            .target
            .get("aqlTemplate")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DashboardSchemaError::InvalidDrilldown {
                panel_id: panel_id.to_string(),
                reason: "explore drilldown requires aqlTemplate".to_string(),
            })?;
        validate_text_field("drilldown.aqlTemplate", template, 512)?;
    }
    if kind == "dashboard" {
        let uid = link
            .target
            .get("uid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DashboardSchemaError::InvalidDrilldown {
                panel_id: panel_id.to_string(),
                reason: "dashboard drilldown requires uid".to_string(),
            })?;
        validate_text_field("drilldown.uid", uid, MAX_UID_LEN)?;
    }
    Ok(())
}

fn validate_variable(variable: &DashboardVariableDefinition) -> Result<(), DashboardSchemaError> {
    validate_text_field("variable.name", &variable.name, 40)?;
    if !matches!(variable.kind.as_str(), "constant" | "query" | "interval") {
        return Err(DashboardSchemaError::InvalidVariable {
            name: variable.name.clone(),
            reason: "kind must be constant, query, or interval".to_string(),
        });
    }
    if let Some(query) = &variable.query {
        validate_text_field("variable.query", query, 256)?;
    }
    Ok(())
}

fn validate_text_field(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), DashboardSchemaError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(match field {
            "title" | "panel.title" | "row.title" => {
                DashboardSchemaError::InvalidTitle(format!("{field} must not be empty"))
            }
            "uid" | "panel.id" | "row.id" => {
                DashboardSchemaError::InvalidUid(format!("{field} must not be empty"))
            }
            _ => DashboardSchemaError::InvalidPanel {
                panel_id: field.to_string(),
                reason: "required text field is empty".to_string(),
            },
        });
    }
    if trimmed.len() > max_len {
        return Err(match field {
            "title" | "panel.title" | "row.title" => {
                DashboardSchemaError::InvalidTitle(format!("{field} exceeds {max_len} characters"))
            }
            "uid" => {
                DashboardSchemaError::InvalidUid(format!("{field} exceeds {max_len} characters"))
            }
            panel_id => DashboardSchemaError::InvalidPanel {
                panel_id: panel_id.to_string(),
                reason: format!("{field} exceeds {max_len} characters"),
            },
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    for pattern in FORBIDDEN_TEXT_PATTERN {
        if lower.contains(pattern) {
            return Err(match field {
                "title" | "panel.title" | "row.title" => {
                    DashboardSchemaError::InvalidTitle("forbidden markup in text field".to_string())
                }
                "uid" => DashboardSchemaError::InvalidUid("forbidden markup in uid".to_string()),
                panel_id => DashboardSchemaError::InvalidPanel {
                    panel_id: panel_id.to_string(),
                    reason: "forbidden markup in text field".to_string(),
                },
            });
        }
    }
    Ok(())
}

/// Parse and validate a dashboard JSON document.
pub fn parse_and_validate_dashboard_json(raw: &str) -> Result<DashboardSchemaPayload, String> {
    let payload: DashboardSchemaPayload =
        serde_json::from_str(raw).map_err(|e| format!("invalid dashboard JSON: {e}"))?;
    validate_dashboard_schema(&payload).map_err(|e| e.to_string())?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_schema() -> DashboardSchemaPayload {
        DashboardSchemaPayload {
            uid: "team-posture".to_string(),
            title: "Team posture".to_string(),
            schema_version: 1,
            variables: vec![],
            time: DashboardTimeConfig {
                default_range: DashboardTimeRange {
                    from: "now-24h".to_string(),
                    to: "now".to_string(),
                },
                refresh_sec: Some(30),
            },
            layout: vec![DashboardRow {
                id: "row-1".to_string(),
                tab: None,
                title: Some("Vitals".to_string()),
                panels: vec![DashboardLayoutItem {
                    panel: DashboardPanelDefinition {
                        id: "stat-1".to_string(),
                        panel_type: "stat".to_string(),
                        title: "Decisions".to_string(),
                        datasource_id: "gateway-entity".to_string(),
                        entity: None,
                        snapshot: Some("soc-summary".to_string()),
                        limit: None,
                        query: None,
                        search: None,
                        aggregate: None,
                        group_by: None,
                        interval: None,
                        rules_catalog: None,
                        options: Some(serde_json::json!({ "valueField": "decisions_today" })),
                        drilldowns: Some(vec![DashboardDrilldownLink {
                            label: "Explore".to_string(),
                            target: serde_json::json!({
                                "kind": "explore",
                                "aqlTemplate": "decision:*"
                            }),
                        }]),
                    },
                    w: 4,
                    h: 1,
                }],
            }],
        }
    }

    #[test]
    fn accepts_minimal_valid_schema() {
        validate_dashboard_schema(&minimal_schema()).unwrap();
    }

    #[test]
    fn rejects_reserved_system_uid() {
        let mut schema = minimal_schema();
        schema.uid = "overview".to_string();
        assert_eq!(
            validate_dashboard_schema(&schema),
            Err(DashboardSchemaError::ReservedUid("overview".to_string()))
        );
    }

    #[test]
    fn rejects_unknown_panel_type() {
        let mut schema = minimal_schema();
        schema.layout[0].panels[0].panel.panel_type = "iframe".to_string();
        let err = validate_dashboard_schema(&schema).unwrap_err();
        assert!(matches!(err, DashboardSchemaError::InvalidPanel { .. }));
    }

    #[test]
    fn rejects_script_in_title() {
        let mut schema = minimal_schema();
        schema.title = "<script>alert(1)</script>".to_string();
        assert!(validate_dashboard_schema(&schema).is_err());
    }

    #[test]
    fn round_trip_json() {
        let schema = minimal_schema();
        let raw = serde_json::to_string(&schema).unwrap();
        let parsed = parse_and_validate_dashboard_json(&raw).unwrap();
        assert_eq!(parsed.uid, "team-posture");
    }
}
