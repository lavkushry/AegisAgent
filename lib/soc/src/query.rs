//! Storage-neutral orchestration for structured SOC queries.

use aegis_api::models::{RuntimeEventRecord, SocQueryRequest};
use aegis_common::errors::AegisError;
use aegis_storage::traits::{
    RuntimeEventGroupField, RuntimeEventListFilters, StorageBackend, TimeBucket,
};

/// Typed service result that protocol adapters render into their wire format.
pub enum RuntimeEventQueryResult {
    Rows {
        rows: Vec<RuntimeEventRecord>,
        next_cursor: Option<i64>,
    },
    Count(i64),
    CountOverTime(Vec<(String, i64)>),
    CountBy {
        group_by: String,
        rows: Vec<(String, i64)>,
    },
}

fn source_component_filter(req: &SocQueryRequest) -> Result<Option<&str>, AegisError> {
    let aliases = [
        req.filters.source_component.as_deref(),
        req.filters.tool.as_deref(),
        req.filters.skill.as_deref(),
    ];
    let selected = aliases.into_iter().flatten().next();
    if selected.is_some_and(|value| aliases.into_iter().flatten().any(|alias| alias != value)) {
        return Err(AegisError::BadRequest(
            "source_component, tool, and skill filters must match when combined".to_string(),
        ));
    }
    Ok(selected)
}

/// Execute one tenant-scoped Agent Security Event query through `StorageBackend`.
pub async fn query_runtime_events(
    storage: &dyn StorageBackend,
    tenant_id: &str,
    req: &SocQueryRequest,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<RuntimeEventQueryResult, AegisError> {
    if req.filters.action.is_some() || req.filters.resource.is_some() {
        return Err(AegisError::BadRequest(
            "action and resource filters are not supported for the ase entity".to_string(),
        ));
    }
    let q = req
        .filters
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty());
    let filters = RuntimeEventListFilters {
        event_type: req.filters.event_type.as_deref(),
        severity: req.filters.severity.as_deref(),
        agent_id: req.filters.agent_id.as_deref(),
        run_id: req.filters.run_id.as_deref(),
        trace_id: req.filters.trace_id.as_deref(),
        source_component: source_component_filter(req)?,
        source_trust: req.filters.source_trust.as_deref(),
        decision: req.filters.decision.as_deref(),
        action_hash: req.filters.action_hash.as_deref(),
        receipt_hash: req.filters.receipt_hash.as_deref(),
        from,
        to,
        q,
    };

    match req.aggregate.as_deref().unwrap_or("none") {
        "none" => {
            let (rows, next_cursor) = storage
                .query_runtime_events(
                    tenant_id,
                    req.limit.unwrap_or(50).clamp(1, 200),
                    req.cursor,
                    filters,
                )
                .await?;
            Ok(RuntimeEventQueryResult::Rows { rows, next_cursor })
        }
        "count" => Ok(RuntimeEventQueryResult::Count(
            storage.count_runtime_events(tenant_id, filters).await?,
        )),
        "count_over_time" => Ok(RuntimeEventQueryResult::CountOverTime(
            storage
                .count_runtime_events_over_time(
                    tenant_id,
                    TimeBucket::parse(req.interval.as_deref().unwrap_or("hour")),
                    filters,
                )
                .await?,
        )),
        "count_by" => {
            let group_by = req.group_by.as_deref().ok_or_else(|| {
                AegisError::BadRequest("group_by is required for count_by".to_string())
            })?;
            let field = RuntimeEventGroupField::parse(group_by).ok_or_else(|| {
                AegisError::BadRequest(format!(
                    "unsupported ASE group_by '{group_by}' (supported: event_type, severity, agent_id, source_component, source_trust, decision)"
                ))
            })?;
            let rows = storage
                .count_runtime_events_grouped(tenant_id, field, filters, req.limit.unwrap_or(20))
                .await?;
            Ok(RuntimeEventQueryResult::CountBy {
                group_by: group_by.to_string(),
                rows,
            })
        }
        other => Err(AegisError::BadRequest(format!(
            "unsupported aggregate '{other}' (supported: none, count, count_over_time, count_by)"
        ))),
    }
}
