#![allow(unused_imports)]
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

use super::*;

// ── #1272: Evidence Graph Query API ──────────────────────────────────────────

/// #1272: append the provenance subgraph for one decision (tool call ->
/// decision -> optional approval/receipt/policies) into `graph`.
///
/// `seen` dedups node ids across repeated calls (e.g. multiple decisions in
/// the same run sharing an agent/run node). `depth` (already clamped by the
/// caller) controls how much of the chain is included:
/// - depth >= 1: `ToolCall` + `Decision` nodes, `Run`/`Agent` linkage.
/// - depth >= 2: `Approval` (if `require_approval`) and `Receipt` (if
///   produced) nodes.
/// - depth >= 3: `Policy` nodes for each entry in `matched_policy_ids`.
///
/// #1316: builds the tool_call/decision/run/approval/receipt/policy nodes and
/// edges for one decision. `approvals_by_decision`/`receipts_by_decision` are
/// prefetched in a single batched query per caller (not queried per-decision
/// here) to avoid the N+1 pattern when expanding a multi-decision subgraph.
pub(crate) fn add_decision_subgraph(
    graph: &mut crate::graph::EvidenceGraph,
    seen: &mut std::collections::HashSet<String>,
    approvals_by_decision: &std::collections::HashMap<String, ApprovalRecord>,
    receipts_by_decision: &std::collections::HashMap<String, ActionReceiptRecord>,
    decision: &DecisionRecord,
    agent_node_id: &str,
    depth: u32,
) {
    use crate::graph::{EdgeType, GraphEdge, GraphNode, NodeType};

    let timestamp = decision.created_at.to_rfc3339();
    let tool_call_id = format!("tool_call:{}", decision.id);
    let decision_node_id = format!("decision:{}", decision.id);

    if seen.insert(tool_call_id.clone()) {
        graph.add_node(GraphNode::new(
            tool_call_id.clone(),
            NodeType::ToolCall,
            format!("{}.{}", decision.skill, decision.action),
            timestamp.clone(),
        ));
    }
    if seen.insert(decision_node_id.clone()) {
        graph.add_node(
            GraphNode::new(
                decision_node_id.clone(),
                NodeType::Decision,
                decision.decision.clone(),
                timestamp.clone(),
            )
            .with_metadata(json!({
                "risk_score": decision.risk_score,
                "reason": decision.reason,
            })),
        );
    }
    graph.add_edge(GraphEdge::new(
        tool_call_id.clone(),
        decision_node_id.clone(),
        EdgeType::Decided,
        timestamp.clone(),
    ));

    if let Some(run_id) = &decision.run_id {
        let run_node_id = format!("run:{run_id}");
        if seen.insert(run_node_id.clone()) {
            graph.add_node(GraphNode::new(
                run_node_id.clone(),
                NodeType::Run,
                run_id.clone(),
                timestamp.clone(),
            ));
        }
        graph.add_edge(GraphEdge::new(
            run_node_id.clone(),
            tool_call_id.clone(),
            EdgeType::Executed,
            timestamp.clone(),
        ));
        let run_triggered_edge = format!("{run_node_id}->{agent_node_id}:triggered_by");
        if seen.insert(run_triggered_edge) {
            graph.add_edge(GraphEdge::new(
                run_node_id,
                agent_node_id.to_string(),
                EdgeType::TriggeredBy,
                timestamp.clone(),
            ));
        }
    } else {
        graph.add_edge(GraphEdge::new(
            tool_call_id.clone(),
            agent_node_id.to_string(),
            EdgeType::TriggeredBy,
            timestamp.clone(),
        ));
    }

    if depth < 2 {
        return;
    }

    if let Some(approval) = approvals_by_decision.get(&decision.id) {
        let approval_node_id = format!("approval:{}", approval.id);
        if seen.insert(approval_node_id.clone()) {
            graph.add_node(GraphNode::new(
                approval_node_id.clone(),
                NodeType::Approval,
                approval.status.clone(),
                approval.created_at.to_rfc3339(),
            ));
        }
        graph.add_edge(GraphEdge::new(
            decision_node_id.clone(),
            approval_node_id,
            EdgeType::Approved,
            timestamp.clone(),
        ));
    }

    if let Some(receipt) = receipts_by_decision.get(&decision.id) {
        let receipt_node_id = format!("receipt:{}", receipt.id);
        if seen.insert(receipt_node_id.clone()) {
            graph.add_node(GraphNode::new(
                receipt_node_id.clone(),
                NodeType::Receipt,
                receipt.receipt_hash.clone(),
                receipt.ts.clone(),
            ));
        }
        graph.add_edge(GraphEdge::new(
            decision_node_id.clone(),
            receipt_node_id,
            EdgeType::Produced,
            timestamp.clone(),
        ));
    }

    if depth < 3 {
        return;
    }

    for policy_name in decision
        .matched_policy_ids
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
    {
        let policy_node_id = format!("policy:{policy_name}");
        if seen.insert(policy_node_id.clone()) {
            graph.add_node(GraphNode::new(
                policy_node_id.clone(),
                NodeType::Policy,
                policy_name.to_string(),
                timestamp.clone(),
            ));
        }
        graph.add_edge(GraphEdge::new(
            decision_node_id.clone(),
            policy_node_id,
            EdgeType::LinkedTo,
            timestamp.clone(),
        ));
    }
}

/// `GET /v1/graph/run/:run_id` — the full evidence subgraph for one agent run:
/// the agent, every tool call / decision in the run, and any approvals,
/// receipts, and matched policies. Tenant-scoped (#1271 `EvidenceGraph`
/// shape, vis.js-compatible). 404 if the run has no decisions for this tenant.
pub async fn get_graph_for_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    use crate::graph::{EvidenceGraph, GraphNode, NodeType};

    let decisions = match db::list_decisions_by_run_id(&state.pool, &tenant_id, &run_id).await {
        Ok(decisions) => decisions,
        Err(e) => {
            error!("Failed to list decisions for run {}: {:?}", run_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if decisions.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Run not found"})),
        )
            .into_response();
    }

    let mut graph = EvidenceGraph::new();
    let mut seen = std::collections::HashSet::new();

    let agent_id = decisions[0].agent_id.clone();
    let agent_node_id = format!("agent:{agent_id}");
    if let Ok(Some(agent)) = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        seen.insert(agent_node_id.clone());
        graph.add_node(GraphNode::new(
            agent_node_id.clone(),
            NodeType::Agent,
            agent.name,
            agent.created_at.to_rfc3339(),
        ));
    }

    // #1316: batch-fetch approvals/receipts for every decision in this run in
    // 2 indexed queries total, instead of up to 2 per decision (N+1).
    let decision_ids: Vec<String> = decisions.iter().map(|d| d.id.clone()).collect();
    let approvals_by_decision =
        db::list_approvals_by_decision_ids(&state.pool, &tenant_id, &decision_ids)
            .await
            .unwrap_or_default();
    let receipts_by_decision =
        db::list_action_receipts_by_decision_ids(&state.pool, &tenant_id, &decision_ids)
            .await
            .unwrap_or_default();

    for decision in &decisions {
        add_decision_subgraph(
            &mut graph,
            &mut seen,
            &approvals_by_decision,
            &receipts_by_decision,
            decision,
            &agent_node_id,
            3,
        );
    }

    (StatusCode::OK, Json(graph)).into_response()
}

/// `GET /v1/graph/incident/:incident_id` — the evidence subgraph for one SOC
/// incident: the incident, its agent, and the decisions behind each event in
/// `source_event_ids` (#1301 audit-event-to-decision linkage). Tenant-scoped.
/// 404 if the incident doesn't exist for this tenant.
pub async fn get_graph_for_incident(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    use crate::graph::{EdgeType, EvidenceGraph, GraphEdge, GraphNode, NodeType};

    let incident = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(incident)) => incident,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Incident not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident {}: {:?}", incident_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let mut graph = EvidenceGraph::new();
    let mut seen = std::collections::HashSet::new();

    let incident_node_id = format!("incident:{}", incident.id);
    seen.insert(incident_node_id.clone());
    graph.add_node(GraphNode::new(
        incident_node_id.clone(),
        NodeType::Incident,
        incident.summary.clone(),
        incident.opened_at.clone(),
    ));

    let agent_node_id = format!("agent:{}", incident.agent_id);
    if let Ok(Some(agent)) = db::get_agent_by_id(&state.pool, &tenant_id, &incident.agent_id).await
    {
        if seen.insert(agent_node_id.clone()) {
            graph.add_node(GraphNode::new(
                agent_node_id.clone(),
                NodeType::Agent,
                agent.name,
                agent.created_at.to_rfc3339(),
            ));
        }
        graph.add_edge(GraphEdge::new(
            incident_node_id.clone(),
            agent_node_id.clone(),
            EdgeType::LinkedTo,
            incident.opened_at.clone(),
        ));
    }

    let event_ids: Vec<String> =
        serde_json::from_str(&incident.source_event_ids).unwrap_or_default();

    // #1316: resolve event -> decision first, then batch-fetch approvals/
    // receipts for all distinct decisions in 2 indexed queries (instead of
    // up to 2 per-decision queries inside add_decision_subgraph).
    let mut decisions_for_incident: Vec<DecisionRecord> = Vec::new();
    let mut linked_decision_ids: Vec<String> = Vec::new();
    for event_id in &event_ids {
        let decision_id =
            match db::get_audit_event_decision_id(&state.pool, &tenant_id, event_id).await {
                Ok(Some(id)) => id,
                _ => continue,
            };
        linked_decision_ids.push(decision_id.clone());

        let decision_node_id = format!("decision:{decision_id}");
        if !seen.contains(&decision_node_id) {
            if let Ok(Some(decision)) =
                db::get_decision_by_id(&state.pool, &tenant_id, &decision_id).await
            {
                decisions_for_incident.push(decision);
            }
        }
    }

    let decision_ids_to_fetch: Vec<String> = decisions_for_incident
        .iter()
        .map(|d| d.id.clone())
        .collect();
    let approvals_by_decision =
        db::list_approvals_by_decision_ids(&state.pool, &tenant_id, &decision_ids_to_fetch)
            .await
            .unwrap_or_default();
    let receipts_by_decision =
        db::list_action_receipts_by_decision_ids(&state.pool, &tenant_id, &decision_ids_to_fetch)
            .await
            .unwrap_or_default();

    for decision in &decisions_for_incident {
        add_decision_subgraph(
            &mut graph,
            &mut seen,
            &approvals_by_decision,
            &receipts_by_decision,
            decision,
            &agent_node_id,
            2,
        );
    }

    for decision_id in &linked_decision_ids {
        let decision_node_id = format!("decision:{decision_id}");
        if seen.contains(&decision_node_id) {
            graph.add_edge(GraphEdge::new(
                incident_node_id.clone(),
                decision_node_id,
                EdgeType::LinkedTo,
                incident.opened_at.clone(),
            ));
        }
    }

    (StatusCode::OK, Json(graph)).into_response()
}

/// Query params for `GET /v1/graph/agent/:agent_id`.
#[derive(Debug, serde::Deserialize, Default)]
pub struct GraphDepthParams {
    pub depth: Option<u32>,
}

/// Maximum number of decisions expanded into a `GET /v1/graph/agent/:agent_id`
/// subgraph — bounds the query regardless of `depth` (#1272 "Depth limit to
/// prevent unbounded queries").
const GRAPH_AGENT_DECISION_LIMIT: i64 = 50;

/// `GET /v1/graph/agent/:agent_id?depth=N` — an agent-centric evidence graph:
/// the agent, its recent decisions (tool calls), and (depth >= 2)
/// approvals/receipts/policies, and (depth >= 3) open/closed SOC incidents
/// linked to this agent. `depth` is clamped to `[1, 5]` (default 3); depths
/// 4-5 are accepted but currently behave the same as depth 3. Tenant-scoped.
/// 404 if the agent doesn't exist for this tenant.
pub async fn get_graph_for_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<GraphDepthParams>,
) -> impl IntoResponse {
    use crate::graph::{EdgeType, EvidenceGraph, GraphEdge, GraphNode, NodeType};

    let depth = params.depth.unwrap_or(3).clamp(1, 5);

    let agent = match db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch agent {}: {:?}", agent_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let mut graph = EvidenceGraph::new();
    let mut seen = std::collections::HashSet::new();

    let agent_node_id = format!("agent:{agent_id}");
    seen.insert(agent_node_id.clone());
    graph.add_node(GraphNode::new(
        agent_node_id.clone(),
        NodeType::Agent,
        agent.name,
        agent.created_at.to_rfc3339(),
    ));

    let decisions = db::list_decisions(
        &state.pool,
        &tenant_id,
        GRAPH_AGENT_DECISION_LIMIT,
        0,
        Some(&agent_id),
        None,
    )
    .await
    .unwrap_or_default();

    // #1316: batch-fetch approvals/receipts for every decision in this
    // agent's graph in 2 indexed queries total, instead of up to 2 per
    // decision (N+1) — up to 100 unindexed queries for a 50-decision agent
    // graph before this change.
    let decision_ids: Vec<String> = decisions.iter().map(|d| d.id.clone()).collect();
    let approvals_by_decision =
        db::list_approvals_by_decision_ids(&state.pool, &tenant_id, &decision_ids)
            .await
            .unwrap_or_default();
    let receipts_by_decision =
        db::list_action_receipts_by_decision_ids(&state.pool, &tenant_id, &decision_ids)
            .await
            .unwrap_or_default();

    for decision in &decisions {
        add_decision_subgraph(
            &mut graph,
            &mut seen,
            &approvals_by_decision,
            &receipts_by_decision,
            decision,
            &agent_node_id,
            depth,
        );
    }

    if depth >= 3 {
        let incidents = db::list_soc_incidents(
            &state.pool,
            &tenant_id,
            GRAPH_AGENT_DECISION_LIMIT,
            0,
            None,
            None,
            Some(&agent_id),
        )
        .await
        .unwrap_or_default();

        for incident in &incidents {
            let incident_node_id = format!("incident:{}", incident.id);
            if seen.insert(incident_node_id.clone()) {
                graph.add_node(GraphNode::new(
                    incident_node_id.clone(),
                    NodeType::Incident,
                    incident.summary.clone(),
                    incident.opened_at.clone(),
                ));
            }
            graph.add_edge(GraphEdge::new(
                incident_node_id,
                agent_node_id.clone(),
                EdgeType::LinkedTo,
                incident.opened_at.clone(),
            ));
        }
    }

    (StatusCode::OK, Json(graph)).into_response()
}

// ── SOC Phase 4: Response API ─────────────────────────────────────────────────

/// Optional request body for `POST /v1/agents/:id/freeze` (#0079) — an
/// operator-supplied reason recorded on `agents.frozen_reason` and surfaced in
/// the audit trail / SOC UI. Omit the body (or `reason`) to freeze without one.
#[derive(Debug, serde::Deserialize, Default)]
pub struct FreezeAgentRequest {
    pub reason: Option<String>,
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::db;
    use crate::events;
    use crate::metrics::SecurityMetrics;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use crate::routes::test_helpers::*;
    use axum::body::{to_bytes, Bytes};
    use axum::extract::{FromRequestParts, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    fn make_graph_test_agent(id: &str, tenant_id: &str, name: &str) -> AgentRecord {
        AgentRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_key: format!("{id}-key"),
            agent_token: format!("{id}-token"),
            name: name.to_string(),
            owner_team: None,
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "medium".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_graph_test_decision(
        id: &str,
        tenant_id: &str,
        agent_id: &str,
        run_id: Option<&str>,
        decision: &str,
        matched_policy_ids: Option<&str>,
    ) -> DecisionRecord {
        DecisionRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
            user_id: None,
            run_id: run_id.map(|s| s.to_string()),
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: Some("payments#1".to_string()),
            input_json: "{}".to_string(),
            decision: decision.to_string(),
            risk_score: Some(80),
            reason: Some("test reason".to_string()),
            matched_policy_ids: matched_policy_ids.map(|s| s.to_string()),
            request_id: None,
            latency_ms: Some(5),
            composite_risk_score: Some(50),
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn get_graph_for_run_returns_evidence_graph_with_approval_and_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("graph_run_basic").await;

        let agent = make_graph_test_agent("graph_run_agent", &tenant_id, "Graph Run Agent");
        db::insert_agent(&state.pool, &agent).await.unwrap();

        let decision = make_graph_test_decision(
            "graph_run_decision_1",
            &tenant_id,
            &agent.id,
            Some("run_graph_1"),
            "require_approval",
            Some("policy_a,policy_b"),
        );
        db::insert_decision(&state.pool, &decision).await.unwrap();

        let approval = make_test_approval(Some(Utc::now() + chrono::Duration::hours(1)), "pending");
        let mut approval = approval;
        approval.tenant_id = tenant_id.clone();
        approval.decision_id = decision.id.clone();
        db::insert_approval(&state.pool, &approval).await.unwrap();

        db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.decision_id = Some(decision.id.clone());
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r
        })
        .await
        .unwrap();

        let response = get_graph_for_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("run_graph_1".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let graph: crate::graph::EvidenceGraph = serde_json::from_slice(&body).unwrap();

        use crate::graph::{EdgeType, NodeType};

        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Agent && n.id == "agent:graph_run_agent"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Run && n.id == "run:run_graph_1"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::ToolCall && n.id == "tool_call:graph_run_decision_1"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Decision && n.id == "decision:graph_run_decision_1"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Approval && n.id == format!("approval:{}", approval.id)));
        assert!(graph.nodes.iter().any(|n| n.group == NodeType::Receipt));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Policy && n.id == "policy:policy_a"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Policy && n.id == "policy:policy_b"));

        assert!(graph
            .edges
            .iter()
            .any(|e| e.from == "run:run_graph_1" && e.label == EdgeType::TriggeredBy));
        assert!(graph.edges.iter().any(|e| e.label == EdgeType::Decided));
        assert!(graph.edges.iter().any(|e| e.label == EdgeType::Approved));
        assert!(graph.edges.iter().any(|e| e.label == EdgeType::Produced));
        assert!(graph.edges.iter().any(|e| e.label == EdgeType::LinkedTo));
    }

    #[tokio::test]
    async fn get_graph_for_run_returns_404_for_unknown_or_cross_tenant_run() {
        let (state, tenant_id, _agent_token) = setup_state("graph_run_404").await;

        let agent = make_graph_test_agent("graph_run_404_agent", &tenant_id, "Agent");
        db::insert_agent(&state.pool, &agent).await.unwrap();
        let decision = make_graph_test_decision(
            "graph_run_404_decision",
            &tenant_id,
            &agent.id,
            Some("run_404"),
            "allow",
            None,
        );
        db::insert_decision(&state.pool, &decision).await.unwrap();

        // Unknown run_id.
        let response = get_graph_for_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does_not_exist".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Cross-tenant lookup of a real run_id.
        let response_cross = get_graph_for_run(
            State(state.clone()),
            TenantId("other_tenant".to_string()),
            Path("run_404".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_graph_for_incident_returns_evidence_graph_with_linked_decision() {
        let (state, tenant_id, _agent_token) = setup_state("graph_incident_basic").await;

        let agent = make_graph_test_agent("graph_incident_agent", &tenant_id, "Incident Agent");
        db::insert_agent(&state.pool, &agent).await.unwrap();

        let decision = make_graph_test_decision(
            "graph_incident_decision_1",
            &tenant_id,
            &agent.id,
            None,
            "deny",
            None,
        );
        db::insert_decision(&state.pool, &decision).await.unwrap();

        let audit_event = AuditEventRecord {
            id: "graph_incident_event_1".to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "decision".to_string(),
            agent_id: Some(agent.id.clone()),
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: Some(decision.id.clone()),
            approval_id: None,
            created_at: Utc::now(),
        };
        db::insert_audit_event(&state.pool, &audit_event)
            .await
            .unwrap();

        let incident = crate::models::SocIncidentRecord {
            id: "graph_incident_1".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: agent.id.clone(),
            summary: "Graph test incident".to_string(),
            source_event_ids: serde_json::to_string(&vec![audit_event.id.clone()]).unwrap(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(&state.pool, &incident)
            .await
            .unwrap();

        let response = get_graph_for_incident(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(incident.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let graph: crate::graph::EvidenceGraph = serde_json::from_slice(&body).unwrap();

        use crate::graph::{EdgeType, NodeType};

        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Incident && n.id == "incident:graph_incident_1"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.group == NodeType::Agent && n.id == "agent:graph_incident_agent"));
        assert!(
            graph
                .nodes
                .iter()
                .any(|n| n.group == NodeType::Decision
                    && n.id == "decision:graph_incident_decision_1")
        );

        assert!(graph.edges.iter().any(|e| {
            e.from == "incident:graph_incident_1"
                && e.to == "agent:graph_incident_agent"
                && e.label == EdgeType::LinkedTo
        }));
        assert!(graph.edges.iter().any(|e| {
            e.from == "incident:graph_incident_1"
                && e.to == "decision:graph_incident_decision_1"
                && e.label == EdgeType::LinkedTo
        }));
    }

    #[tokio::test]
    async fn get_graph_for_incident_returns_404_for_unknown_or_cross_tenant_incident() {
        let (state, tenant_id, _agent_token) = setup_state("graph_incident_404").await;

        let response = get_graph_for_incident(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does_not_exist".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let incident = crate::models::SocIncidentRecord {
            id: "graph_incident_404_real".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "some_agent".to_string(),
            summary: "Real incident".to_string(),
            source_event_ids: "[]".to_string(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(&state.pool, &incident)
            .await
            .unwrap();

        let response_cross = get_graph_for_incident(
            State(state.clone()),
            TenantId("other_tenant".to_string()),
            Path(incident.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_graph_for_agent_depth_controls_subgraph_expansion() {
        let (state, tenant_id, _agent_token) = setup_state("graph_agent_depth").await;

        let agent = make_graph_test_agent("graph_agent_depth_agent", &tenant_id, "Depth Agent");
        db::insert_agent(&state.pool, &agent).await.unwrap();

        let decision = make_graph_test_decision(
            "graph_agent_depth_decision",
            &tenant_id,
            &agent.id,
            None,
            "require_approval",
            Some("policy_depth"),
        );
        db::insert_decision(&state.pool, &decision).await.unwrap();

        let mut approval =
            make_test_approval(Some(Utc::now() + chrono::Duration::hours(1)), "pending");
        approval.tenant_id = tenant_id.clone();
        approval.decision_id = decision.id.clone();
        db::insert_approval(&state.pool, &approval).await.unwrap();

        let incident = crate::models::SocIncidentRecord {
            id: "graph_agent_depth_incident".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: agent.id.clone(),
            summary: "Depth incident".to_string(),
            source_event_ids: "[]".to_string(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(&state.pool, &incident)
            .await
            .unwrap();

        use crate::graph::NodeType;

        // depth=1: tool call + decision present, but no approval/policy/incident.
        let response_d1 = get_graph_for_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent.id.clone()),
            axum::extract::Query(GraphDepthParams { depth: Some(1) }),
        )
        .await
        .into_response();
        assert_eq!(response_d1.status(), StatusCode::OK);
        let body_d1 = to_bytes(response_d1.into_body(), usize::MAX).await.unwrap();
        let graph_d1: crate::graph::EvidenceGraph = serde_json::from_slice(&body_d1).unwrap();
        assert!(graph_d1.nodes.iter().any(|n| n.group == NodeType::Decision));
        assert!(!graph_d1.nodes.iter().any(|n| n.group == NodeType::Approval));
        assert!(!graph_d1.nodes.iter().any(|n| n.group == NodeType::Policy));
        assert!(!graph_d1.nodes.iter().any(|n| n.group == NodeType::Incident));

        // depth=2: approval appears, but not policy/incident.
        let response_d2 = get_graph_for_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent.id.clone()),
            axum::extract::Query(GraphDepthParams { depth: Some(2) }),
        )
        .await
        .into_response();
        let body_d2 = to_bytes(response_d2.into_body(), usize::MAX).await.unwrap();
        let graph_d2: crate::graph::EvidenceGraph = serde_json::from_slice(&body_d2).unwrap();
        assert!(graph_d2.nodes.iter().any(|n| n.group == NodeType::Approval));
        assert!(!graph_d2.nodes.iter().any(|n| n.group == NodeType::Policy));
        assert!(!graph_d2.nodes.iter().any(|n| n.group == NodeType::Incident));

        // depth=99 clamps to 5, behaves like depth>=3: policy + incident appear.
        let response_d99 = get_graph_for_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent.id.clone()),
            axum::extract::Query(GraphDepthParams { depth: Some(99) }),
        )
        .await
        .into_response();
        let body_d99 = to_bytes(response_d99.into_body(), usize::MAX)
            .await
            .unwrap();
        let graph_d99: crate::graph::EvidenceGraph = serde_json::from_slice(&body_d99).unwrap();
        assert!(graph_d99.nodes.iter().any(|n| n.group == NodeType::Policy));
        assert!(graph_d99.nodes.iter().any(
            |n| n.group == NodeType::Incident && n.id == "incident:graph_agent_depth_incident"
        ));

        // depth=0 clamps to 1: same as depth=1 (no approval/policy/incident).
        let response_d0 = get_graph_for_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent.id.clone()),
            axum::extract::Query(GraphDepthParams { depth: Some(0) }),
        )
        .await
        .into_response();
        let body_d0 = to_bytes(response_d0.into_body(), usize::MAX).await.unwrap();
        let graph_d0: crate::graph::EvidenceGraph = serde_json::from_slice(&body_d0).unwrap();
        assert!(!graph_d0.nodes.iter().any(|n| n.group == NodeType::Approval));
    }

    #[tokio::test]
    async fn get_graph_for_agent_returns_404_for_unknown_or_cross_tenant_agent() {
        let (state, tenant_id, _agent_token) = setup_state("graph_agent_404").await;

        let agent = make_graph_test_agent("graph_agent_404_agent", &tenant_id, "Agent");
        db::insert_agent(&state.pool, &agent).await.unwrap();

        let response = get_graph_for_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does_not_exist".to_string()),
            axum::extract::Query(GraphDepthParams::default()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response_cross = get_graph_for_agent(
            State(state.clone()),
            TenantId("other_tenant".to_string()),
            Path(agent.id.clone()),
            axum::extract::Query(GraphDepthParams::default()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }
}
