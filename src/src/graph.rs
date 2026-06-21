//! Evidence Graph — canonical node/edge schema (#1271).
//!
//! The evidence graph is the compliance-facing view that ties one tenant's
//! agents, runs, tool calls, decisions, approvals, receipts, incidents, MCP
//! servers, and policies together into a single auditable graph. It is
//! constructed **at query time** from existing tables (`agents`, `decisions`,
//! `approvals`, `action_receipts`, `soc_incidents`, `mcp_servers`,
//! `policies`, ...) — this module defines only the shared, serializable
//! shape; #1272 adds the `/v1/graph/*` query endpoints that build it.
//!
//! [`GraphNode`] and [`GraphEdge`] serialize directly to the field names
//! [vis.js Network](https://visjs.github.io/vis-network/docs/network/) expects
//! (`id`/`label`/`group` for nodes, `from`/`to`/`label` for edges), so a
//! [`EvidenceGraph`] can be handed straight to a `vis.Network` `DataSet`
//! without client-side remapping.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The kind of entity a [`GraphNode`] represents. Serializes to the node's
/// vis.js `group` (used for grouping/coloring nodes by type).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Agent,
    Run,
    ToolCall,
    Decision,
    Approval,
    Receipt,
    Incident,
    McpServer,
    Policy,
}

/// The relationship a [`GraphEdge`] represents. Serializes to the edge's
/// vis.js `label`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    TriggeredBy,
    Executed,
    Decided,
    Approved,
    Produced,
    LinkedTo,
}

/// One entity in the evidence graph (an agent, run, decision, ...).
///
/// Serializes with vis.js's expected node fields: `id`, `group` (the
/// [`NodeType`]), `label`, plus `timestamp` and free-form `metadata`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub group: NodeType,
    pub label: String,
    /// RFC 3339 UTC timestamp the underlying record was created/occurred.
    pub timestamp: String,
    /// Free-form, redacted-by-construction metadata (no secrets — the same
    /// redaction invariant as `AseEvent`/`Alert`).
    #[serde(default)]
    pub metadata: Value,
}

impl GraphNode {
    pub fn new(
        id: impl Into<String>,
        group: NodeType,
        label: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        GraphNode {
            id: id.into(),
            group,
            label: label.into(),
            timestamp: timestamp.into(),
            metadata: Value::Null,
        }
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// One relationship between two [`GraphNode`]s.
///
/// Serializes with vis.js's expected edge fields: `from`, `to`, `label` (the
/// [`EdgeType`]), plus `timestamp`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: EdgeType,
    /// RFC 3339 UTC timestamp the relationship was recorded.
    pub timestamp: String,
}

impl GraphEdge {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        label: EdgeType,
        timestamp: impl Into<String>,
    ) -> Self {
        GraphEdge {
            from: from.into(),
            to: to.into(),
            label,
            timestamp: timestamp.into(),
        }
    }
}

/// A full (sub)graph: nodes plus the edges connecting them. Serializes to
/// `{ "nodes": [...], "edges": [...] }`, the shape `vis.Network`'s
/// `DataSet` constructors accept directly.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EvidenceGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl EvidenceGraph {
    pub fn new() -> Self {
        EvidenceGraph::default()
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.edges.push(edge);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn node_serializes_with_vis_js_field_names() {
        let node = GraphNode::new(
            "agent_1",
            NodeType::Agent,
            "coding-agent-prod",
            "2026-06-06T12:00:00Z",
        );
        let value = serde_json::to_value(&node).unwrap();
        assert_eq!(value["id"], "agent_1");
        assert_eq!(value["group"], "agent");
        assert_eq!(value["label"], "coding-agent-prod");
        assert_eq!(value["timestamp"], "2026-06-06T12:00:00Z");
    }

    #[test]
    fn edge_serializes_with_vis_js_field_names() {
        let edge = GraphEdge::new(
            "run_1",
            "decision_1",
            EdgeType::Decided,
            "2026-06-06T12:00:00Z",
        );
        let value = serde_json::to_value(&edge).unwrap();
        assert_eq!(value["from"], "run_1");
        assert_eq!(value["to"], "decision_1");
        assert_eq!(value["label"], "decided");
        assert_eq!(value["timestamp"], "2026-06-06T12:00:00Z");
    }

    #[test]
    fn node_type_variants_serialize_to_snake_case() {
        assert_eq!(
            serde_json::to_value(NodeType::Agent).unwrap(),
            json!("agent")
        );
        assert_eq!(serde_json::to_value(NodeType::Run).unwrap(), json!("run"));
        assert_eq!(
            serde_json::to_value(NodeType::ToolCall).unwrap(),
            json!("tool_call")
        );
        assert_eq!(
            serde_json::to_value(NodeType::Decision).unwrap(),
            json!("decision")
        );
        assert_eq!(
            serde_json::to_value(NodeType::Approval).unwrap(),
            json!("approval")
        );
        assert_eq!(
            serde_json::to_value(NodeType::Receipt).unwrap(),
            json!("receipt")
        );
        assert_eq!(
            serde_json::to_value(NodeType::Incident).unwrap(),
            json!("incident")
        );
        assert_eq!(
            serde_json::to_value(NodeType::McpServer).unwrap(),
            json!("mcp_server")
        );
        assert_eq!(
            serde_json::to_value(NodeType::Policy).unwrap(),
            json!("policy")
        );
    }

    #[test]
    fn edge_type_variants_serialize_to_snake_case() {
        assert_eq!(
            serde_json::to_value(EdgeType::TriggeredBy).unwrap(),
            json!("triggered_by")
        );
        assert_eq!(
            serde_json::to_value(EdgeType::Executed).unwrap(),
            json!("executed")
        );
        assert_eq!(
            serde_json::to_value(EdgeType::Decided).unwrap(),
            json!("decided")
        );
        assert_eq!(
            serde_json::to_value(EdgeType::Approved).unwrap(),
            json!("approved")
        );
        assert_eq!(
            serde_json::to_value(EdgeType::Produced).unwrap(),
            json!("produced")
        );
        assert_eq!(
            serde_json::to_value(EdgeType::LinkedTo).unwrap(),
            json!("linked_to")
        );
    }

    #[test]
    fn node_metadata_defaults_to_null_and_round_trips() {
        let node = GraphNode::new("decision_1", NodeType::Decision, "deny github.merge", "t");
        assert_eq!(node.metadata, Value::Null);

        let with_meta = node
            .clone()
            .with_metadata(json!({"tool": "github", "action": "merge_pull_request"}));
        let value = serde_json::to_value(&with_meta).unwrap();
        assert_eq!(value["metadata"]["tool"], "github");

        let round_tripped: GraphNode = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, with_meta);
    }

    #[test]
    fn evidence_graph_serializes_to_nodes_and_edges_arrays() {
        let mut graph = EvidenceGraph::new();
        graph.add_node(GraphNode::new(
            "agent_1",
            NodeType::Agent,
            "coding-agent-prod",
            "t1",
        ));
        graph.add_node(GraphNode::new("run_1", NodeType::Run, "run_456", "t1"));
        graph.add_edge(GraphEdge::new(
            "agent_1",
            "run_1",
            EdgeType::TriggeredBy,
            "t1",
        ));

        let value = serde_json::to_value(&graph).unwrap();
        assert!(value["nodes"].is_array());
        assert!(value["edges"].is_array());
        assert_eq!(value["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(value["edges"].as_array().unwrap().len(), 1);
        assert_eq!(value["edges"][0]["from"], "agent_1");
        assert_eq!(value["edges"][0]["to"], "run_1");
    }

    #[test]
    fn empty_evidence_graph_serializes_to_empty_arrays() {
        let graph = EvidenceGraph::new();
        let value = serde_json::to_value(&graph).unwrap();
        assert_eq!(value["nodes"], json!([]));
        assert_eq!(value["edges"], json!([]));
    }

    #[test]
    fn evidence_graph_round_trips_through_json() {
        let mut graph = EvidenceGraph::new();
        graph.add_node(GraphNode::new(
            "policy_1",
            NodeType::Policy,
            "untrusted-mutation-forbid",
            "t1",
        ));
        graph.add_node(GraphNode::new(
            "incident_1",
            NodeType::Incident,
            "deny_storm",
            "t2",
        ));
        graph.add_edge(GraphEdge::new(
            "policy_1",
            "incident_1",
            EdgeType::LinkedTo,
            "t2",
        ));

        let json_str = serde_json::to_string(&graph).unwrap();
        let round_tripped: EvidenceGraph = serde_json::from_str(&json_str).unwrap();
        assert_eq!(round_tripped, graph);
    }
}
