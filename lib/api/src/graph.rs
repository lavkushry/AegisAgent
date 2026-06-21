use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub group: NodeType,
    pub label: String,
    pub timestamp: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: EdgeType,
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
