//! Wire types for `POST /v1/execute`. Deliberately a separate DTO from
//! `aegis_tool_broker_connectors`' own types (matching this codebase's
//! existing convention for gateway<->satellite contracts, e.g.
//! `routes/egress.rs`'s `EgressCheckRequest` vs. `aegis-egress-proxy`'s own
//! `GatewayCheckRequest` — two independently-defined, structurally-matching
//! types, not a shared crate) so this binary's public HTTP contract can
//! evolve without dragging the gateway's `Cargo.toml` along.

use aegis_tool_broker_core::BrokerAction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub tool_name: String,
    pub connector_type: String,
    /// Opaque reference (e.g. `env:GITHUB_TOKEN`), or `None` for a tool
    /// registered without a credential. Never a secret value.
    pub credential_ref: Option<String>,
    /// `active` | `disabled` — from the gateway's `broker_tools` row.
    pub tool_status: String,
    pub action: BrokerAction,
    pub consumed_approval: Option<ConsumedApprovalWire>,
}

#[derive(Debug, Deserialize)]
pub struct ConsumedApprovalWire {
    pub approval_id: String,
    pub action_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub output: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub kind: &'static str,
}
