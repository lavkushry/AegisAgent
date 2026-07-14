//! Agent snapshot used by the admit + evaluate pipeline.
//!
//! Deliberately smaller than the full storage `AgentRecord`: only fields the
//! decision path reads after authentication. Storage adapters map records
//! into this view; `aegis-decision` never depends on `aegis-storage`.

/// Authenticated agent identity and authorize-relevant configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeAgent {
    pub id: String,
    pub tenant_id: String,
    /// Human-readable key used in deny reasons / logs.
    pub agent_key: String,
    /// Lifecycle status (`active`, `frozen`, `revoked`, …). Quarantined agents
    /// never reach admit (`Ok(None)` from the runtime lookup).
    pub status: String,
    pub risk_tier: String,
    pub force_approval: bool,
    /// HMAC signing key when request-body signatures are required.
    pub signing_key: Option<String>,
    /// JSON-encoded allow-list of environments, or `None` if unrestricted.
    pub allowed_environments: Option<String>,
}

impl AuthorizeAgent {
    pub fn new(
        id: impl Into<String>,
        tenant_id: impl Into<String>,
        risk_tier: impl Into<String>,
    ) -> Self {
        let id = id.into();
        Self {
            agent_key: id.clone(),
            id,
            tenant_id: tenant_id.into(),
            status: "active".into(),
            risk_tier: risk_tier.into(),
            force_approval: false,
            signing_key: None,
            allowed_environments: None,
        }
    }
}
