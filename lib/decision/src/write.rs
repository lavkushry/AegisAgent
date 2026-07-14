//! Parameters for host-side decision/audit persistence.

use aegis_api::models::AuthorizeRequest;
use std::time::Instant;
use uuid::Uuid;

/// Inputs for one durable (or dry-run) decision + audit write.
///
/// Host implements the write via `StorageBackend` / batch sinks; the decision
/// crate only orchestrates when to call this after an early deny or full
/// policy evaluation.
#[derive(Debug)]
pub struct DecisionAuditWrite<'a> {
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub request: &'a AuthorizeRequest,
    pub decision_id: Uuid,
    pub decision: &'a str,
    pub risk_score: i32,
    pub reason: &'a str,
    pub matched_policies: &'a [String],
    pub audit_event_type: &'a str,
    pub started_at: Instant,
    pub dry_run: bool,
    pub action_hash: &'a str,
    pub root_trust_level: &'a str,
}
