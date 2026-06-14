use crate::models::AuthorizeRequest;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Cedar parsing error: {0}")]
    Parse(String),
    #[error("Entity UID creation error: {0}")]
    EntityUid(String),
    #[error("Context validation error: {0}")]
    Context(String),
    #[error("File access error: {0}")]
    File(String),
}

pub struct PolicyEngine {
    base_policy_set: RwLock<PolicySet>,
    tenant_policy_sets: RwLock<HashMap<String, PolicySet>>,
}

impl PolicyEngine {
    pub async fn init<P: AsRef<Path>>(policy_path: P) -> Result<Self, PolicyError> {
        let policy_str = tokio::fs::read_to_string(policy_path)
            .await
            .map_err(|e| PolicyError::File(e.to_string()))?;

        let policy_set =
            PolicySet::from_str(&policy_str).map_err(|e| PolicyError::Parse(e.to_string()))?;

        Ok(Self {
            base_policy_set: RwLock::new(policy_set),
            tenant_policy_sets: RwLock::new(HashMap::new()),
        })
    }

    pub fn has_tenant(&self, tenant_id: &str) -> bool {
        let sets = self
            .tenant_policy_sets
            .read()
            .unwrap_or_else(|e| e.into_inner());
        sets.contains_key(tenant_id)
    }

    pub async fn reload_tenant_policies(
        &self,
        pool: &sqlx::SqlitePool,
        tenant_id: &str,
    ) -> Result<(), PolicyError> {
        let db_policies = crate::db::list_policies(pool, tenant_id)
            .await
            .map_err(|e| PolicyError::File(e.to_string()))?;

        // Rebuild policy set for this tenant.
        // Start with the base policy set
        let mut policy_set = {
            let base = self
                .base_policy_set
                .read()
                .unwrap_or_else(|e| e.into_inner());
            base.clone()
        };

        // Append each active policy from the database
        for policy_rec in db_policies {
            if policy_rec.status != "active" {
                continue;
            }
            // Parse Cedar policy from the body string
            let custom_set = PolicySet::from_str(&policy_rec.body).map_err(|e| {
                PolicyError::Parse(format!(
                    "Failed to parse custom policy '{}': {}",
                    policy_rec.id, e
                ))
            })?;

            // Merge custom rules into policy_set
            for p in custom_set.policies() {
                policy_set.add(p.clone()).map_err(|e| {
                    PolicyError::Parse(format!(
                        "Failed to add custom policy '{}': {}",
                        policy_rec.id, e
                    ))
                })?;
            }
        }

        // Write the rebuilt policy set to our thread-safe map
        let mut sets = self
            .tenant_policy_sets
            .write()
            .unwrap_or_else(|e| e.into_inner());
        sets.insert(tenant_id.to_string(), policy_set);

        Ok(())
    }

    pub async fn reload_file<P: AsRef<Path>>(&self, policy_path: P) -> Result<(), PolicyError> {
        let policy_str = tokio::fs::read_to_string(policy_path)
            .await
            .map_err(|e| PolicyError::File(e.to_string()))?;

        let policy_set =
            PolicySet::from_str(&policy_str).map_err(|e| PolicyError::Parse(e.to_string()))?;

        // Update the base policy set
        {
            let mut base = self
                .base_policy_set
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *base = policy_set;
        }

        // Clear cached tenant policy sets as base policies changed
        {
            let mut sets = self
                .tenant_policy_sets
                .write()
                .unwrap_or_else(|e| e.into_inner());
            sets.clear();
        }

        Ok(())
    }

    pub fn authorize(
        &self,
        tenant_id: &str,
        auth_req: &AuthorizeRequest,
    ) -> Result<AuthorizeDecision, PolicyError> {
        let authorizer = Authorizer::new();

        // Construct Entity UIDs matching Cedar policy structures
        // Principal: Agent::"agent_id"
        let principal_uid = EntityUid::from_str(&format!("Agent::\"{}\"", auth_req.agent.id))
            .map_err(|e| PolicyError::EntityUid(e.to_string()))?;

        // Action: Action::"tool_call"
        let action_uid = EntityUid::from_str("Action::\"tool_call\"")
            .map_err(|e| PolicyError::EntityUid(e.to_string()))?;

        // Resource: ToolAction::"tool_action"
        let resource_uid = EntityUid::from_str(&format!(
            "ToolAction::\"{}_{}\"",
            auth_req.tool_call.tool, auth_req.tool_call.action
        ))
        .map_err(|e| PolicyError::EntityUid(e.to_string()))?;

        // Context: Construct from AuthorizeRequest's dynamic context and tool call details
        let context_json = serde_json::json!({
            "trust_level": auth_req.context.source_trust,
            "contains_sensitive_data": auth_req.context.contains_sensitive_data,
            "mutates_state": auth_req.tool_call.mutates_state,
            "resource_base_branch": auth_req.tool_call.parameters.get("base_branch").and_then(|v| v.as_str()).unwrap_or(""),
        });

        let context = Context::from_json_value(context_json, None)
            .map_err(|e| PolicyError::Context(e.to_string()))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            context,
            None,
        )
        .map_err(|e| PolicyError::Context(e.to_string()))?;

        // We use empty entities for now as we evaluate policies based on request context attributes
        let entities = Entities::empty();

        // Read lock to get this tenant's policy set
        let sets = self
            .tenant_policy_sets
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let policy_set = sets.get(tenant_id).cloned().unwrap_or_else(|| {
            let base = self
                .base_policy_set
                .read()
                .unwrap_or_else(|e| e.into_inner());
            base.clone()
        });

        let response = authorizer.is_authorized(&request, &policy_set, &entities);

        let mut decision = match response.decision() {
            Decision::Allow => "allow".to_string(),
            Decision::Deny => "deny".to_string(),
        };

        let mut matched_policies = Vec::new();
        let mut approver_group = None;
        let mut reason = "Policy evaluation complete.".to_string();

        for policy_id in response.diagnostics().reason() {
            matched_policies.push(policy_id.to_string());
            if let Some(policy) = policy_set.policy(policy_id) {
                // If the decision is ALLOW but any of the satisfied policies annotations indicate
                // `require_approval`, override the binary decision to `require_approval`.
                if decision == "allow" {
                    if let Some(dec) = policy.annotation("decision") {
                        // Strip quotes from annotation string representation
                        let dec_clean = dec.trim_matches('"');
                        if dec_clean == "require_approval" {
                            decision = "require_approval".to_string();
                        }
                    }
                }

                // Get the approver group annotation if present
                if let Some(group) = policy.annotation("approver_group") {
                    approver_group = Some(group.trim_matches('"').to_string());
                }

                // Get custom reason annotation if present
                if let Some(r) = policy.annotation("reason") {
                    reason = r.trim_matches('"').to_string();
                }
            }
        }

        Ok(AuthorizeDecision {
            decision,
            matched_policies,
            approver_group,
            reason,
        })
    }
}

pub struct AuthorizeDecision {
    pub decision: String,
    pub matched_policies: Vec<String>,
    pub approver_group: Option<String>,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthorizeAgentContext, AuthorizeDynamicContext, AuthorizeToolCall};

    async fn setup_engine() -> PolicyEngine {
        // Look for policies.cedar in the package root
        PolicyEngine::init("policies.cedar").await.unwrap()
    }

    fn mutating_request_at_trust(trust_level: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "create_branch".to_string(),
                resource: Some("repo/branch/1".to_string()),
                mutates_state: true,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: trust_level.to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        }
    }

    #[tokio::test]
    async fn test_trusted_internal_signed_mutation_allowed() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("trusted_internal_signed");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "allow");
    }

    #[tokio::test]
    async fn test_trusted_internal_unsigned_mutation_allowed() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("trusted_internal_unsigned");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "allow");
    }

    #[tokio::test]
    async fn test_semi_trusted_customer_mutation_requires_approval() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("semi_trusted_customer");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "require_approval");
    }

    #[tokio::test]
    async fn test_untrusted_external_mutation_denied() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("untrusted_external");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "deny");
    }

    #[tokio::test]
    async fn test_malicious_suspected_mutation_denied() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("malicious_suspected");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "deny");
    }

    #[tokio::test]
    async fn test_unknown_mutation_denied() {
        let engine = setup_engine().await;
        let request = mutating_request_at_trust("unknown");
        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "deny");
    }

    #[tokio::test]
    async fn test_readonly_allowed() {
        let engine = setup_engine().await;
        let request = AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "read_issue".to_string(),
                resource: Some("repo/pr/1".to_string()),
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "untrusted_external".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "allow");
    }

    #[tokio::test]
    async fn test_main_branch_merge_requires_approval() {
        let engine = setup_engine().await;
        let request = AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "merge_pull_request".to_string(),
                resource: Some("repo/pr/1".to_string()),
                mutates_state: true,
                parameters: serde_json::json!({
                    "base_branch": "main"
                }),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "require_approval");
        assert_eq!(result.approver_group, Some("platform-leads".to_string()));
    }

    #[tokio::test]
    async fn test_untrusted_context_mutation_forbidden() {
        let engine = setup_engine().await;
        let request = AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "create_branch".to_string(),
                resource: Some("repo/branch/1".to_string()),
                mutates_state: true,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "untrusted_external".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "deny");
    }

    #[tokio::test]
    async fn test_customer_context_mutation_requires_approval() {
        let engine = setup_engine().await;
        let request = AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "create_branch".to_string(),
                resource: Some("repo/branch/1".to_string()),
                mutates_state: true,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "semi_trusted_customer".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "require_approval");
        assert_eq!(
            result.approver_group,
            Some("security-reviewers".to_string())
        );
    }
}
