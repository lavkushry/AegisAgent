use crate::models::AuthorizeRequest;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;
use unicode_normalization::UnicodeNormalization;

/// Normalize a tool or action identifier before building the Cedar entity UID.
/// Applies the same algorithm as `routes::normalize_tool_identifier`:
/// percent-decode → Unicode NFC → trim whitespace → lowercase.
/// This prevents case/encoding/Unicode-form variations from bypassing Cedar
/// deny rules (e.g. `GitHub` and `github` must match the same policy).
fn normalize_policy_identifier(value: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| value.to_string());
    decoded.nfc().collect::<String>().trim().to_lowercase()
}

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
    /// Raw Cedar source of the base policy set (#1352). Kept alongside the
    /// parsed `base_policy_set` so [`Self::reload_tenant_policies`] can
    /// re-parse the base text together with a tenant's custom policy bodies
    /// in a single [`PolicySet::from_str`] call, avoiding the `policy0..N`
    /// auto-id collisions that occur when each policy source is parsed
    /// independently and then merged via [`PolicySet::add`].
    base_policy_src: RwLock<String>,
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
            base_policy_src: RwLock::new(policy_str),
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

        // Rebuild policy set for this tenant by re-parsing the base policy
        // source together with each active custom policy's source in a
        // single `PolicySet::from_str` call (#1352). Parsing each policy
        // body independently (the prior approach) assigns auto-generated
        // ids starting from `policy0` for every source, so merging a
        // separately-parsed custom `PolicySet` into the base set via
        // `PolicySet::add` collides with the base set's own `policy0..N`
        // ids and fails with "duplicate template or policy id". A single
        // combined-source parse assigns globally-unique sequential ids.
        let mut combined_src = {
            let base = self
                .base_policy_src
                .read()
                .unwrap_or_else(|e| e.into_inner());
            base.clone()
        };

        for policy_rec in &db_policies {
            if policy_rec.status != "active" {
                continue;
            }
            // Validate the custom policy parses on its own before merging,
            // so a malformed policy is attributed to its own id rather than
            // surfacing as an opaque error against the combined source.
            PolicySet::from_str(&policy_rec.body).map_err(|e| {
                PolicyError::Parse(format!(
                    "Failed to parse custom policy '{}': {}",
                    policy_rec.id, e
                ))
            })?;

            combined_src.push('\n');
            combined_src.push_str(&policy_rec.body);
        }

        let policy_set = PolicySet::from_str(&combined_src).map_err(|e| {
            PolicyError::Parse(format!(
                "Failed to parse combined policy set for tenant '{}': {}",
                tenant_id, e
            ))
        })?;

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

        // Update the base policy set and its raw source
        {
            let mut base = self
                .base_policy_set
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *base = policy_set;
        }
        {
            let mut src = self
                .base_policy_src
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *src = policy_str;
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

        // Resource: ToolAction::"tool_action" — normalize before Cedar evaluation
        // (#1384) so percent-encoding, letter-case, or Unicode-form variation cannot
        // bypass deny policies (e.g., `GitHub` and `github` resolve identically).
        let resource_uid = EntityUid::from_str(&format!(
            "ToolAction::\"{}_{}\"",
            normalize_policy_identifier(&auth_req.tool_call.tool),
            normalize_policy_identifier(&auth_req.tool_call.action)
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
                // Escalate the binary Cedar `allow` using annotation overrides.
                // Severity order: quarantine > require_approval > allow.
                // Only escalate — never de-escalate a more severe decision.
                if matches!(decision.as_str(), "allow" | "require_approval") {
                    if let Some(dec) = policy.annotation("decision") {
                        // Strip quotes from annotation string representation
                        let dec_clean = dec.trim_matches('"');
                        match dec_clean {
                            "quarantine" => decision = "quarantine".to_string(),
                            "require_approval" if decision == "allow" => {
                                decision = "require_approval".to_string();
                            }
                            _ => {}
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

    /// Regression test for #1352: a tenant with an active custom policy
    /// must successfully load (not error out and silently fall back to
    /// `base_policy_set`), and the custom policy must actually affect
    /// `authorize` decisions. The custom policy body below is parsed
    /// independently by `PolicySet::from_str`, which assigns it id
    /// `policy0` — the same id the base `policies.cedar` set assigns to
    /// its own first policy. Before the fix, merging this into a clone of
    /// the base set via `PolicySet::add` returned
    /// `Err("duplicate template or policy id")`, `reload_tenant_policies`
    /// propagated that error, and the caller (`let _ = ...`) silently
    /// ignored it — leaving the tenant on the base policy set forever.
    #[tokio::test]
    async fn test_reload_tenant_policies_with_custom_policy_succeeds_and_applies() {
        use crate::models::PolicyRecord;
        use chrono::Utc;
        use uuid::Uuid;

        std::fs::create_dir_all("target").unwrap();
        let db_url = format!("sqlite://target/policy_{}.db", Uuid::new_v4().simple());
        let pool = crate::db::init_db(&db_url).await.unwrap();
        let tenant_id = "tenant_custom_policy";
        crate::db::register_tenant(&pool, tenant_id, "Custom Policy Tenant", "developer")
            .await
            .unwrap();

        let engine = setup_engine().await;

        // Sanity check: without any custom policy, a read-only filesystem
        // action is allowed by the base policy set (see
        // `test_readonly_allowed` above).
        let readonly_request = AuthorizeRequest {
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
                tool: "filesystem".to_string(),
                action: "read_file".to_string(),
                resource: Some("/etc/hosts".to_string()),
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "untrusted_external".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };
        let before = engine.authorize(tenant_id, &readonly_request).unwrap();
        assert_eq!(before.decision, "allow");

        // Active custom policy: forbid the filesystem_read_file tool
        // action outright. Parsed on its own, this policy is assigned id
        // `policy0`, colliding with the base set's `policy0`.
        let policy = PolicyRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            policy_key: "deny_filesystem_read".to_string(),
            name: "Deny filesystem read".to_string(),
            language: "cedar".to_string(),
            body: "forbid(principal, action == Action::\"tool_call\", resource == ToolAction::\"filesystem_read_file\");".to_string(),
            version: 1,
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
        };
        crate::db::insert_policy(&pool, &policy).await.unwrap();

        // Must succeed (not Err("duplicate template or policy id")).
        engine
            .reload_tenant_policies(&pool, tenant_id)
            .await
            .unwrap();
        assert!(engine.has_tenant(tenant_id));

        // The custom forbid must now take effect for this tenant.
        let after = engine.authorize(tenant_id, &readonly_request).unwrap();
        assert_eq!(after.decision, "deny");
    }

    /// #1386: the `@decision("quarantine")` annotation on a permit rule overrides
    /// the Cedar `allow` decision with `quarantine`. Calling the canary endpoint
    /// (`quarantine_canary_trigger`) must return `decision == "quarantine"` via
    /// the annotation escalation path.
    #[tokio::test]
    async fn test_quarantine_annotation_overrides_allow() {
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
                tool: "quarantine_canary".to_string(),
                action: "trigger".to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize("test_tenant", &request).unwrap();
        assert_eq!(result.decision, "quarantine");
    }

    /// #1386: `quarantine` is more severe than `require_approval` — if a policy
    /// set produces both annotations on different matched rules, the final decision
    /// must be `quarantine` (not `require_approval`).
    #[tokio::test]
    async fn test_quarantine_annotation_beats_require_approval() {
        use crate::models::PolicyRecord;
        use chrono::Utc;
        use uuid::Uuid;

        let engine = setup_engine().await;

        // Register a tenant with a custom `require_approval` policy so that
        // two policies match: the quarantine canary permit + a custom
        // `require_approval` permit for the same resource.
        let run_id = Uuid::new_v4().simple().to_string();
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!("sqlite://target/policy_quarantine_beats_{}.db", run_id);
        let pool = crate::db::init_db(&db_url).await.unwrap();
        let tenant_id_owned = format!("tenant_quarantine_beats_{}", &run_id[..8]);
        let tenant_id = tenant_id_owned.as_str();
        crate::db::register_tenant(&pool, tenant_id, "QA Tenant", "developer")
            .await
            .unwrap();

        let extra_policy = PolicyRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            policy_key: "also_require_approval".to_string(),
            name: "Also require approval".to_string(),
            language: "cedar".to_string(),
            body: r#"@decision("require_approval") permit(principal, action == Action::"tool_call", resource == ToolAction::"quarantine_canary_trigger") when { context.mutates_state == false };"#.to_string(),
            version: 1,
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
        };
        crate::db::insert_policy(&pool, &extra_policy)
            .await
            .unwrap();
        engine
            .reload_tenant_policies(&pool, tenant_id)
            .await
            .unwrap();

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
                tool: "quarantine_canary".to_string(),
                action: "trigger".to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let result = engine.authorize(tenant_id, &request).unwrap();
        assert_eq!(result.decision, "quarantine");
    }

    // --- #1384: normalize_policy_identifier unit tests ---

    #[test]
    fn normalize_policy_identifier_lowercases() {
        assert_eq!(normalize_policy_identifier("GitHub"), "github");
        assert_eq!(normalize_policy_identifier("FILESYSTEM"), "filesystem");
        assert_eq!(normalize_policy_identifier("MixedCase"), "mixedcase");
    }

    #[test]
    fn normalize_policy_identifier_percent_decodes() {
        assert_eq!(normalize_policy_identifier("git%20hub"), "git hub");
        assert_eq!(
            normalize_policy_identifier("merge%5Fpull%5Frequest"),
            "merge_pull_request"
        );
    }

    #[test]
    fn normalize_policy_identifier_trims_whitespace() {
        assert_eq!(normalize_policy_identifier("  github  "), "github");
        assert_eq!(normalize_policy_identifier("\tread_file\n"), "read_file");
    }

    #[test]
    fn normalize_policy_identifier_already_normalized_is_idempotent() {
        let inputs = ["github", "merge_pull_request", "filesystem_read"];
        for s in &inputs {
            assert_eq!(&normalize_policy_identifier(s), s);
        }
    }

    /// #1384: A mixed-case tool name `GitHub`/`Merge_Pull_Request` must hit
    /// the same Cedar policy as the canonical lowercase form `github`/
    /// `merge_pull_request`. Without normalization the Cedar entity UID would
    /// be `ToolAction::"GitHub_Merge_Pull_Request"` which doesn't match the
    /// policy rule targeting `ToolAction::"github_merge_pull_request"`, making
    /// the approval gate bypassable via case variations.
    #[tokio::test]
    async fn mixed_case_tool_names_hit_same_cedar_policy_as_lowercase() {
        let engine = setup_engine().await;

        // Lowercase canonical form — must require approval (github_merge_pull_request
        // with base_branch == "main").
        let canonical = AuthorizeRequest {
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
                resource: Some("repo/pr/42".to_string()),
                mutates_state: true,
                parameters: serde_json::json!({ "base_branch": "main" }),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        // Mixed-case variant — must produce the same decision.
        let mixed_case = AuthorizeRequest {
            tool_call: AuthorizeToolCall {
                tool: "GitHub".to_string(),
                action: "Merge_Pull_Request".to_string(),
                ..canonical.tool_call.clone()
            },
            ..canonical.clone()
        };

        let canonical_result = engine.authorize("test_tenant", &canonical).unwrap();
        let mixed_result = engine.authorize("test_tenant", &mixed_case).unwrap();

        assert_eq!(canonical_result.decision, "require_approval");
        assert_eq!(
            mixed_result.decision, canonical_result.decision,
            "mixed-case tool names must produce the same Cedar decision as lowercase"
        );
    }
}
