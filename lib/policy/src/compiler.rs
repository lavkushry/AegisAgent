use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGuardPolicy {
    pub kind: String, // Must be "AgentGuardPolicy"
    pub metadata: PolicyMetadata,
    pub spec: PolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySpec {
    pub unknown_mcp_tools: Option<String>,          // "deny" | "allow" | "require_approval"
    pub production_mutations: Option<String>,        // "deny" | "allow" | "require_approval"
    pub untrusted_context_plus_write: Option<String>, // "deny" | "allow" | "require_approval"
    pub approval_timeout: Option<String>,            // "auto_deny" | "auto_allow"
    pub sensitive_data_to_public_tool: Option<String>, // "deny" | "allow" | "require_approval"
    #[serde(rename = "require_mTLS")]
    pub require_mtls: Option<bool>,
    pub quarantine_on_sensitive_data: Option<bool>,
    pub allowed_environments: Option<Vec<String>>,
    pub force_approval_for_all: Option<bool>,
    pub redact_fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub key: String,
    pub name: String,
    pub body: String,
}

pub fn get_templates() -> Vec<PolicyTemplate> {
    vec![
        PolicyTemplate {
            key: "production-baseline".to_string(),
            name: "Production Baseline".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: production-baseline
spec:
  unknownMcpTools: deny
  productionMutations: require_approval
  untrustedContextPlusWrite: deny
  require_mTLS: true
  allowedEnvironments:
    - production
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "read-only-access".to_string(),
            name: "Read-only Access".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: read-only-access
spec:
  unknownMcpTools: deny
  productionMutations: deny
  untrustedContextPlusWrite: deny
  forceApprovalForAll: true
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "strict-write-review".to_string(),
            name: "Strict Write Review".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: strict-write-review
spec:
  unknownMcpTools: require_approval
  productionMutations: require_approval
  untrustedContextPlusWrite: require_approval
  forceApprovalForAll: true
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "unrestricted-dev".to_string(),
            name: "Unrestricted Development".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: unrestricted-dev
spec:
  unknownMcpTools: allow
  productionMutations: allow
  untrustedContextPlusWrite: allow
  allowedEnvironments:
    - development
    - local
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "quarantine-on-untrusted-mutation".to_string(),
            name: "Quarantine on Untrusted Mutation".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: quarantine-on-untrusted-mutation
spec:
  untrustedContextPlusWrite: deny
  quarantineOnSensitiveData: true
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "redact-sensitive-credentials".to_string(),
            name: "Redact Sensitive Credentials".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: redact-sensitive-credentials
spec:
  redactFields:
    - api_key
    - password
    - secret
    - token
    - private_key
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "audit-only-mode".to_string(),
            name: "Audit-only Mode".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: audit-only-mode
spec:
  unknownMcpTools: allow
  productionMutations: allow
  untrustedContextPlusWrite: allow
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "fail-closed-default".to_string(),
            name: "Fail-closed Default".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: fail-closed-default
spec:
  unknownMcpTools: deny
  untrustedContextPlusWrite: deny
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "semi-trusted-customer-review".to_string(),
            name: "Semi-trusted Customer Review".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: semi-trusted-customer-review
spec:
  untrustedContextPlusWrite: require_approval
"#
            .to_string(),
        },
        PolicyTemplate {
            key: "escalated-risk-human-gate".to_string(),
            name: "Escalated Risk Human Gate".to_string(),
            body: r#"kind: AgentGuardPolicy
metadata:
  name: escalated-risk-human-gate
spec:
  forceApprovalForAll: true
  quarantineOnSensitiveData: true
"#
            .to_string(),
        },
    ]
}

pub fn compile_yaml_to_cedar(yaml_str: &str) -> Result<String, String> {
    let policy: AgentGuardPolicy = serde_yml::from_str(yaml_str)
        .map_err(|e| format!("YAML parsing error: {}", e))?;

    if policy.kind != "AgentGuardPolicy" {
        return Err("Invalid policy kind. Expected 'AgentGuardPolicy'".to_string());
    }

    let mut cedar_rules = Vec::new();
    let spec = &policy.spec;

    // 1. unknown_mcp_tools
    if let Some(val) = &spec.unknown_mcp_tools {
        match val.as_str() {
            "deny" => {
                cedar_rules.push(
                    "forbid (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.is_mcp_tool_known == false\n};".to_string()
                );
            }
            "require_approval" => {
                cedar_rules.push(
                    "@decision(\"require_approval\")\n@reason(\"Unknown MCP tools require human review\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.is_mcp_tool_known == false\n};".to_string()
                );
            }
            "allow" => {
                cedar_rules.push(
                    "permit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.is_mcp_tool_known == false\n};".to_string()
                );
            }
            _ => return Err(format!("Invalid value for unknown_mcp_tools: '{}'. Expected 'deny', 'allow', or 'require_approval'", val)),
        }
    }

    // 2. production_mutations
    if let Some(val) = &spec.production_mutations {
        match val.as_str() {
            "deny" => {
                cedar_rules.push(
                    "forbid (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    context.environment == \"production\"\n};".to_string()
                );
            }
            "require_approval" => {
                cedar_rules.push(
                    "@decision(\"require_approval\")\n@reason(\"Production mutating actions require human review\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    context.environment == \"production\"\n};".to_string()
                );
            }
            "allow" => {
                cedar_rules.push(
                    "permit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    context.environment == \"production\"\n};".to_string()
                );
            }
            _ => return Err(format!("Invalid value for production_mutations: '{}'. Expected 'deny', 'allow', or 'require_approval'", val)),
        }
    }

    // 3. untrusted_context_plus_write
    if let Some(val) = &spec.untrusted_context_plus_write {
        match val.as_str() {
            "deny" => {
                cedar_rules.push(
                    "forbid (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    (\n        context.trust_level == \"untrusted_external\" ||\n        context.trust_level == \"malicious_suspected\" ||\n        context.trust_level == \"unknown\"\n    )\n};".to_string()
                );
            }
            "require_approval" => {
                cedar_rules.push(
                    "@decision(\"require_approval\")\n@reason(\"Mutations triggered by untrusted context require human review\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    (\n        context.trust_level == \"untrusted_external\" ||\n        context.trust_level == \"malicious_suspected\" ||\n        context.trust_level == \"unknown\"\n    )\n};".to_string()
                );
            }
            "allow" => {
                cedar_rules.push(
                    "permit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true &&\n    (\n        context.trust_level == \"untrusted_external\" ||\n        context.trust_level == \"malicious_suspected\" ||\n        context.trust_level == \"unknown\"\n    )\n};".to_string()
                );
            }
            _ => return Err(format!("Invalid value for untrusted_context_plus_write: '{}'. Expected 'deny', 'allow', or 'require_approval'", val)),
        }
    }

    // 4. require_mTLS
    if let Some(true) = spec.require_mtls {
        cedar_rules.push(
            "forbid (\n    principal,\n    action,\n    resource\n)\nwhen {\n    context.is_mtls == false\n};".to_string()
        );
    }

    // 5. quarantine_on_sensitive_data
    if let Some(true) = spec.quarantine_on_sensitive_data {
        cedar_rules.push(
            "@decision(\"quarantine\")\n@reason(\"Sensitive data detected in tool call — agent quarantined\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.contains_sensitive_data == true\n};".to_string()
        );
    }

    // 6. allowed_environments
    if let Some(envs) = &spec.allowed_environments {
        if envs.is_empty() {
            return Err("allowed_environments list cannot be empty if specified".to_string());
        }
        let env_conditions: Vec<String> = envs
            .iter()
            .map(|e| format!("context.environment == \"{}\"", e))
            .collect();
        let condition_str = env_conditions.join(" || ");
        cedar_rules.push(
            format!("forbid (\n    principal,\n    action,\n    resource\n)\nwhen {{\n    !({})\n}};", condition_str)
        );
    }

    // 7. force_approval_for_all
    if let Some(true) = spec.force_approval_for_all {
        cedar_rules.push(
            "@decision(\"require_approval\")\n@reason(\"Operator forced approval for all mutating actions\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {\n    context.mutates_state == true\n};".to_string()
        );
    }

    // 8. redact_fields
    if let Some(fields) = &spec.redact_fields {
        if fields.is_empty() {
            return Err("redact_fields list cannot be empty if specified".to_string());
        }
        let fields_str = fields.join(",");
        cedar_rules.push(
            format!("@decision(\"redact\")\n@redact_fields(\"{}\")\n@reason(\"Automated redaction of sensitive parameters\")\npermit (\n    principal,\n    action == Action::\"tool_call\",\n    resource\n)\nwhen {{\n    true\n}};", fields_str)
        );
    }

    Ok(cedar_rules.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_production_baseline() {
        let templates = get_templates();
        let baseline = templates.iter().find(|t| t.key == "production-baseline").unwrap();
        let compiled = compile_yaml_to_cedar(&baseline.body).unwrap();
        
        assert!(compiled.contains("context.is_mcp_tool_known == false"));
        assert!(compiled.contains("context.mutates_state == true &&\n    context.environment == \"production\""));
        assert!(compiled.contains("context.is_mtls == false"));
        assert!(compiled.contains("!(context.environment == \"production\")"));
    }

    #[test]
    fn test_compile_invalid_kind() {
        let invalid_yaml = r#"kind: InvalidKind
metadata:
  name: test
spec: {}
"#;
        let err = compile_yaml_to_cedar(invalid_yaml).unwrap_err();
        assert!(err.contains("Invalid policy kind"));
    }

    #[test]
    fn test_compile_invalid_field_value() {
        let invalid_yaml = r#"kind: AgentGuardPolicy
metadata:
  name: test
spec:
  unknownMcpTools: invalid_value
"#;
        let err = compile_yaml_to_cedar(invalid_yaml).unwrap_err();
        assert!(err.contains("Invalid value for unknown_mcp_tools"));
    }

    // ── #1328: YAML -> Cedar -> evaluate round-trip ─────────────────────────
    //
    // The unit tests above only check the *generated Cedar text* contains the
    // right substrings. They don't prove the compiled Cedar actually behaves
    // as intended once loaded into the real Cedar authorizer — a correct-
    // looking string could still evaluate wrong (e.g. a forbid/permit
    // precedence bug, or an annotation that never gets read). These tests
    // close that gap: every template is compiled, loaded into a real
    // `PolicyEngine`, and evaluated against >=20 request scenarios with an
    // expected decision asserted against each. `production_baseline_*`
    // additionally evaluates the same requests against an independently
    // hand-written Cedar policy (not derived from the compiler's source) and
    // asserts identical decisions — the literal "compiled YAML == equivalent
    // Cedar" comparison from the issue's acceptance criteria.
    mod round_trip {
        use super::*;
        use crate::cedar::PolicyEngine;
        use aegis_api::models::{
            AuthorizeAgentContext, AuthorizeDynamicContext, AuthorizeRequest, AuthorizeToolCall,
        };

        /// Loads `cedar_src` as a *standalone* policy set (no base
        /// `policies.cedar` mixed in) so each template's behavior is tested
        /// in isolation.
        ///
        /// Uses `tempfile::Builder` rather than a predictable path under
        /// `std::env::temp_dir()` (a shared, world-writable directory):
        /// `NamedTempFile` atomically creates a uniquely-named file with
        /// restricted permissions and cleans it up on drop.
        async fn engine_from_cedar(cedar_src: &str) -> PolicyEngine {
            let file = tempfile::Builder::new()
                .prefix("aegis-rt-test-")
                .suffix(".cedar")
                .tempfile()
                .unwrap();
            tokio::fs::write(file.path(), cedar_src).await.unwrap();
            PolicyEngine::init(file.path()).await.unwrap()
        }

        fn compile_template(key: &str) -> String {
            let templates = get_templates();
            let template = templates.iter().find(|t| t.key == key).unwrap();
            compile_yaml_to_cedar(&template.body).unwrap()
        }

        #[allow(clippy::too_many_arguments)]
        fn request(
            tool: &str,
            action: &str,
            mutates_state: bool,
            source_trust: &str,
            environment: &str,
            contains_sensitive_data: bool,
        ) -> AuthorizeRequest {
            AuthorizeRequest {
                request_id: None,
                callback: None,
                nonce: None,
                timestamp: None,
                dry_run: None,
                agent: AuthorizeAgentContext {
                    id: "round-trip-agent".to_string(),
                    environment: environment.to_string(),
                },
                user: None,
                tool_call: AuthorizeToolCall {
                    tool: tool.to_string(),
                    action: action.to_string(),
                    resource: None,
                    mutates_state,
                    parameters: serde_json::json!({}),
                },
                context: AuthorizeDynamicContext {
                    source_trust: source_trust.to_string(),
                    contains_sensitive_data,
                },
                trace: None,
            }
        }

        /// `(is_tool_known, is_mtls)` default to the "this request is
        /// otherwise unremarkable" case — known tool, valid mTLS — so each
        /// scenario only has to vary the field it's actually exercising.
        async fn decide(
            engine: &PolicyEngine,
            req: &AuthorizeRequest,
            is_tool_known: bool,
            is_mtls: bool,
        ) -> String {
            engine
                .authorize("round_trip_tenant", req, "low", is_tool_known, is_mtls)
                .unwrap()
                .decision
        }

        #[tokio::test]
        async fn production_baseline_unknown_tool_denied() {
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, false, true).await, "deny");
        }

        #[tokio::test]
        async fn production_baseline_known_tool_production_mutation_requires_approval() {
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request(
                "github",
                "merge",
                true,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn production_baseline_untrusted_mutation_denied_even_though_also_require_approval() {
            // Forbid must win over a simultaneously-matching require_approval
            // permit (production_mutations) — Cedar's deny-overrides-permit
            // semantics, not "last rule wins" or "most specific wins".
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request("github", "merge", true, "untrusted_external", "production", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn production_baseline_missing_mtls_denied_regardless_of_action() {
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, false).await, "deny");
        }

        #[tokio::test]
        async fn production_baseline_disallowed_environment_denied() {
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "staging", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn production_baseline_unremarkable_request_falls_through_to_default_deny() {
            // None of the five rules' conditions match (known tool, no
            // mutation, trusted source, allowed environment, valid mTLS) —
            // and the template has no unconditional `permit`, so Cedar's
            // default-deny applies. This is the case most likely to be
            // mistaken for "allow" if the compiler ever added an implicit
            // catch-all permit.
            let engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        /// Independently hand-written Cedar for the production-baseline
        /// spec's intent (combined into single forbid/permit blocks with OR
        /// conditions, rather than five separate rule blocks like the
        /// compiler emits) — a structurally different encoding of the same
        /// policy, used to prove the compiled output isn't just internally
        /// self-consistent but matches what a Cedar-fluent engineer would
        /// independently write for this spec.
        fn hand_written_production_baseline() -> &'static str {
            r#"
forbid (principal, action == Action::"tool_call", resource)
when {
    context.is_mcp_tool_known == false ||
    context.is_mtls == false ||
    context.environment != "production"
};

@decision("require_approval")
permit (principal, action == Action::"tool_call", resource)
when {
    context.mutates_state == true &&
    context.environment == "production"
};

forbid (principal, action == Action::"tool_call", resource)
when {
    context.mutates_state == true &&
    (
        context.trust_level == "untrusted_external" ||
        context.trust_level == "malicious_suspected" ||
        context.trust_level == "unknown"
    )
};
"#
        }

        #[tokio::test]
        async fn production_baseline_compiled_matches_hand_written_equivalent() {
            let compiled_engine = engine_from_cedar(&compile_template("production-baseline")).await;
            let hand_written_engine = engine_from_cedar(hand_written_production_baseline()).await;

            let scenarios = [
                request(
                    "github",
                    "read",
                    false,
                    "trusted_internal_signed",
                    "production",
                    false,
                ), // unknown tool case driven by is_tool_known below
                request(
                    "github",
                    "merge",
                    true,
                    "trusted_internal_signed",
                    "production",
                    false,
                ),
                request(
                    "github",
                    "merge",
                    true,
                    "untrusted_external",
                    "production",
                    false,
                ),
                request(
                    "github",
                    "read",
                    false,
                    "trusted_internal_signed",
                    "production",
                    false,
                ),
                request(
                    "github",
                    "read",
                    false,
                    "trusted_internal_signed",
                    "staging",
                    false,
                ),
                request(
                    "github",
                    "read",
                    false,
                    "trusted_internal_signed",
                    "production",
                    false,
                ),
            ];
            let is_tool_known = [false, true, true, true, true, true];
            let is_mtls = [true, true, true, false, true, true];

            for i in 0..scenarios.len() {
                let compiled_decision =
                    decide(&compiled_engine, &scenarios[i], is_tool_known[i], is_mtls[i]).await;
                let hand_written_decision = decide(
                    &hand_written_engine,
                    &scenarios[i],
                    is_tool_known[i],
                    is_mtls[i],
                )
                .await;
                assert_eq!(
                    compiled_decision, hand_written_decision,
                    "scenario {i}: compiled YAML->Cedar and hand-written Cedar must agree"
                );
            }
        }

        #[tokio::test]
        async fn read_only_access_unknown_tool_denied() {
            let engine = engine_from_cedar(&compile_template("read-only-access")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, false, true).await, "deny");
        }

        #[tokio::test]
        async fn read_only_access_production_mutation_denied_despite_force_approval() {
            // forbid (production_mutations) must win over the require_approval
            // permit (force_approval_for_all) that also matches.
            let engine = engine_from_cedar(&compile_template("read-only-access")).await;
            let req = request(
                "github",
                "merge",
                true,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn read_only_access_untrusted_mutation_denied() {
            let engine = engine_from_cedar(&compile_template("read-only-access")).await;
            let req = request("github", "merge", true, "malicious_suspected", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn read_only_access_non_production_mutation_requires_approval() {
            // Neither forbid (unknown tool / production mutation / untrusted
            // write) applies, so force_approval_for_all's permit is the only
            // match.
            let engine = engine_from_cedar(&compile_template("read-only-access")).await;
            let req = request("github", "merge", true, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn strict_write_review_unknown_tool_requires_approval() {
            let engine = engine_from_cedar(&compile_template("strict-write-review")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, false, true).await, "require_approval");
        }

        #[tokio::test]
        async fn strict_write_review_production_mutation_requires_approval() {
            let engine = engine_from_cedar(&compile_template("strict-write-review")).await;
            let req = request(
                "github",
                "merge",
                true,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn strict_write_review_untrusted_mutation_requires_approval() {
            let engine = engine_from_cedar(&compile_template("strict-write-review")).await;
            let req = request("github", "merge", true, "malicious_suspected", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn strict_write_review_unremarkable_request_falls_through_to_default_deny() {
            // No forbids in this template at all (every field is
            // require_approval), so an unremarkable request that matches none
            // of the three conditional permits has no matching policy —
            // Cedar's default-deny, not "allow by absence of a forbid".
            let engine = engine_from_cedar(&compile_template("strict-write-review")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn unrestricted_dev_unknown_tool_in_allowed_env_is_allowed() {
            let engine = engine_from_cedar(&compile_template("unrestricted-dev")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "development",
                false,
            );
            assert_eq!(decide(&engine, &req, false, true).await, "allow");
        }

        #[tokio::test]
        async fn unrestricted_dev_disallowed_environment_denied_despite_allow_rules() {
            // allowed_environments' forbid must win over the unconditional
            // "allow" permits from the other three fields.
            let engine = engine_from_cedar(&compile_template("unrestricted-dev")).await;
            let req = request(
                "github",
                "merge",
                true,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn unrestricted_dev_untrusted_mutation_in_allowed_env_is_allowed() {
            let engine = engine_from_cedar(&compile_template("unrestricted-dev")).await;
            let req = request("github", "merge", true, "untrusted_external", "local", false);
            assert_eq!(decide(&engine, &req, true, true).await, "allow");
        }

        #[tokio::test]
        async fn unrestricted_dev_unremarkable_request_falls_through_to_default_deny() {
            // This template only allows specific risky categories (unknown
            // tool / mutation / untrusted-trust mutation); a plain read in an
            // allowed environment matches none of them.
            let engine = engine_from_cedar(&compile_template("unrestricted-dev")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "development",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn quarantine_on_untrusted_mutation_untrusted_write_denied() {
            let engine =
                engine_from_cedar(&compile_template("quarantine-on-untrusted-mutation")).await;
            let req = request("github", "merge", true, "untrusted_external", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn quarantine_on_untrusted_mutation_sensitive_data_quarantined() {
            let engine =
                engine_from_cedar(&compile_template("quarantine-on-untrusted-mutation")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", true);
            assert_eq!(decide(&engine, &req, true, true).await, "quarantine");
        }

        #[tokio::test]
        async fn quarantine_on_untrusted_mutation_forbid_wins_over_quarantine_annotation() {
            // A request that matches BOTH the untrusted-write forbid and the
            // sensitive-data quarantine permit must end up denied — a forbid
            // is final and must never be downgraded to (or coexist with) a
            // quarantine annotation from a separately-matching permit.
            let engine =
                engine_from_cedar(&compile_template("quarantine-on-untrusted-mutation")).await;
            let req = request("github", "merge", true, "untrusted_external", "dev", true);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn redact_sensitive_credentials_always_redacts_with_configured_fields() {
            let engine = engine_from_cedar(&compile_template("redact-sensitive-credentials")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            let result = engine
                .authorize("round_trip_tenant", &req, "low", true, true)
                .unwrap();
            assert_eq!(result.decision, "redact");
            for field in ["api_key", "password", "secret", "token", "private_key"] {
                assert!(
                    result.redacted_fields.contains(&field.to_string()),
                    "expected {field} in redacted_fields, got {:?}",
                    result.redacted_fields
                );
            }
        }

        #[tokio::test]
        async fn redact_sensitive_credentials_unconditional_regardless_of_request_shape() {
            let engine = engine_from_cedar(&compile_template("redact-sensitive-credentials")).await;
            let req = request("github", "merge", true, "untrusted_external", "production", true);
            let result = engine
                .authorize("round_trip_tenant", &req, "low", true, true)
                .unwrap();
            assert_eq!(result.decision, "redact");
        }

        #[tokio::test]
        async fn audit_only_mode_unknown_tool_allowed() {
            let engine = engine_from_cedar(&compile_template("audit-only-mode")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, false, true).await, "allow");
        }

        #[tokio::test]
        async fn audit_only_mode_production_mutation_allowed() {
            let engine = engine_from_cedar(&compile_template("audit-only-mode")).await;
            let req = request(
                "github",
                "merge",
                true,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "allow");
        }

        #[tokio::test]
        async fn audit_only_mode_untrusted_mutation_allowed() {
            let engine = engine_from_cedar(&compile_template("audit-only-mode")).await;
            let req = request("github", "merge", true, "malicious_suspected", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "allow");
        }

        #[tokio::test]
        async fn audit_only_mode_unremarkable_request_falls_through_to_default_deny() {
            // "Audit-only" allows the three named risky categories, not
            // everything — a plain non-mutating, trusted, known-tool read
            // matches none of them and falls to Cedar's default-deny.
            let engine = engine_from_cedar(&compile_template("audit-only-mode")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn fail_closed_default_unknown_tool_denied() {
            let engine = engine_from_cedar(&compile_template("fail-closed-default")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, false, true).await, "deny");
        }

        #[tokio::test]
        async fn fail_closed_default_untrusted_mutation_denied() {
            let engine = engine_from_cedar(&compile_template("fail-closed-default")).await;
            let req = request("github", "merge", true, "untrusted_external", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn fail_closed_default_has_no_allow_path_at_all() {
            // This template defines only two `forbid`s and zero `permit`s —
            // even the most unremarkable, fully-trusted, non-mutating request
            // denies, because nothing in the policy set ever grants `allow`.
            let engine = engine_from_cedar(&compile_template("fail-closed-default")).await;
            let req = request(
                "github",
                "read",
                false,
                "trusted_internal_signed",
                "production",
                false,
            );
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn semi_trusted_customer_review_untrusted_write_requires_approval() {
            let engine = engine_from_cedar(&compile_template("semi-trusted-customer-review")).await;
            let req = request("github", "merge", true, "untrusted_external", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn semi_trusted_customer_review_does_not_actually_match_its_namesake_trust_level() {
            // untrusted_context_plus_write's condition only checks
            // {untrusted_external, malicious_suspected, unknown} —
            // "semi_trusted_customer" trust itself isn't in that set despite
            // the template's name, so this falls through to default-deny
            // rather than require_approval. Documenting actual behavior, not
            // proposing a fix — out of scope for this round-trip test.
            let engine = engine_from_cedar(&compile_template("semi-trusted-customer-review")).await;
            let req = request("github", "merge", true, "semi_trusted_customer", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "deny");
        }

        #[tokio::test]
        async fn escalated_risk_human_gate_mutation_requires_approval() {
            let engine = engine_from_cedar(&compile_template("escalated-risk-human-gate")).await;
            let req = request("github", "merge", true, "trusted_internal_signed", "dev", false);
            assert_eq!(decide(&engine, &req, true, true).await, "require_approval");
        }

        #[tokio::test]
        async fn escalated_risk_human_gate_sensitive_data_quarantined() {
            let engine = engine_from_cedar(&compile_template("escalated-risk-human-gate")).await;
            let req = request("github", "read", false, "trusted_internal_signed", "dev", true);
            assert_eq!(decide(&engine, &req, true, true).await, "quarantine");
        }

        #[tokio::test]
        async fn escalated_risk_human_gate_mutation_plus_sensitive_data_escalates_to_quarantine() {
            // Both force_approval_for_all (require_approval) and
            // quarantine_on_sensitive_data (quarantine) match; quarantine is
            // the more severe annotation and must win regardless of which
            // policy Cedar's diagnostics happen to enumerate first.
            let engine = engine_from_cedar(&compile_template("escalated-risk-human-gate")).await;
            let req = request("github", "merge", true, "trusted_internal_signed", "dev", true);
            assert_eq!(decide(&engine, &req, true, true).await, "quarantine");
        }
    }
}
