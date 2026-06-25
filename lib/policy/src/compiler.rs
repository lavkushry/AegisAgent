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
}
