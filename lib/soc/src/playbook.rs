use serde::{Deserialize, Serialize};
use aegis_api::models::{PlaybookRecord, AgentRecord};
use crate::correlate::Incident;
use aegis_common::errors::AegisError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TriggerSeverity {
    Single(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaybookTrigger {
    pub kind: String,
    pub severity: TriggerSeverity,
    pub agent_id: Option<String>,
    pub environment: Option<String>,
}

impl PlaybookTrigger {
    pub fn get_severities(&self) -> Vec<String> {
        match &self.severity {
            TriggerSeverity::Single(s) => vec![s.clone()],
            TriggerSeverity::List(l) => l.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PlaybookStep {
    FreezeAgent {
        reason: Option<String>,
    },
    ForceApproval,
    QuarantineMcp {
        server_key: String,
    },
    NotifySlack {
        webhook_url: String,
        channel: Option<String>,
        text: String,
    },
    NotifyWebhook {
        url: String,
        payload_template: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponsePlaybook {
    pub name: String,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
}

impl ResponsePlaybook {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Playbook name cannot be empty".to_string());
        }
        if self.trigger.kind.trim().is_empty() {
            return Err("Trigger kind cannot be empty".to_string());
        }
        let severities = self.trigger.get_severities();
        if severities.is_empty() {
            return Err("Trigger severity list cannot be empty".to_string());
        }
        for sev in &severities {
            match sev.as_str() {
                "info" | "low" | "medium" | "high" | "critical" => {}
                _ => return Err(format!(
                    "Invalid severity: '{sev}'. Expected one of: info, low, medium, high, critical"
                )),
            }
        }
        if self.steps.is_empty() {
            return Err("Playbook must contain at least one step".to_string());
        }
        for (i, step) in self.steps.iter().enumerate() {
            match step {
                PlaybookStep::FreezeAgent { .. } => {}
                PlaybookStep::ForceApproval => {}
                PlaybookStep::QuarantineMcp { server_key } => {
                    if server_key.trim().is_empty() {
                        return Err(format!("Step {i}: server_key cannot be empty in quarantine_mcp"));
                    }
                }
                PlaybookStep::NotifySlack { webhook_url, text, .. } => {
                    if webhook_url.trim().is_empty() {
                        return Err(format!("Step {i}: webhook_url cannot be empty in notify_slack"));
                    }
                    if text.trim().is_empty() {
                        return Err(format!("Step {i}: text cannot be empty in notify_slack"));
                    }
                }
                PlaybookStep::NotifyWebhook { url, .. } => {
                    if url.trim().is_empty() {
                        return Err(format!("Step {i}: url cannot be empty in notify_webhook"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn matches(&self, incident: &Incident, agent: &AgentRecord) -> bool {
        // Match kind
        if self.trigger.kind != incident.kind {
            return false;
        }

        // Match severity
        let severities = self.trigger.get_severities();
        if !severities.contains(&incident.severity) {
            return false;
        }

        // Match agent_id if specified
        if let Some(ref target_agent_id) = self.trigger.agent_id {
            if target_agent_id != &incident.agent_id && target_agent_id != &agent.agent_key {
                return false;
            }
        }

        // Match environment if specified
        if let Some(ref target_env) = self.trigger.environment {
            if target_env != &agent.environment {
                return false;
            }
        }

        true
    }

    pub fn from_record(record: &PlaybookRecord) -> Result<Self, serde_json::Error> {
        let trigger_severity: TriggerSeverity = serde_json::from_str(&record.trigger_severity)?;
        let steps: Vec<PlaybookStep> = serde_json::from_str(&record.steps_json)?;
        Ok(Self {
            name: record.name.clone(),
            trigger: PlaybookTrigger {
                kind: record.trigger_kind.clone(),
                severity: trigger_severity,
                agent_id: record.trigger_agent_id.clone(),
                environment: record.trigger_environment.clone(),
            },
            steps,
        })
    }
}

pub fn render_template(template: &str, incident: &Incident, agent: &AgentRecord) -> String {
    let mut rendered = template.to_string();
    
    // Incident variables
    rendered = rendered.replace("{{ incident.incident_id }}", &incident.incident_id);
    rendered = rendered.replace("{{ incident.tenant_id }}", &incident.tenant_id);
    rendered = rendered.replace("{{ incident.agent_id }}", &incident.agent_id);
    rendered = rendered.replace("{{ incident.kind }}", &incident.kind);
    rendered = rendered.replace("{{ incident.severity }}", &incident.severity);
    rendered = rendered.replace("{{ incident.summary }}", &incident.summary);
    rendered = rendered.replace("{{ incident.opened_at }}", &incident.opened_at);

    // Agent variables
    rendered = rendered.replace("{{ agent.id }}", &agent.id);
    rendered = rendered.replace("{{ agent.agent_key }}", &agent.agent_key);
    rendered = rendered.replace("{{ agent.name }}", &agent.name);
    rendered = rendered.replace("{{ agent.environment }}", &agent.environment);
    rendered = rendered.replace("{{ agent.risk_tier }}", &agent.risk_tier);
    rendered = rendered.replace("{{ agent.status }}", &agent.status);
    
    if let Some(ref reason) = agent.frozen_reason {
        rendered = rendered.replace("{{ agent.frozen_reason }}", reason);
    } else {
        rendered = rendered.replace("{{ agent.frozen_reason }}", "");
    }
    if let Some(ref team) = agent.owner_team {
        rendered = rendered.replace("{{ agent.owner_team }}", team);
    } else {
        rendered = rendered.replace("{{ agent.owner_team }}", "");
    }
    if let Some(ref email) = agent.owner_email {
        rendered = rendered.replace("{{ agent.owner_email }}", email);
    } else {
        rendered = rendered.replace("{{ agent.owner_email }}", "");
    }

    rendered
}

pub async fn execute_step(
    pool: &SqlitePool,
    step: &PlaybookStep,
    incident: &Incident,
    agent: &AgentRecord,
) -> Result<(), AegisError> {
    match step {
        PlaybookStep::FreezeAgent { reason } => {
            let default_reason = format!("auto-response: playbook freeze");
            let rendered_reason = reason.as_ref()
                .map(|r| render_template(r, incident, agent))
                .unwrap_or(default_reason);

            aegis_storage::db::set_agent_status(pool, &incident.tenant_id, &incident.agent_id, "frozen")
                .await
                .map_err(AegisError::Database)?;
            aegis_storage::db::set_agent_frozen_reason(
                pool,
                &incident.tenant_id,
                &incident.agent_id,
                Some(&rendered_reason),
            )
            .await
            .map_err(AegisError::Database)?;
        }
        PlaybookStep::ForceApproval => {
            aegis_storage::db::set_agent_force_approval(pool, &incident.tenant_id, &incident.agent_id, true)
                .await
                .map_err(AegisError::Database)?;
        }
        PlaybookStep::QuarantineMcp { server_key } => {
            let rendered_key = render_template(server_key, incident, agent);
            aegis_storage::db::update_mcp_server(
                pool,
                &incident.tenant_id,
                &rendered_key,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("quarantined"),
            )
            .await
            .map_err(AegisError::Database)?;
        }
        PlaybookStep::NotifySlack { webhook_url, channel, text } => {
            let rendered_url = render_template(webhook_url, incident, agent);
            let rendered_text = render_template(text, incident, agent);
            let rendered_channel = channel.as_ref().map(|c| render_template(c, incident, agent));

            let client = reqwest::Client::new();
            let mut payload = serde_json::json!({
                "text": rendered_text,
            });
            if let Some(c) = rendered_channel {
                payload["channel"] = serde_json::Value::String(c);
            }

            let _ = client.post(&rendered_url)
                .json(&payload)
                .send()
                .await;
        }
        PlaybookStep::NotifyWebhook { url, payload_template } => {
            let rendered_url = render_template(url, incident, agent);
            let client = reqwest::Client::new();
            
            let payload = if let Some(ref template) = payload_template {
                let rendered_payload = render_template(template, incident, agent);
                match serde_json::from_str::<serde_json::Value>(&rendered_payload) {
                    Ok(val) => val,
                    Err(_) => serde_json::json!({
                        "incident": incident,
                        "error": "Failed to render custom payload JSON template",
                    }),
                }
            } else {
                serde_json::json!({
                    "incident": incident,
                    "agent": {
                        "id": agent.id,
                        "agent_key": agent.agent_key,
                        "name": agent.name,
                        "environment": agent.environment,
                    }
                })
            };

            let _ = client.post(&rendered_url)
                .json(&payload)
                .send()
                .await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mock_agent() -> AgentRecord {
        AgentRecord {
            id: "agent-123-id".to_string(),
            tenant_id: "tenant-abc".to_string(),
            agent_key: "agent-123-key".to_string(),
            agent_token: "secret-token".to_string(),
            name: "Test Agent".to_string(),
            owner_team: Some("Security".to_string()),
            owner_email: Some("security@aegis.com".to_string()),
            environment: "production".to_string(),
            framework: Some("langchain".to_string()),
            model_provider: Some("openai".to_string()),
            model_name: Some("gpt-4".to_string()),
            purpose: Some("testing playbooks".to_string()),
            risk_tier: "low".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            quarantined_at: None,
            force_approval: false,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn make_mock_incident(kind: &str, severity: &str) -> Incident {
        let json = serde_json::json!({
            "incident_id": "incident-789-id",
            "opened_at": "2026-06-23T12:00:00Z",
            "tenant_id": "tenant-abc",
            "agent_id": "agent-123-id",
            "kind": kind,
            "severity": severity,
            "summary": "Mock anomaly summary",
            "source_event_ids": ["event-1"],
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn test_playbook_validation() {
        // Valid playbook
        let pb = ResponsePlaybook {
            name: "Slack Alert Playbook".to_string(),
            trigger: PlaybookTrigger {
                kind: "deny_storm".to_string(),
                severity: TriggerSeverity::List(vec!["high".to_string(), "critical".to_string()]),
                agent_id: None,
                environment: None,
            },
            steps: vec![PlaybookStep::FreezeAgent { reason: Some("Freeze reason".to_string()) }],
        };
        assert!(pb.validate().is_ok());

        // Empty name
        let mut invalid_pb = pb.clone();
        invalid_pb.name = "".to_string();
        assert!(invalid_pb.validate().is_err());

        // Invalid severity
        let mut invalid_pb = pb.clone();
        invalid_pb.trigger.severity = TriggerSeverity::Single("super-critical".to_string());
        assert!(invalid_pb.validate().is_err());

        // Empty steps
        let mut invalid_pb = pb.clone();
        invalid_pb.steps = vec![];
        assert!(invalid_pb.validate().is_err());
    }

    #[test]
    fn test_trigger_matching() {
        let agent = make_mock_agent();
        let incident = make_mock_incident("deny_storm", "critical");

        // Match kind, severity, no agent/env filters
        let pb = ResponsePlaybook {
            name: "Test Playbook".to_string(),
            trigger: PlaybookTrigger {
                kind: "deny_storm".to_string(),
                severity: TriggerSeverity::List(vec!["critical".to_string()]),
                agent_id: None,
                environment: None,
            },
            steps: vec![PlaybookStep::ForceApproval],
        };
        assert!(pb.matches(&incident, &agent));

        // Mismatched kind
        let mut pb_mismatch = pb.clone();
        pb_mismatch.trigger.kind = "runaway".to_string();
        assert!(!pb_mismatch.matches(&incident, &agent));

        // Mismatched severity
        let mut pb_mismatch = pb.clone();
        pb_mismatch.trigger.severity = TriggerSeverity::Single("low".to_string());
        assert!(!pb_mismatch.matches(&incident, &agent));

        // Mismatched agent_id
        let mut pb_mismatch = pb.clone();
        pb_mismatch.trigger.agent_id = Some("other-agent".to_string());
        assert!(!pb_mismatch.matches(&incident, &agent));

        // Matching agent_id by id
        let mut pb_match = pb.clone();
        pb_match.trigger.agent_id = Some("agent-123-id".to_string());
        assert!(pb_match.matches(&incident, &agent));

        // Matching agent_id by key
        let mut pb_match = pb.clone();
        pb_match.trigger.agent_id = Some("agent-123-key".to_string());
        assert!(pb_match.matches(&incident, &agent));

        // Matching environment
        let mut pb_match = pb.clone();
        pb_match.trigger.environment = Some("production".to_string());
        assert!(pb_match.matches(&incident, &agent));

        // Mismatched environment
        let mut pb_mismatch = pb.clone();
        pb_mismatch.trigger.environment = Some("staging".to_string());
        assert!(!pb_mismatch.matches(&incident, &agent));
    }

    #[test]
    fn test_template_rendering() {
        let agent = make_mock_agent();
        let incident = make_mock_incident("deny_storm", "critical");

        let template = "Incident {{ incident.incident_id }} occurred in {{ agent.environment }} for agent {{ agent.name }} (key: {{ agent.agent_key }})";
        let rendered = render_template(template, &incident, &agent);
        assert_eq!(
            rendered,
            "Incident incident-789-id occurred in production for agent Test Agent (key: agent-123-key)"
        );
    }
}
