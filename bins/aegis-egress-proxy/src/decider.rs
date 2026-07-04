//! The egress decision seam. The proxy never decides on its own
//! authority: it asks an [`EgressDecider`], and every failure mode of the
//! decider is a deny — an unreachable gateway must never become an open
//! proxy.

use std::net::IpAddr;
use std::time::Duration;

use aegis_egress::{EgressDecision, EgressDestination, EgressPolicy, EgressRule};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

const GATEWAY_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressCheckOutcome {
    pub decision: EgressDecision,
    pub reason: String,
}

impl EgressCheckOutcome {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            decision: EgressDecision::Allow,
            reason: reason.into(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: EgressDecision::Deny,
            reason: reason.into(),
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.decision == EgressDecision::Allow
    }
}

#[async_trait]
pub trait EgressDecider: Send + Sync {
    async fn check(&self, host: &str, port: u16) -> EgressCheckOutcome;
}

fn destination_for(host: &str) -> EgressDestination {
    match host.parse::<IpAddr>() {
        Ok(ip) => EgressDestination::Ip(ip),
        Err(_) => EgressDestination::Domain(host.to_string()),
    }
}

/// Standalone/dev mode: evaluates an in-process `aegis_egress`
/// [`EgressPolicy`]. No ban/quarantine layering, no durable evidence —
/// gateway mode is the production posture.
pub struct PolicyDecider {
    policy: EgressPolicy,
}

impl PolicyDecider {
    pub fn new(
        deny_by_default: bool,
        tenant_rules: &[EgressRule],
        run_rules: &[EgressRule],
    ) -> Self {
        Self {
            policy: EgressPolicy::new(deny_by_default, tenant_rules, run_rules),
        }
    }
}

#[async_trait]
impl EgressDecider for PolicyDecider {
    async fn check(&self, host: &str, _port: u16) -> EgressCheckOutcome {
        match self.policy.check(&destination_for(host)) {
            EgressDecision::Allow => EgressCheckOutcome::allow("allowed by local egress policy"),
            EgressDecision::Deny => EgressCheckOutcome::deny("denied by local egress policy"),
        }
    }
}

/// Body sent to the gateway's `POST /v1/egress/check` (Phase 5.2). Rules
/// travel in the request per that route's contract — the gateway owns ban
/// and quarantine state, the proxy owns its configured rule sets.
#[derive(Debug, Serialize)]
struct GatewayCheckRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<&'a str>,
    destination: &'a str,
    tenant_rules: &'a [EgressRule],
    run_rules: &'a [EgressRule],
    deny_by_default: bool,
}

#[derive(Debug, Deserialize)]
struct GatewayCheckResponse {
    decision: String,
    reason: String,
}

/// Production mode: every check goes to the gateway, which layers bans and
/// quarantine over the rules and writes the durable runtime event (and
/// receipt where warranted). Any transport or protocol failure is a deny.
pub struct GatewayDecider {
    http: reqwest::Client,
    check_url: String,
    api_token: String,
    pub agent_id: Option<String>,
    pub run_id: Option<String>,
    pub sandbox_id: Option<String>,
    tenant_rules: Vec<EgressRule>,
    run_rules: Vec<EgressRule>,
    deny_by_default: bool,
}

impl GatewayDecider {
    pub fn new(
        gateway_base_url: &str,
        api_token: impl Into<String>,
        tenant_rules: Vec<EgressRule>,
        run_rules: Vec<EgressRule>,
        deny_by_default: bool,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            check_url: format!("{}/v1/egress/check", gateway_base_url.trim_end_matches('/')),
            api_token: api_token.into(),
            agent_id: None,
            run_id: None,
            sandbox_id: None,
            tenant_rules,
            run_rules,
            deny_by_default,
        }
    }
}

#[async_trait]
impl EgressDecider for GatewayDecider {
    async fn check(&self, host: &str, _port: u16) -> EgressCheckOutcome {
        let body = GatewayCheckRequest {
            agent_id: self.agent_id.as_deref(),
            run_id: self.run_id.as_deref(),
            sandbox_id: self.sandbox_id.as_deref(),
            destination: host,
            tenant_rules: &self.tenant_rules,
            run_rules: &self.run_rules,
            deny_by_default: self.deny_by_default,
        };
        let response = self
            .http
            .post(&self.check_url)
            .bearer_auth(&self.api_token)
            .timeout(GATEWAY_CHECK_TIMEOUT)
            .json(&body)
            .send()
            .await;
        let response = match response {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                return EgressCheckOutcome::deny(format!(
                    "gateway egress check returned {} — failing closed",
                    response.status()
                ));
            }
            Err(err) => {
                return EgressCheckOutcome::deny(format!(
                    "gateway unreachable ({err}) — failing closed"
                ));
            }
        };
        match response.json::<GatewayCheckResponse>().await {
            Ok(check) if check.decision == "allow" => EgressCheckOutcome::allow(check.reason),
            Ok(check) => EgressCheckOutcome::deny(check.reason),
            Err(err) => EgressCheckOutcome::deny(format!(
                "unparseable gateway egress response ({err}) — failing closed"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};

    #[tokio::test]
    async fn policy_decider_allows_and_denies_per_the_local_rules() {
        let decider = PolicyDecider::new(
            true,
            &[EgressRule::allow_domain_suffix("api.example.com")],
            &[],
        );
        assert!(decider.check("api.example.com", 443).await.is_allowed());
        assert!(!decider.check("evil.example", 443).await.is_allowed());
    }

    #[tokio::test]
    async fn gateway_decider_fails_closed_when_the_gateway_is_unreachable() {
        // A port that nothing listens on — RFC 5737 wouldn't fail fast, a
        // local closed port does.
        let decider = GatewayDecider::new("http://127.0.0.1:1", "token", vec![], vec![], false);
        let outcome = decider.check("api.example.com", 443).await;
        assert!(!outcome.is_allowed());
        assert!(outcome.reason.contains("failing closed"));
    }

    #[tokio::test]
    async fn gateway_decider_honors_the_gateway_verdict() {
        let app = Router::new().route(
            "/v1/egress/check",
            post(|Json(body): Json<serde_json::Value>| async move {
                let allowed = body["destination"] == "good.example.com";
                Json(serde_json::json!({
                    "decision": if allowed { "allow" } else { "deny" },
                    "reason": "mock gateway verdict",
                    "event_id": "evt-1",
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock gateway");
        let addr = listener.local_addr().expect("mock gateway addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let decider =
            GatewayDecider::new(&format!("http://{addr}"), "token", vec![], vec![], false);
        assert!(decider.check("good.example.com", 443).await.is_allowed());
        assert!(!decider.check("bad.example.com", 443).await.is_allowed());
    }
}
