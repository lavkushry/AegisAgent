//! #1627 — alerting settings validation and silence matching.

use aegis_common::ssrf::{validate_callback_url, CallbackUrlError};
use chrono::{DateTime, Utc};

/// Supported contact-point channel types.
pub const CHANNEL_WEBHOOK: &str = "webhook";
pub const CHANNEL_SLACK: &str = "slack";
pub const CHANNEL_PAGERDUTY: &str = "pagerduty";
pub const CHANNEL_EMAIL: &str = "email";

/// Classify a destination URL into a contact channel.
pub fn classify_channel_from_url(url: &str) -> &'static str {
    let lower = url.to_ascii_lowercase();
    if lower.contains("hooks.slack.com") {
        CHANNEL_SLACK
    } else if lower.contains("events.pagerduty.com") {
        CHANNEL_PAGERDUTY
    } else if lower.starts_with("mailto:") {
        CHANNEL_EMAIL
    } else {
        CHANNEL_WEBHOOK
    }
}

/// Validate a tenant-supplied outbound destination URL (SSRF-guarded, HTTPS-only).
pub fn validate_destination_url(raw: &str) -> Result<(), String> {
    validate_callback_url(raw).map_err(map_callback_url_error)
}

fn map_callback_url_error(err: CallbackUrlError) -> String {
    match err {
        CallbackUrlError::Empty => "destination URL must not be empty".to_string(),
        CallbackUrlError::HttpsRequired => "destination URL must use https".to_string(),
        CallbackUrlError::UserinfoForbidden => {
            "destination URL must not embed credentials".to_string()
        }
        CallbackUrlError::MissingHost => "destination URL is missing a host".to_string(),
        CallbackUrlError::BlockedHost(h) => format!("destination URL host is blocked: {h}"),
        CallbackUrlError::BlockedAddress(ip) => {
            format!("destination URL resolves to a blocked address: {ip}")
        }
        CallbackUrlError::Unresolvable => "destination URL could not be resolved".to_string(),
        CallbackUrlError::InvalidUrl(msg) => format!("invalid destination URL: {msg}"),
    }
}

/// Whether `channel_type` is supported for create/update at this API revision.
pub fn channel_type_is_supported(channel_type: &str) -> bool {
    matches!(
        channel_type,
        CHANNEL_WEBHOOK | CHANNEL_SLACK | CHANNEL_PAGERDUTY
    )
}

/// Returns true when an active silence covers the given rule/agent at `at`.
pub fn silence_matches(
    silence_rule_key: Option<&str>,
    silence_agent_id: Option<&str>,
    rule_key: Option<&str>,
    agent_id: Option<&str>,
) -> bool {
    if let Some(sk) = silence_rule_key {
        if rule_key != Some(sk) {
            return false;
        }
    }
    if let Some(aid) = silence_agent_id {
        if agent_id != Some(aid) {
            return false;
        }
    }
    true
}

/// Returns true when `at` falls within the silence window.
pub fn silence_is_active(
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    at: DateTime<Utc>,
) -> bool {
    at >= starts_at && at < ends_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_slack_url() {
        assert_eq!(
            classify_channel_from_url("https://hooks.slack.com/services/T/B/X"),
            CHANNEL_SLACK
        );
    }

    #[test]
    fn rejects_ssrf_loopback() {
        assert!(validate_destination_url("https://127.0.0.1/hook").is_err());
    }

    #[test]
    fn silence_matches_rule_and_agent() {
        assert!(silence_matches(
            Some("rule_a"),
            Some("agent_1"),
            Some("rule_a"),
            Some("agent_1"),
        ));
        assert!(!silence_matches(
            Some("rule_a"),
            Some("agent_1"),
            Some("rule_b"),
            Some("agent_1"),
        ));
        assert!(silence_matches(
            None,
            Some("agent_1"),
            Some("any"),
            Some("agent_1")
        ));
    }

    #[test]
    fn silence_window_is_half_open() {
        let start = Utc::now();
        let end = start + chrono::Duration::hours(1);
        assert!(silence_is_active(start, end, start));
        assert!(!silence_is_active(start, end, end));
    }
}
