//! Slack interactive-approval approver-group parsing (#1277).
//!
//! Pure logic only — no network I/O. Gateway code uses this to decide whether
//! a Slack `user.id` is authorized before approving/rejecting via callback.

/// How a tenant's `slack_approver_group` column is interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackApproverGroupConfig {
    /// No group configured — any authenticated Slack callback may approve.
    AllowAll,
    /// Comma-separated Slack user IDs (`U…`) stored inline; no Slack API needed.
    UserAllowlist(Vec<String>),
    /// Slack usergroup handle ID (`S…`); membership resolved at runtime via API.
    UsergroupId(String),
}

/// Parse `tenants.slack_approver_group`. Whitespace around commas is trimmed.
pub fn parse_slack_approver_group(raw: Option<&str>) -> SlackApproverGroupConfig {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return SlackApproverGroupConfig::AllowAll;
    };

    let upper = s.to_ascii_uppercase();
    if upper.starts_with('S') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_alphanumeric()) {
        return SlackApproverGroupConfig::UsergroupId(s.to_string());
    }

    let users: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect();

    if users.is_empty() {
        SlackApproverGroupConfig::AllowAll
    } else {
        SlackApproverGroupConfig::UserAllowlist(users)
    }
}

/// Returns `true` when `slack_user_id` is listed in a static allowlist config.
pub fn slack_user_in_allowlist(config: &SlackApproverGroupConfig, slack_user_id: &str) -> bool {
    match config {
        SlackApproverGroupConfig::AllowAll => true,
        SlackApproverGroupConfig::UserAllowlist(ids) => ids.iter().any(|id| id == slack_user_id),
        SlackApproverGroupConfig::UsergroupId(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_none_means_allow_all() {
        assert_eq!(
            parse_slack_approver_group(None),
            SlackApproverGroupConfig::AllowAll
        );
        assert_eq!(
            parse_slack_approver_group(Some("")),
            SlackApproverGroupConfig::AllowAll
        );
        assert_eq!(
            parse_slack_approver_group(Some("   ")),
            SlackApproverGroupConfig::AllowAll
        );
    }

    #[test]
    fn comma_separated_user_ids_form_allowlist() {
        let cfg = parse_slack_approver_group(Some("U111, U222"));
        assert_eq!(
            cfg,
            SlackApproverGroupConfig::UserAllowlist(vec!["U111".to_string(), "U222".to_string()])
        );
        assert!(slack_user_in_allowlist(&cfg, "U111"));
        assert!(!slack_user_in_allowlist(&cfg, "U999"));
    }

    #[test]
    fn usergroup_id_detected_by_s_prefix() {
        let cfg = parse_slack_approver_group(Some("S01234567"));
        assert_eq!(
            cfg,
            SlackApproverGroupConfig::UsergroupId("S01234567".to_string())
        );
    }
}
