//! Slack approver-group membership gate (#1277).

use aegis_common::slack_approver::{
    parse_slack_approver_group, slack_user_in_allowlist, SlackApproverGroupConfig,
};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum SlackApproverGateError {
    #[error("Slack usergroup validation requires AEGIS_SLACK_BOT_TOKEN")]
    BotTokenRequired,
    #[error("Slack API error: {0}")]
    Api(String),
}

/// Returns whether `slack_user_id` may approve via Slack callback for this tenant.
pub async fn slack_user_authorized_for_approval(
    config_raw: Option<&str>,
    slack_user_id: &str,
    bot_token: Option<&str>,
) -> Result<bool, SlackApproverGateError> {
    let parsed = parse_slack_approver_group(config_raw);
    match parsed {
        SlackApproverGroupConfig::AllowAll => Ok(true),
        SlackApproverGroupConfig::UserAllowlist(_) => {
            Ok(slack_user_in_allowlist(&parsed, slack_user_id))
        }
        SlackApproverGroupConfig::UsergroupId(ref group_id) => {
            let token = bot_token.ok_or(SlackApproverGateError::BotTokenRequired)?;
            let members = fetch_usergroup_members(token, group_id).await?;
            Ok(members.iter().any(|id| id == slack_user_id))
        }
    }
}

async fn fetch_usergroup_members(
    bot_token: &str,
    usergroup_id: &str,
) -> Result<Vec<String>, SlackApproverGateError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| SlackApproverGateError::Api(e.to_string()))?;

    let response = client
        .get("https://slack.com/api/usergroups.users.list")
        .bearer_auth(bot_token)
        .query(&[("usergroup", usergroup_id)])
        .send()
        .await
        .map_err(|e| SlackApproverGateError::Api(e.to_string()))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| SlackApproverGateError::Api(e.to_string()))?;

    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_error");
        return Err(SlackApproverGateError::Api(err.to_string()));
    }

    let users = body
        .get("users")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allowlist_authorizes_listed_user() {
        let ok = slack_user_authorized_for_approval(Some("U111,U222"), "U111", None)
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn allowlist_rejects_unlisted_user() {
        let ok = slack_user_authorized_for_approval(Some("U111"), "U999", None)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn usergroup_without_bot_token_errors() {
        let err = slack_user_authorized_for_approval(Some("S0123"), "U111", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SlackApproverGateError::BotTokenRequired));
    }
}
