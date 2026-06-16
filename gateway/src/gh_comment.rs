//! GitHub PR comment notifier for denied actions (#1382).
//!
//! When a coding agent's PR-related action is denied, this module posts a
//! templated PR comment explaining the decision. The comment is posted
//! asynchronously in a background task so the `/v1/authorize` hot path is
//! never delayed. It is strictly best-effort — a failure to post a comment is
//! logged but never surfaces as an error to the caller.
//!
//! **Rate limit:** at most [`MAX_COMMENTS_PER_PR`] comments are posted per
//! `(repo, pr_number)` pair per gateway process lifetime. This prevents spam
//! during a noisy deny-storm.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tracing::{debug, warn};

/// Maximum comments Aegis will post per pull-request number.
pub const MAX_COMMENTS_PER_PR: u32 = 5;

/// Parse a resource string of the form `"owner/repo#42"` into
/// `("owner/repo", 42)`. Returns `None` for strings without a `#<digits>`
/// suffix, or where the PR number is zero or non-numeric.
pub fn extract_pr_ref(resource: &str) -> Option<(String, u64)> {
    let hash_pos = resource.rfind('#')?;
    let repo = &resource[..hash_pos];
    let number_str = &resource[hash_pos + 1..];
    let pr_number: u64 = number_str.parse().ok().filter(|&n| n > 0)?;
    if repo.is_empty() {
        return None;
    }
    Some((repo.to_string(), pr_number))
}

/// Format the deny comment body from decision metadata.
///
/// The comment is branded as an Aegis notification and includes structured
/// detail so the developer can understand and act on the denial.
pub fn format_deny_comment(
    reason: &str,
    matched_policies: &[String],
    risk_score: i32,
    decision_id: &str,
    tool: &str,
    action: &str,
) -> String {
    let policies_str = if matched_policies.is_empty() {
        "_none_".to_string()
    } else {
        matched_policies
            .iter()
            .map(|p| format!("`{p}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"## 🛡️ Aegis: Action Denied

An automated coding agent attempted a **{tool} / {action}** action on this pull request, which was **denied** by the AegisAgent integrity layer.

| Field | Value |
|---|---|
| **Reason** | {reason} |
| **Matched policy** | {policies_str} |
| **Risk score** | {risk_score} / 100 |
| **Decision ID** | `{decision_id}` |

### What to do

- Review the decision at `GET /v1/decisions/{decision_id}`.
- If the action was legitimate, ask an authorized approver to unblock it via the Aegis dashboard or Slack.
- If the denial was unexpected, check the Cedar policy in `gateway/policies.cedar` and the agent's registered `source_trust` level.

_This comment was posted automatically by [AegisAgent](https://github.com/lavkushry/AegisAgent). At most {MAX_COMMENTS_PER_PR} comments are posted per pull request to prevent noise._"#
    )
}

/// Client for posting Aegis deny comments on GitHub pull requests.
///
/// Constructed once at gateway startup and stored in [`AppState`].
/// All state is cheaply clonable via `Arc`.
pub struct GhPrCommenter {
    /// GitHub App installation token (bearer token for the GitHub API).
    token: String,
    /// Reqwest client — reused across requests.
    http_client: reqwest::Client,
    /// Per-`"owner/repo#pr_number"` comment count (in-memory; resets on
    /// restart). Protected by a `Mutex` so spawned tasks can share it.
    counts: Arc<Mutex<HashMap<String, u32>>>,
}

impl GhPrCommenter {
    /// Construct a new commenter. `token` is the GitHub App installation
    /// bearer token (no `token ` prefix — the caller supplies the raw value).
    pub fn new(token: String) -> Self {
        Self {
            token,
            http_client: reqwest::Client::new(),
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the rate-limit key for a `(repo, pr_number)` pair.
    fn rate_key(repo: &str, pr_number: u64) -> String {
        format!("{repo}#{pr_number}")
    }

    /// Return `true` if this `(repo, pr_number)` is under the comment cap.
    pub fn under_limit(&self, repo: &str, pr_number: u64) -> bool {
        let key = Self::rate_key(repo, pr_number);
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.get(&key).copied().unwrap_or(0) < MAX_COMMENTS_PER_PR
    }

    /// Increment the comment counter for `(repo, pr_number)`.
    fn increment(&self, repo: &str, pr_number: u64) {
        let key = Self::rate_key(repo, pr_number);
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        *counts.entry(key).or_insert(0) += 1;
    }

    /// Post `body` as a comment on pull request `pr_number` in `repo`
    /// (`"owner/repo"` format). Best-effort — returns `Ok(())` even if
    /// the comment could not be posted (caller should not surface this
    /// as an authorization error).
    pub async fn post_comment(&self, repo: &str, pr_number: u64, body: &str) -> Result<(), String> {
        if !self.under_limit(repo, pr_number) {
            debug!(
                repo,
                pr_number, "Aegis PR comment rate limit reached; skipping"
            );
            return Ok(());
        }

        let url = format!("https://api.github.com/repos/{repo}/issues/{pr_number}/comments");

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "AegisAgent/1.0")
            .json(&serde_json::json!({"body": body}))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            self.increment(repo, pr_number);
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("GitHub API error {status}: {text}"))
        }
    }
}

/// Spawn a background task that posts a deny comment on a GitHub PR.
///
/// This is fire-and-forget — failures are logged at WARN level and never
/// propagate to the caller. The task is spawned on the current Tokio runtime.
pub fn spawn_pr_comment(commenter: Arc<GhPrCommenter>, repo: String, pr_number: u64, body: String) {
    tokio::spawn(async move {
        match commenter.post_comment(&repo, pr_number, &body).await {
            Ok(()) => debug!(repo, pr_number, "Aegis PR comment posted"),
            Err(e) => warn!(repo, pr_number, error = %e, "Failed to post Aegis PR comment"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pr_ref_standard_format() {
        let result = extract_pr_ref("org/repo#42").unwrap();
        assert_eq!(result.0, "org/repo");
        assert_eq!(result.1, 42);
    }

    #[test]
    fn extract_pr_ref_nested_repo() {
        let result = extract_pr_ref("owner/repo-name#100").unwrap();
        assert_eq!(result.0, "owner/repo-name");
        assert_eq!(result.1, 100);
    }

    #[test]
    fn extract_pr_ref_no_hash_returns_none() {
        assert!(extract_pr_ref("org/repo").is_none());
    }

    #[test]
    fn extract_pr_ref_zero_number_returns_none() {
        assert!(extract_pr_ref("org/repo#0").is_none());
    }

    #[test]
    fn extract_pr_ref_non_numeric_returns_none() {
        assert!(extract_pr_ref("org/repo#abc").is_none());
    }

    #[test]
    fn extract_pr_ref_empty_repo_returns_none() {
        assert!(extract_pr_ref("#42").is_none());
    }

    #[test]
    fn format_deny_comment_contains_key_fields() {
        let body = format_deny_comment(
            "Untrusted source cannot trigger mutation",
            &["policy3".to_string()],
            90,
            "dec-uuid-1234",
            "github",
            "merge_pull_request",
        );
        assert!(body.contains("denied"));
        assert!(body.contains("Untrusted source cannot trigger mutation"));
        assert!(body.contains("`policy3`"));
        assert!(body.contains("90 / 100"));
        assert!(body.contains("dec-uuid-1234"));
        assert!(body.contains("github / merge_pull_request"));
    }

    #[test]
    fn format_deny_comment_empty_policies() {
        let body = format_deny_comment("Fail closed", &[], 100, "dec-0", "github", "push");
        assert!(body.contains("_none_"));
    }

    #[test]
    fn rate_limiter_under_limit_initially() {
        let c = GhPrCommenter::new("tok".to_string());
        assert!(c.under_limit("org/repo", 1));
    }

    #[test]
    fn rate_limiter_blocks_after_max_comments() {
        let c = GhPrCommenter::new("tok".to_string());
        for _ in 0..MAX_COMMENTS_PER_PR {
            assert!(c.under_limit("org/repo", 1));
            c.increment("org/repo", 1);
        }
        assert!(!c.under_limit("org/repo", 1));
    }

    #[test]
    fn rate_limiter_independent_per_pr() {
        let c = GhPrCommenter::new("tok".to_string());
        for _ in 0..MAX_COMMENTS_PER_PR {
            c.increment("org/repo", 1);
        }
        // PR #2 is a different key — still under limit
        assert!(c.under_limit("org/repo", 2));
        // PR #1 on a different repo is also independent
        assert!(c.under_limit("other/repo", 1));
    }

    #[test]
    fn rate_key_format() {
        assert_eq!(GhPrCommenter::rate_key("owner/repo", 42), "owner/repo#42");
    }
}
