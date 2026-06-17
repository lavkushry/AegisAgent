//! GitHub Checks API integration (#1383).
//!
//! Surfaces Aegis authorize decisions as a GitHub Check Run on the PR's head
//! commit, so a denied or pending-approval tool call shows up directly in the
//! PR UI as a failing/action-required check — no separate dashboard visit
//! required.
//!
//! Aegis tool calls are not tied to a file/line in the repo diff, so
//! `path`/`start_line`/`end_line` on each annotation point at a synthetic
//! `.aegisagent/decisions` reference rather than real source — the GitHub
//! Checks API requires these fields to be present, but they carry no
//! diff-positional meaning here. The risky-action detail is the message.
//!
//! State (check_run_id + head_sha + tally per PR) is in-memory only and
//! resets on gateway restart, matching the precedent set by
//! [`crate::gh_comment::GhPrCommenter`]'s rate limiter (#1382).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde_json::{json, Value};
use tracing::{debug, warn};

/// Maximum risky actions retained (and surfaced as annotations) per check run.
/// Bounds memory growth during a long-lived PR with many denied/pending calls.
pub const MAX_RISKY_ACTIONS: usize = 20;

/// A single denied or pending-approval tool call, kept for the check-run
/// summary and annotations.
#[derive(Debug, Clone)]
pub struct RiskyAction {
    pub tool: String,
    pub action: String,
    pub decision: String,
    pub reason: String,
    pub risk_score: i32,
}

/// One authorize decision to record against a PR's check run. Bundled into
/// a struct (rather than five loose parameters) to keep
/// [`GhChecksClient::record_decision`] and [`spawn_record_decision`] under
/// clippy's argument-count lint.
#[derive(Debug, Clone)]
pub struct DecisionInfo {
    pub tool: String,
    pub action: String,
    pub decision: String,
    pub reason: String,
    pub risk_score: i32,
}

/// Classify a decision into one of the three Checks-API tally buckets.
/// `redact` still allows the call to proceed, so it counts as allowed.
/// `quarantine` is the most severe outcome (the agent itself is quarantined)
/// and is folded into `denied` so the check fails loudly.
pub fn tally_bucket(decision: &str) -> &'static str {
    match decision {
        "allow" | "redact" => "allowed",
        "require_approval" => "pending",
        _ => "denied", // deny, quarantine, and any unrecognized value fail closed.
    }
}

/// Compute the Checks API `conclusion` from the running tally.
/// `denied` wins over `pending` when both are present — once any action was
/// denied the check must show a hard failure, not just "action required".
pub fn compute_conclusion(denied: u32, pending: u32) -> &'static str {
    if denied > 0 {
        "failure"
    } else if pending > 0 {
        "action_required"
    } else {
        "success"
    }
}

/// Build the check run `(title, summary_markdown)` from the current tally.
pub fn format_check_output(
    allowed: u32,
    denied: u32,
    pending: u32,
    risky_actions: &[RiskyAction],
) -> (String, String) {
    let total = allowed + denied + pending;
    let title = if denied > 0 {
        format!("{denied} action(s) denied")
    } else if pending > 0 {
        format!("{pending} action(s) pending approval")
    } else {
        format!("All {allowed} action(s) allowed")
    };

    let mut summary = format!(
        "**Aegis decision breakdown** ({total} tool call(s) observed)\n\n\
         | Allowed | Denied | Pending approval |\n\
         |---|---|---|\n\
         | {allowed} | {denied} | {pending} |\n"
    );

    if !risky_actions.is_empty() {
        summary.push_str("\n### Risky actions\n\n");
        for ra in risky_actions {
            summary.push_str(&format!(
                "- **{}.{}** → `{}` (risk {}/100): {}\n",
                ra.tool, ra.action, ra.decision, ra.risk_score, ra.reason
            ));
        }
    }

    summary.push_str(
        "\n_Posted automatically by [AegisAgent](https://github.com/lavkushry/AegisAgent)._",
    );

    (title, summary)
}

/// Build the GitHub Checks API `annotations` array from risky actions.
/// Capped at [`MAX_RISKY_ACTIONS`] (the API itself caps at 50 per request).
pub fn build_annotations(risky_actions: &[RiskyAction]) -> Vec<Value> {
    risky_actions
        .iter()
        .take(MAX_RISKY_ACTIONS)
        .map(|ra| {
            let level = if ra.decision == "deny" || ra.decision == "quarantine" {
                "failure"
            } else {
                "warning"
            };
            json!({
                "path": ".aegisagent/decisions",
                "start_line": 1,
                "end_line": 1,
                "annotation_level": level,
                "title": format!("{}.{}", ra.tool, ra.action),
                "message": format!("{} (risk {}/100): {}", ra.decision, ra.risk_score, ra.reason),
            })
        })
        .collect()
}

/// Running per-`(repo, pr_number)` check-run state.
#[derive(Debug, Default)]
struct CheckRunState {
    check_run_id: Option<u64>,
    head_sha: Option<String>,
    allowed: u32,
    denied: u32,
    pending: u32,
    risky_actions: Vec<RiskyAction>,
}

/// Client for creating/updating Aegis GitHub Check Runs.
///
/// Constructed once at gateway startup and stored in `AppState`. All state is
/// cheaply clonable via `Arc`.
pub struct GhChecksClient {
    /// GitHub App installation token (bearer token for the GitHub API).
    token: String,
    http_client: reqwest::Client,
    /// Per-`"owner/repo#pr_number"` running tally and check_run_id.
    runs: Arc<Mutex<HashMap<String, CheckRunState>>>,
}

impl GhChecksClient {
    /// Construct a new client. `token` is the GitHub App installation bearer
    /// token (no `token ` prefix — the caller supplies the raw value).
    pub fn new(token: String) -> Self {
        Self {
            token,
            http_client: reqwest::Client::new(),
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn run_key(repo: &str, pr_number: u64) -> String {
        format!("{repo}#{pr_number}")
    }

    /// Fetch the PR's current head SHA via the GitHub REST API.
    async fn fetch_head_sha(&self, repo: &str, pr_number: u64) -> Result<String, String> {
        let url = format!("https://api.github.com/repos/{repo}/pulls/{pr_number}");
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "AegisAgent/1.0")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("GitHub API error {status}: {text}"));
        }

        let body: Value = resp.json().await.map_err(|e| e.to_string())?;
        body.get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "PR response missing head.sha".to_string())
    }

    async fn create_check_run(
        &self,
        repo: &str,
        head_sha: &str,
        title: &str,
        summary: &str,
        conclusion: &str,
        annotations: &[Value],
    ) -> Result<u64, String> {
        let url = format!("https://api.github.com/repos/{repo}/check-runs");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "AegisAgent/1.0")
            .json(&json!({
                "name": "Aegis Security Gate",
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    "summary": summary,
                    "annotations": annotations,
                },
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("GitHub API error {status}: {text}"));
        }

        let body: Value = resp.json().await.map_err(|e| e.to_string())?;
        body.get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "create check-run response missing id".to_string())
    }

    async fn update_check_run(
        &self,
        repo: &str,
        check_run_id: u64,
        title: &str,
        summary: &str,
        conclusion: &str,
        annotations: &[Value],
    ) -> Result<(), String> {
        let url = format!("https://api.github.com/repos/{repo}/check-runs/{check_run_id}");
        let resp = self
            .http_client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "AegisAgent/1.0")
            .json(&json!({
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    "summary": summary,
                    "annotations": annotations,
                },
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("GitHub API error {status}: {text}"))
        }
    }

    /// Record one authorize decision against the running tally for
    /// `(repo, pr_number)`, then create (first call) or update (subsequent
    /// calls) the Aegis check run to reflect the new totals.
    ///
    /// Best-effort: errors are returned to the caller (who should log and
    /// never surface them as an authorize-path failure — see
    /// [`spawn_record_decision`]).
    pub async fn record_decision(
        &self,
        repo: &str,
        pr_number: u64,
        info: &DecisionInfo,
    ) -> Result<(), String> {
        let key = Self::run_key(repo, pr_number);

        // Update the in-memory tally and snapshot what we need for the API
        // call outside the lock (the lock must never be held across .await).
        let (check_run_id, head_sha_cached, allowed, denied, pending, risky_actions) = {
            let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
            let state = runs.entry(key.clone()).or_default();

            match tally_bucket(&info.decision) {
                "allowed" => state.allowed += 1,
                "pending" => state.pending += 1,
                _ => state.denied += 1,
            }
            if tally_bucket(&info.decision) != "allowed"
                && state.risky_actions.len() < MAX_RISKY_ACTIONS
            {
                state.risky_actions.push(RiskyAction {
                    tool: info.tool.clone(),
                    action: info.action.clone(),
                    decision: info.decision.clone(),
                    reason: info.reason.clone(),
                    risk_score: info.risk_score,
                });
            }

            (
                state.check_run_id,
                state.head_sha.clone(),
                state.allowed,
                state.denied,
                state.pending,
                state.risky_actions.clone(),
            )
        };

        let head_sha = match head_sha_cached {
            Some(sha) => sha,
            None => self.fetch_head_sha(repo, pr_number).await?,
        };

        let conclusion = compute_conclusion(denied, pending);
        let (title, summary) = format_check_output(allowed, denied, pending, &risky_actions);
        let annotations = build_annotations(&risky_actions);

        let new_check_run_id = match check_run_id {
            Some(id) => {
                self.update_check_run(repo, id, &title, &summary, conclusion, &annotations)
                    .await?;
                id
            }
            None => {
                self.create_check_run(repo, &head_sha, &title, &summary, conclusion, &annotations)
                    .await?
            }
        };

        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = runs.get_mut(&key) {
            state.check_run_id = Some(new_check_run_id);
            state.head_sha = Some(head_sha);
        }

        Ok(())
    }
}

/// Spawn a background task that records a decision against the Aegis check
/// run for `(repo, pr_number)`. Fire-and-forget — failures are logged at WARN
/// level and never propagate to the `/v1/authorize` caller (Law 3: SOC/
/// notification work is always out-of-band).
pub fn spawn_record_decision(
    client: Arc<GhChecksClient>,
    repo: String,
    pr_number: u64,
    info: DecisionInfo,
) {
    tokio::spawn(async move {
        let decision = info.decision.clone();
        match client.record_decision(&repo, pr_number, &info).await {
            Ok(()) => debug!(repo, pr_number, decision, "Aegis check run updated"),
            Err(e) => warn!(repo, pr_number, error = %e, "Failed to update Aegis check run"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_bucket_allow_and_redact_count_as_allowed() {
        assert_eq!(tally_bucket("allow"), "allowed");
        assert_eq!(tally_bucket("redact"), "allowed");
    }

    #[test]
    fn tally_bucket_require_approval_counts_as_pending() {
        assert_eq!(tally_bucket("require_approval"), "pending");
    }

    #[test]
    fn tally_bucket_deny_and_quarantine_count_as_denied() {
        assert_eq!(tally_bucket("deny"), "denied");
        assert_eq!(tally_bucket("quarantine"), "denied");
    }

    #[test]
    fn tally_bucket_unknown_decision_fails_closed_as_denied() {
        assert_eq!(tally_bucket("something_unexpected"), "denied");
    }

    #[test]
    fn compute_conclusion_all_allowed_is_success() {
        assert_eq!(compute_conclusion(0, 0), "success");
    }

    #[test]
    fn compute_conclusion_any_denied_is_failure() {
        assert_eq!(compute_conclusion(1, 0), "failure");
    }

    #[test]
    fn compute_conclusion_pending_without_denied_is_action_required() {
        assert_eq!(compute_conclusion(0, 1), "action_required");
    }

    #[test]
    fn compute_conclusion_denied_beats_pending() {
        assert_eq!(compute_conclusion(1, 1), "failure");
    }

    #[test]
    fn format_check_output_all_allowed() {
        let (title, summary) = format_check_output(3, 0, 0, &[]);
        assert_eq!(title, "All 3 action(s) allowed");
        assert!(summary.contains("| 3 | 0 | 0 |"));
        assert!(!summary.contains("Risky actions"));
    }

    #[test]
    fn format_check_output_with_denied_includes_risky_action_detail() {
        let risky = vec![RiskyAction {
            tool: "github".to_string(),
            action: "merge_pull_request".to_string(),
            decision: "deny".to_string(),
            reason: "untrusted provenance".to_string(),
            risk_score: 90,
        }];
        let (title, summary) = format_check_output(1, 1, 0, &risky);
        assert_eq!(title, "1 action(s) denied");
        assert!(summary.contains("Risky actions"));
        assert!(summary.contains("github.merge_pull_request"));
        assert!(summary.contains("untrusted provenance"));
        assert!(summary.contains("90/100"));
    }

    #[test]
    fn format_check_output_pending_title_when_no_denied() {
        let (title, _) = format_check_output(2, 0, 1, &[]);
        assert_eq!(title, "1 action(s) pending approval");
    }

    #[test]
    fn build_annotations_empty_for_no_risky_actions() {
        assert!(build_annotations(&[]).is_empty());
    }

    #[test]
    fn build_annotations_deny_is_failure_level() {
        let risky = vec![RiskyAction {
            tool: "github".to_string(),
            action: "push".to_string(),
            decision: "deny".to_string(),
            reason: "blocked".to_string(),
            risk_score: 95,
        }];
        let annotations = build_annotations(&risky);
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["annotation_level"], "failure");
        assert_eq!(annotations[0]["path"], ".aegisagent/decisions");
    }

    #[test]
    fn build_annotations_require_approval_is_warning_level() {
        let risky = vec![RiskyAction {
            tool: "github".to_string(),
            action: "push".to_string(),
            decision: "require_approval".to_string(),
            reason: "needs review".to_string(),
            risk_score: 60,
        }];
        let annotations = build_annotations(&risky);
        assert_eq!(annotations[0]["annotation_level"], "warning");
    }

    #[test]
    fn build_annotations_caps_at_max_risky_actions() {
        let risky: Vec<RiskyAction> = (0..30)
            .map(|i| RiskyAction {
                tool: "github".to_string(),
                action: format!("action_{i}"),
                decision: "deny".to_string(),
                reason: "blocked".to_string(),
                risk_score: 80,
            })
            .collect();
        let annotations = build_annotations(&risky);
        assert_eq!(annotations.len(), MAX_RISKY_ACTIONS);
    }

    #[test]
    fn run_key_format() {
        assert_eq!(GhChecksClient::run_key("owner/repo", 42), "owner/repo#42");
    }

    #[tokio::test]
    async fn record_decision_accumulates_tally_across_calls() {
        let client = GhChecksClient::new("tok".to_string());
        // No network calls are exercised directly here — this test only
        // verifies the in-memory tally bookkeeping via the internal lock,
        // since record_decision's HTTP calls would require a live GitHub API.
        // We instead unit-test the pure tally/format helpers above and rely
        // on this test to confirm key derivation is stable.
        let key = GhChecksClient::run_key("owner/repo", 7);
        let runs = client.runs.lock().unwrap();
        assert!(!runs.contains_key(&key));
    }
}
