//! Cedar policy hot-reload via filesystem watch (#883).
//!
//! `POST /v1/policies/reload` (`routes::reload_global_policies`) already lets
//! an operator trigger a reload of the global Cedar policy file on demand.
//! This module adds the other half named by the issue: an opt-in background
//! watcher that calls the same [`PolicyEngine::reload_file`] automatically
//! whenever the watched file changes on disk, so editing it directly (GitOps
//! sync, `scp`, a local edit during development) takes effect without an
//! explicit API call.
//!
//! Gated on `AEGIS_POLICY_HOT_RELOAD=true` — unset,
//! [`spawn_policy_hot_reload_watcher`] returns `None` immediately: no
//! watcher thread, no tokio task, no new dependency surface touched. Most
//! production deployments redeploy via CI/CD rather than editing the policy
//! file in place, so this stays opt-in rather than the default.

use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::policy::PolicyEngine;
use crate::routes::AppState;

/// Debounce window: editors and sync tools often emit several filesystem
/// events (truncate + write, or write + rename) for a single logical save.
/// 300ms collapses those into one reload without adding perceptible latency
/// to picking up a real change.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(300);

fn hot_reload_enabled() -> bool {
    std::env::var("AEGIS_POLICY_HOT_RELOAD")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Re-reads `policy_path` and reloads it into `policy_engine`, logging the
/// outcome. Kept independent of the filesystem watcher itself so it can be
/// unit tested directly against a real [`PolicyEngine`] without spinning up
/// a real `notify` watcher. A parse failure on the new file content is
/// logged and otherwise inert — `reload_file` itself never mutates the
/// engine's state unless the new content parses successfully, so a bad edit
/// can't take the gateway from "running on the last-good policy set" to
/// "running on nothing."
async fn reload_now(policy_engine: &PolicyEngine, policy_path: &Path) {
    match policy_engine.reload_file(policy_path).await {
        Ok(()) => tracing::info!(
            "Cedar policy file {:?} reloaded via hot-reload watcher",
            policy_path
        ),
        Err(e) => tracing::error!(
            "Hot-reload watcher failed to reload Cedar policy file {:?}: {:?}",
            policy_path,
            e
        ),
    }
}

/// Starts a debounced filesystem watcher on `watch_path`'s parent directory
/// (not the file itself — many editors/sync tools replace a file via
/// rename-on-save, which can orphan a watch placed directly on the file) and
/// returns a channel that receives one `()` per debounced change to that
/// exact path, plus the [`Debouncer`] guard the caller must keep alive for as
/// long as it wants events delivered. Returns `None` if the underlying
/// watcher fails to start (e.g. the directory doesn't exist).
///
/// Pure filesystem-watch plumbing — no [`PolicyEngine`]/`AppState` involved —
/// so it's testable on its own, independent of [`reload_now`].
fn start_fs_watcher(
    watch_path: PathBuf,
) -> Option<(Debouncer<RecommendedWatcher>, mpsc::UnboundedReceiver<()>)> {
    let watch_dir = watch_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let (tx, rx) = mpsc::unbounded_channel::<()>();

    let mut debouncer = match new_debouncer(DEBOUNCE_WINDOW, move |res: DebounceEventResult| {
        match res {
            Ok(events) => {
                if events.iter().any(|e| e.path == watch_path) {
                    // Unbounded send; only fails if the receiver has already
                    // been dropped (e.g. the watching task exited during
                    // shutdown), which is fine to ignore here.
                    let _ = tx.send(());
                }
            }
            Err(e) => tracing::warn!("Cedar policy hot-reload watcher error: {:?}", e),
        }
    }) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to start Cedar policy hot-reload watcher: {:?}", e);
            return None;
        }
    };

    if let Err(e) = debouncer
        .watcher()
        .watch(&watch_dir, RecursiveMode::NonRecursive)
    {
        tracing::error!(
            "Failed to watch directory {:?} for Cedar policy hot-reload: {:?}",
            watch_dir,
            e
        );
        return None;
    }

    Some((debouncer, rx))
}

/// Starts the background hot-reload watcher for `policy_path`. Returns
/// `None` (a complete no-op) when `AEGIS_POLICY_HOT_RELOAD` isn't set to
/// `"true"`, or if the underlying `notify` watcher fails to start — logged,
/// not fatal, since the gateway still runs correctly with manual-reload-only
/// behavior via `POST /v1/policies/reload`.
pub fn spawn_policy_hot_reload_watcher(
    state: Arc<AppState>,
    policy_path: PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    if !hot_reload_enabled() {
        return None;
    }

    let (debouncer, mut rx) = start_fs_watcher(policy_path.clone())?;

    tracing::info!(
        "Cedar policy hot-reload enabled — watching {:?} for changes",
        policy_path
    );

    Some(tokio::spawn(async move {
        // Keep the debouncer (and its underlying OS watch) alive for the
        // life of this task; dropping it stops delivering events.
        let _debouncer = debouncer;
        while rx.recv().await.is_some() {
            reload_now(&state.policy_engine, &policy_path).await;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_api::models::{
        AuthorizeAgentContext, AuthorizeDynamicContext, AuthorizeRequest, AuthorizeToolCall,
    };

    #[test]
    fn disabled_by_default_when_env_var_unset() {
        // #883: mirrors the otel.rs / SQLCipher convention of not mutating
        // process-global env vars inside a binary that `cargo test` runs
        // concurrently — this only asserts the *documented contract* against
        // whatever ambient env the test happens to run in, not a fixed
        // branch (see otel.rs's `init_tracer_provider_is_noop_when_endpoint_unset`
        // for the same pattern and rationale).
        let expected = std::env::var("AEGIS_POLICY_HOT_RELOAD")
            .map(|v| v == "true")
            .unwrap_or(false);
        assert_eq!(hot_reload_enabled(), expected);
    }

    fn permissive_request() -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            dry_run: None,
            agent: AuthorizeAgentContext {
                id: "hot-reload-test-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "test_tool".to_string(),
                action: "test_action".to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "unknown".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        }
    }

    #[tokio::test]
    async fn reload_now_picks_up_changed_policy_file_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hotreload.cedar");
        std::fs::write(&path, "// no policies yet\n").unwrap();

        let engine = PolicyEngine::init(&path).await.unwrap();
        let request = permissive_request();

        // Empty policy set: Cedar's default is deny.
        let before = engine
            .authorize("hot_reload_test_tenant", &request, "low", true, false)
            .unwrap();
        assert_eq!(before.decision, "deny");

        std::fs::write(&path, "permit(principal, action, resource);\n").unwrap();
        reload_now(&engine, &path).await;

        let after = engine
            .authorize("hot_reload_test_tenant", &request, "low", true, false)
            .unwrap();
        assert_eq!(after.decision, "allow");
    }

    #[tokio::test]
    async fn reload_now_keeps_last_good_policy_on_parse_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hotreload.cedar");
        std::fs::write(&path, "permit(principal, action, resource);\n").unwrap();

        let engine = PolicyEngine::init(&path).await.unwrap();
        let request = permissive_request();

        let before = engine
            .authorize("hot_reload_test_tenant", &request, "low", true, false)
            .unwrap();
        assert_eq!(before.decision, "allow");

        // A syntactically invalid edit must not clobber the last-good policy
        // set — `reload_now`/`reload_file` only swap in new state once the
        // new content parses successfully.
        std::fs::write(&path, "this is not valid cedar {{{\n").unwrap();
        reload_now(&engine, &path).await;

        let after = engine
            .authorize("hot_reload_test_tenant", &request, "low", true, false)
            .unwrap();
        assert_eq!(after.decision, "allow");
    }

    #[tokio::test]
    async fn start_fs_watcher_emits_event_when_watched_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watched.cedar");
        std::fs::write(&path, "initial\n").unwrap();

        let (_debouncer, mut rx) = start_fs_watcher(path.clone()).expect("watcher should start");

        std::fs::write(&path, "changed\n").unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("expected a change notification within 5s");
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn start_fs_watcher_ignores_changes_to_other_files_in_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let watched_path = dir.path().join("watched.cedar");
        let other_path = dir.path().join("unrelated.txt");
        std::fs::write(&watched_path, "initial\n").unwrap();
        std::fs::write(&other_path, "initial\n").unwrap();

        let (_debouncer, mut rx) =
            start_fs_watcher(watched_path.clone()).expect("watcher should start");

        std::fs::write(&other_path, "changed\n").unwrap();

        // No event should arrive for the unrelated file within a window well
        // past the debounce duration.
        let result = tokio::time::timeout(Duration::from_millis(800), rx.recv()).await;
        assert!(
            result.is_err(),
            "watcher should not emit an event for a different file"
        );
    }
}
