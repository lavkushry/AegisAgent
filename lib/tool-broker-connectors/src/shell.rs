//! Scoped cage-shell connector — Phase 6.3: runs one command inside the
//! agent's cage workspace with a **scrubbed environment**. This is where
//! "credential not in cage env/logs/events" becomes structural:
//!
//! - `env_clear()` before spawn — the child inherits *nothing* from the
//!   broker process, so `GITHUB_TOKEN` & friends in the broker's own
//!   environment never reach the cage.
//! - The `credential` argument is deliberately ignored — a shell tool
//!   registered with a credential still cannot export it to the command.
//! - The command runs with the workspace as its working directory; argv is
//!   exec'd directly (no `sh -c`), so there is no shell-metacharacter
//!   injection surface inside the broker itself.
//!
//! Output is captured, truncated, and still passes through the executor's
//! sanitize pass before it leaves the broker — defense in depth even though
//! no credential should ever be present.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use aegis_tool_broker_core::{BrokerAction, Connector, ConnectorError, ConnectorOutput, Secret};

/// Captured stdout/stderr are each truncated to this many bytes.
const MAX_STREAM_BYTES: usize = 64 * 1024;

/// The only environment the caged child gets: a fixed PATH. No tokens, no
/// broker internals, no inherited surprises.
const CAGE_PATH: &str = "/usr/bin:/bin";

pub struct ShellConnector {
    /// Canonicalized cage workspace; the child's working directory.
    workspace: PathBuf,
    /// Wall-clock budget per command; the child is killed on expiry.
    timeout: Duration,
}

impl ShellConnector {
    /// `workspace` must already exist — fail at construction, not at spawn.
    pub fn new(workspace: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self {
            workspace: workspace.as_ref().canonicalize()?,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

fn truncate_stream(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_STREAM_BYTES;
    (
        String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_STREAM_BYTES)]).to_string(),
        truncated,
    )
}

#[async_trait]
impl Connector for ShellConnector {
    fn connector_type(&self) -> &'static str {
        "shell"
    }

    async fn execute(
        &self,
        action: &BrokerAction,
        _credential: Option<&Secret>, // deliberately never exported — see module docs
    ) -> Result<ConnectorOutput, ConnectorError> {
        if action.action != "run" {
            return Err(ConnectorError::UnsupportedAction {
                connector: "shell".to_string(),
                action: action.action.clone(),
            });
        }
        let argv: Vec<String> = action
            .parameters
            .get("command")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return Err(ConnectorError::ExecutionFailed(
                "shell run requires parameters.command as a non-empty argv array".to_string(),
            ));
        }

        let mut command = tokio::process::Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&self.workspace)
            // The scrub: nothing from the broker's environment survives.
            .env_clear()
            .env("PATH", CAGE_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let output = tokio::time::timeout(self.timeout, command.output())
            .await
            .map_err(|_| {
                ConnectorError::ExecutionFailed(format!(
                    "command timed out after {:?}",
                    self.timeout
                ))
            })?
            .map_err(|e| ConnectorError::ExecutionFailed(format!("spawn: {e}")))?;

        let (stdout, stdout_truncated) = truncate_stream(&output.stdout);
        let (stderr, stderr_truncated) = truncate_stream(&output.stderr);
        Ok(ConnectorOutput::new(json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
            "truncated": stdout_truncated || stderr_truncated,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv: Value) -> BrokerAction {
        BrokerAction {
            tool: "cage-shell".to_string(),
            action: "run".to_string(),
            resource: None,
            mutates_state: false,
            parameters: json!({ "command": argv }),
        }
    }

    #[tokio::test]
    async fn the_cage_environment_never_contains_the_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shell = ShellConnector::new(dir.path()).expect("connector");

        // Even with a poisoned broker environment *and* a resolved
        // credential handed to the connector, the child sees only PATH.
        std::env::set_var("AEGIS_TEST_POISON_TOKEN", "ghp_env_poison_value");
        let secret = Secret::new("ghp_direct_credential_value");
        let raw = shell
            .execute(&run(json!(["/usr/bin/env"])), Some(&secret))
            .await
            .expect("run env");
        std::env::remove_var("AEGIS_TEST_POISON_TOKEN");

        let stdout = raw.output["stdout"].as_str().expect("stdout").to_string();
        assert!(
            !stdout.contains("ghp_env_poison_value"),
            "env leaked: {stdout}"
        );
        assert!(!stdout.contains("ghp_direct_credential_value"));
        assert!(stdout.contains(&format!("PATH={CAGE_PATH}")));
    }

    #[tokio::test]
    async fn commands_run_inside_the_workspace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shell = ShellConnector::new(dir.path()).expect("connector");
        let raw = shell
            .execute(&run(json!(["/bin/pwd"])), None)
            .await
            .expect("run pwd");
        let cwd = raw.output["stdout"]
            .as_str()
            .expect("stdout")
            .trim()
            .to_string();
        let canonical = dir.path().canonicalize().expect("canonical workspace");
        assert_eq!(Path::new(&cwd), canonical.as_path());
    }

    #[tokio::test]
    async fn a_command_over_budget_is_killed_not_awaited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shell = ShellConnector::new(dir.path())
            .expect("connector")
            .with_timeout(Duration::from_millis(200));
        let err = shell
            .execute(&run(json!(["/bin/sleep", "5"])), None)
            .await
            .expect_err("sleep must exceed the budget");
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn empty_argv_and_unknown_actions_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shell = ShellConnector::new(dir.path()).expect("connector");
        assert!(shell.execute(&run(json!([])), None).await.is_err());

        let mut action = run(json!(["/bin/echo", "hi"]));
        action.action = "exec".to_string();
        assert!(matches!(
            shell.execute(&action, None).await,
            Err(ConnectorError::UnsupportedAction { .. })
        ));
    }
}
