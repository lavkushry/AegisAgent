//! Scoped-filesystem connector — Phase 6.3: file `read`/`write`/`list`
//! confined to one workspace root (the agent's cage workspace). Scoping is
//! structural, not advisory: relative paths only, no `..` components, and
//! the resolved target is canonicalized and prefix-checked against the
//! canonical root — a symlink pointing out of the workspace is caught at
//! resolution time, not trusted.
//!
//! No credential is ever involved: the connector deliberately ignores the
//! `credential` argument, so a filesystem tool registered with a credential
//! by mistake still cannot leak it through file content or the cage.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use serde_json::{json, Value};

use aegis_tool_broker_core::{BrokerAction, Connector, ConnectorError, ConnectorOutput, Secret};

/// Files larger than this are truncated on `read` — the broker is a choke
/// point, not a bulk data plane.
const MAX_READ_BYTES: usize = 64 * 1024;

pub struct FilesystemConnector {
    /// Canonicalized workspace root; every action resolves inside it.
    root: PathBuf,
}

impl FilesystemConnector {
    /// `root` must already exist — fail at construction, not at first use.
    pub fn new(root: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self {
            root: root.as_ref().canonicalize()?,
        })
    }

    /// Resolves `parameters.path` inside the root. Rejects absolute paths
    /// and any `..`/prefix component *before* touching the filesystem, then
    /// re-checks the canonical form (symlink escape) for existing targets.
    fn resolve(&self, action: &BrokerAction, must_exist: bool) -> Result<PathBuf, ConnectorError> {
        let rel = action
            .parameters
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ConnectorError::ExecutionFailed(
                    "filesystem actions require parameters.path".to_string(),
                )
            })?;
        let rel_path = Path::new(rel);
        let escapes = rel_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir));
        if rel_path.is_absolute() || escapes {
            return Err(ConnectorError::ExecutionFailed(format!(
                "path escapes the workspace root: {rel}"
            )));
        }
        let joined = self.root.join(rel_path);
        if must_exist {
            let canonical = joined
                .canonicalize()
                .map_err(|e| ConnectorError::ExecutionFailed(format!("path {rel}: {e}")))?;
            if !canonical.starts_with(&self.root) {
                return Err(ConnectorError::ExecutionFailed(format!(
                    "path escapes the workspace root: {rel}"
                )));
            }
            return Ok(canonical);
        }
        // For writes the leaf may not exist yet; the parent must, and must
        // canonicalize inside the root.
        let parent = joined.parent().unwrap_or(&self.root);
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| ConnectorError::ExecutionFailed(format!("parent of {rel}: {e}")))?;
        if !canonical_parent.starts_with(&self.root) {
            return Err(ConnectorError::ExecutionFailed(format!(
                "path escapes the workspace root: {rel}"
            )));
        }
        Ok(canonical_parent.join(joined.file_name().unwrap_or_default()))
    }
}

#[async_trait]
impl Connector for FilesystemConnector {
    fn connector_type(&self) -> &'static str {
        "filesystem"
    }

    async fn execute(
        &self,
        action: &BrokerAction,
        _credential: Option<&Secret>, // deliberately unused — see module docs
    ) -> Result<ConnectorOutput, ConnectorError> {
        match action.action.as_str() {
            "read" => {
                let path = self.resolve(action, true)?;
                let bytes = tokio::fs::read(&path)
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("read: {e}")))?;
                let truncated = bytes.len() > MAX_READ_BYTES;
                let content =
                    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_READ_BYTES)]).to_string();
                Ok(ConnectorOutput::new(json!({
                    "content": content,
                    "truncated": truncated,
                })))
            }
            "list" => {
                let path = self.resolve(action, true)?;
                let mut dir = tokio::fs::read_dir(&path)
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("list: {e}")))?;
                let mut entries = Vec::new();
                while let Some(entry) = dir
                    .next_entry()
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("list: {e}")))?
                {
                    entries.push(entry.file_name().to_string_lossy().to_string());
                }
                entries.sort_unstable();
                Ok(ConnectorOutput::new(json!({ "entries": entries })))
            }
            "write" => {
                if !action.mutates_state {
                    return Err(ConnectorError::ExecutionFailed(
                        "filesystem write actions must set mutates_state: true".to_string(),
                    ));
                }
                let content = action
                    .parameters
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ConnectorError::ExecutionFailed(
                            "filesystem write requires parameters.content".to_string(),
                        )
                    })?;
                let path = self.resolve(action, false)?;
                tokio::fs::write(&path, content)
                    .await
                    .map_err(|e| ConnectorError::ExecutionFailed(format!("write: {e}")))?;
                Ok(ConnectorOutput::new(json!({
                    "bytes_written": content.len(),
                })))
            }
            other => Err(ConnectorError::UnsupportedAction {
                connector: "filesystem".to_string(),
                action: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(kind: &str, params: Value, mutates: bool) -> BrokerAction {
        BrokerAction {
            tool: "workspace-fs".to_string(),
            action: kind.to_string(),
            resource: None,
            mutates_state: mutates,
            parameters: params,
        }
    }

    #[tokio::test]
    async fn write_then_read_then_list_round_trips_inside_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = FilesystemConnector::new(dir.path()).expect("connector");

        let written = fs
            .execute(
                &action(
                    "write",
                    json!({"path": "notes.txt", "content": "hello"}),
                    true,
                ),
                None,
            )
            .await
            .expect("write");
        assert_eq!(written.output["bytes_written"], json!(5));

        let read = fs
            .execute(&action("read", json!({"path": "notes.txt"}), false), None)
            .await
            .expect("read");
        assert_eq!(read.output["content"], json!("hello"));

        let listed = fs
            .execute(&action("list", json!({"path": "."}), false), None)
            .await
            .expect("list");
        assert_eq!(listed.output["entries"], json!(["notes.txt"]));
    }

    #[tokio::test]
    async fn traversal_and_absolute_paths_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = FilesystemConnector::new(dir.path()).expect("connector");

        for path in ["../outside.txt", "/etc/passwd", "a/../../b"] {
            let err = fs
                .execute(&action("read", json!({"path": path}), false), None)
                .await
                .expect_err("escaping path must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("escapes the workspace root") || msg.contains("path"),
                "unexpected error for {path}: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn a_symlink_pointing_out_of_the_root_is_caught_at_resolution() {
        let outside = tempfile::tempdir().expect("outside dir");
        let secret_file = outside.path().join("secret.txt");
        std::fs::write(&secret_file, "outside contents").expect("seed outside file");

        let dir = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(&secret_file, dir.path().join("sneaky")).expect("symlink");
        let fs = FilesystemConnector::new(dir.path()).expect("connector");

        let err = fs
            .execute(&action("read", json!({"path": "sneaky"}), false), None)
            .await
            .expect_err("symlink escape must be rejected");
        assert!(err.to_string().contains("escapes the workspace root"));
    }

    #[tokio::test]
    async fn write_without_mutates_state_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = FilesystemConnector::new(dir.path()).expect("connector");
        let err = fs
            .execute(
                &action("write", json!({"path": "x.txt", "content": "y"}), false),
                None,
            )
            .await
            .expect_err("write without mutates_state must fail");
        assert!(err.to_string().contains("mutates_state"));
    }
}
