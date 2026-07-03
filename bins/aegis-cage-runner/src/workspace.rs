//! Phase 4.2 (Agent Cage): isolated temp workspace management
//! (`docs/AegisAgent_Agent_Cage.md`, section 8.1 — "empty isolated
//! workspace per run, no host home directory"). Pure filesystem logic,
//! deliberately kept independent of any specific `SandboxRuntime` backend
//! so it's testable without a container runtime.

use std::path::{Path, PathBuf};

use crate::error::CageError;

/// Create a fresh, empty directory for `sandbox_id` under `root`, isolated
/// from every other sandbox's workspace. Fails if the directory already
/// exists — a reused `sandbox_id` reusing another run's workspace would
/// leak state between runs, which is exactly the isolation this exists to
/// prevent.
pub fn create_isolated_workspace(root: &Path, sandbox_id: &str) -> Result<PathBuf, CageError> {
    let workspace_dir = root.join(sandbox_id);
    if workspace_dir.exists() {
        return Err(CageError::InvalidSpec(format!(
            "workspace for sandbox {sandbox_id:?} already exists — refusing to reuse it"
        )));
    }
    std::fs::create_dir_all(&workspace_dir)
        .map_err(|e| CageError::Runtime(format!("failed to create workspace directory: {e}")))?;
    Ok(workspace_dir)
}

/// Remove a sandbox's workspace directory and everything in it. Called on
/// `destroy` for a normal cleanup; quarantine preserves the workspace
/// instead by simply never calling this (Agent Cage doc, 8.3).
pub fn destroy_workspace(workspace_dir: &Path) -> Result<(), CageError> {
    if !workspace_dir.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(workspace_dir)
        .map_err(|e| CageError::Runtime(format!("failed to remove workspace directory: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_empty_isolated_directory() {
        let root = tempfile::tempdir().unwrap();
        let workspace = create_isolated_workspace(root.path(), "sandbox-1").unwrap();
        assert!(workspace.exists());
        assert!(workspace.is_dir());
        assert_eq!(
            std::fs::read_dir(&workspace).unwrap().count(),
            0,
            "a freshly created workspace must be empty"
        );
    }

    #[test]
    fn two_sandboxes_get_independent_workspaces() {
        let root = tempfile::tempdir().unwrap();
        let workspace_a = create_isolated_workspace(root.path(), "sandbox-a").unwrap();
        let workspace_b = create_isolated_workspace(root.path(), "sandbox-b").unwrap();
        assert_ne!(workspace_a, workspace_b);

        std::fs::write(workspace_a.join("secret.txt"), b"a's data").unwrap();
        assert!(
            !workspace_b.join("secret.txt").exists(),
            "sandbox b must not see sandbox a's workspace contents"
        );
    }

    #[test]
    fn refuses_to_reuse_an_existing_sandbox_id() {
        let root = tempfile::tempdir().unwrap();
        create_isolated_workspace(root.path(), "sandbox-1").unwrap();
        let err = create_isolated_workspace(root.path(), "sandbox-1").unwrap_err();
        assert!(matches!(err, CageError::InvalidSpec(_)));
    }

    #[test]
    fn destroy_removes_the_workspace_and_its_contents() {
        let root = tempfile::tempdir().unwrap();
        let workspace = create_isolated_workspace(root.path(), "sandbox-1").unwrap();
        std::fs::write(workspace.join("output.txt"), b"agent output").unwrap();

        destroy_workspace(&workspace).unwrap();
        assert!(!workspace.exists());
    }

    #[test]
    fn destroy_on_a_missing_workspace_is_a_harmless_no_op() {
        let root = tempfile::tempdir().unwrap();
        let never_created = root.path().join("never-existed");
        destroy_workspace(&never_created).unwrap();
    }
}
