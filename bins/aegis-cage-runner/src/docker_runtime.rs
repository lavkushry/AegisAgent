//! Phase 4.2 (Agent Cage): the first concrete `SandboxRuntime` — Docker.
//! Composes the isolated-workspace management ([`crate::workspace`]) with
//! the `docker` CLI wrapper ([`crate::docker_cli`]) into the trait every
//! other backend (Kubernetes, gVisor, Kata, Firecracker) will eventually
//! also implement.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use crate::docker_cli;
use crate::error::CageError;
use crate::events::{CageEvent, CageEventSink, CageEventType, NullEventSink};
use crate::runtime::{
    EvidenceSnapshot, KillReason, SandboxHandle, SandboxRuntime, SandboxState, SandboxStatus,
};
use crate::spec::SandboxSpec;
use crate::workspace::{create_isolated_workspace, destroy_workspace};

/// How often [`DockerRuntime::wait_or_kill_on_timeout`] polls container
/// status while waiting for a run to finish on its own.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

pub struct DockerRuntime {
    workspace_root: PathBuf,
    /// Maps `sandbox_id` -> its isolated workspace directory, so `destroy`
    /// knows what to clean up without re-deriving the path (and so a
    /// caller can't accidentally point cleanup at an arbitrary directory).
    workspaces: Mutex<HashMap<String, PathBuf>>,
    event_sink: Arc<dyn CageEventSink>,
}

impl DockerRuntime {
    pub fn new(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            workspaces: Mutex::new(HashMap::new()),
            event_sink: Arc::new(NullEventSink),
        }
    }

    /// Same as [`Self::new`], but with an explicit destination for the
    /// `agent_run_started`/`process_started`/`process_exited`/
    /// `agent_run_finished` events this runtime emits over its lifecycle
    /// (Phase 4.4). Defaults to [`NullEventSink`] when unset.
    pub fn with_event_sink(workspace_root: PathBuf, event_sink: Arc<dyn CageEventSink>) -> Self {
        Self {
            workspace_root,
            workspaces: Mutex::new(HashMap::new()),
            event_sink,
        }
    }

    fn emit(&self, event_type: CageEventType, handle: &SandboxHandle, exit_code: Option<i32>) {
        self.event_sink.record(
            CageEvent::new(
                event_type,
                &handle.tenant_id,
                &handle.run_id,
                &handle.sandbox_id,
            )
            .with_exit_code(exit_code),
        );
    }

    fn container_name(sandbox_id: &str) -> String {
        format!("aegis-cage-{sandbox_id}")
    }

    fn workspace_dir(&self, sandbox_id: &str) -> Result<PathBuf, CageError> {
        self.workspaces
            .lock()
            .unwrap()
            .get(sandbox_id)
            .cloned()
            .ok_or_else(|| CageError::NotFound(sandbox_id.to_string()))
    }

    /// Poll until the sandbox exits on its own or `timeout` elapses,
    /// whichever comes first. On timeout, kills it and reports
    /// [`SandboxStatus::TimedOut`] rather than whatever raw status Docker
    /// reports for a just-killed container — the caller needs to know
    /// *why* it stopped running, not just that it did.
    pub async fn wait_or_kill_on_timeout(
        &self,
        handle: &SandboxHandle,
        timeout: Duration,
    ) -> Result<SandboxState, CageError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let state = self.status(handle).await?;
            if state.status != SandboxStatus::Running {
                // The process ended on its own — not via our own `kill()`
                // call below, which emits this event itself.
                self.emit(CageEventType::ProcessExited, handle, state.exit_code);
                return Ok(state);
            }
            if tokio::time::Instant::now() >= deadline {
                self.kill(handle, KillReason::Timeout).await?;
                return Ok(SandboxState {
                    status: SandboxStatus::TimedOut,
                    exit_code: None,
                });
            }
            tokio::time::sleep(POLL_INTERVAL.min(deadline - tokio::time::Instant::now())).await;
        }
    }
}

#[async_trait]
impl SandboxRuntime for DockerRuntime {
    async fn create(&self, spec: &SandboxSpec) -> Result<SandboxHandle, CageError> {
        spec.validate()?;
        let workspace_dir = create_isolated_workspace(&self.workspace_root, &spec.sandbox_id)?;
        let container_name = Self::container_name(&spec.sandbox_id);

        let container_id = match docker_cli::create(spec, &container_name, &workspace_dir).await {
            Ok(id) => id,
            Err(e) => {
                // Don't leak the workspace directory if container creation
                // failed partway through.
                let _ = destroy_workspace(&workspace_dir);
                return Err(e);
            }
        };

        self.workspaces
            .lock()
            .unwrap()
            .insert(spec.sandbox_id.clone(), workspace_dir);

        Ok(SandboxHandle {
            sandbox_id: spec.sandbox_id.clone(),
            backend_id: container_id,
            tenant_id: spec.tenant_id.clone(),
            run_id: spec.run_id.clone(),
            created_at: Utc::now(),
        })
    }

    async fn start(&self, handle: &SandboxHandle) -> Result<(), CageError> {
        docker_cli::start(&handle.backend_id).await?;
        self.emit(CageEventType::AgentRunStarted, handle, None);
        self.emit(CageEventType::ProcessStarted, handle, None);
        Ok(())
    }

    async fn pause(&self, handle: &SandboxHandle) -> Result<(), CageError> {
        docker_cli::pause(&handle.backend_id).await
    }

    async fn resume(&self, handle: &SandboxHandle) -> Result<(), CageError> {
        docker_cli::unpause(&handle.backend_id).await
    }

    async fn kill(&self, handle: &SandboxHandle, _reason: KillReason) -> Result<(), CageError> {
        docker_cli::kill(&handle.backend_id).await?;
        // A killed container doesn't report a normal exit code — Docker
        // has already torn down the process by signal.
        self.emit(CageEventType::ProcessExited, handle, None);
        Ok(())
    }

    async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, CageError> {
        docker_cli::inspect_status(&handle.backend_id).await
    }

    async fn snapshot(&self, handle: &SandboxHandle) -> Result<EvidenceSnapshot, CageError> {
        let workspace_dir = self.workspace_dir(&handle.sandbox_id)?;
        let status = self.status(handle).await?.status;
        let mut file_manifest_hashes = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&workspace_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    let hash = crc32fast::hash(&bytes);
                    if let Some(name) = entry.file_name().to_str() {
                        file_manifest_hashes.insert(name.to_string(), format!("crc32:{hash:08x}"));
                    }
                }
            }
        }
        Ok(EvidenceSnapshot {
            sandbox_id: handle.sandbox_id.clone(),
            captured_at: Utc::now(),
            file_manifest_hashes,
            last_status: status,
        })
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), CageError> {
        docker_cli::remove(&handle.backend_id).await?;
        if let Some(workspace_dir) = self.workspaces.lock().unwrap().remove(&handle.sandbox_id) {
            destroy_workspace(&workspace_dir)?;
        }
        self.emit(CageEventType::AgentRunFinished, handle, None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! These tests exercise a real Docker daemon and are skipped (not
    //! failed) when one isn't reachable — the intent is real coverage in
    //! CI (which has Docker for the Docker Compose E2E / container-scan
    //! jobs) without breaking `cargo test` in a Docker-less dev sandbox.
    //! `alpine:3` is used as the universally-available, tiny test image.

    use super::*;
    use crate::spec::{ImageSpec, NetworkSpec, ResourceLimits, ToolingSpec, WorkspaceSpec};
    use std::collections::HashMap;

    macro_rules! skip_without_docker {
        () => {
            if !docker_cli::docker_available().await {
                eprintln!("skipping: no docker daemon reachable in this environment");
                return;
            }
        };
    }

    fn sleep_spec(sandbox_id: &str, seconds: u64) -> SandboxSpec {
        SandboxSpec {
            tenant_id: "tenant_a".to_string(),
            run_id: format!("run_{sandbox_id}"),
            agent_id: "anon".to_string(),
            sandbox_id: sandbox_id.to_string(),
            mode: "observe".to_string(),
            image: ImageSpec {
                image_ref: "alpine:3".to_string(),
                digest: String::new(),
                read_only_rootfs: false,
            },
            command: vec!["sleep".to_string(), seconds.to_string()],
            working_dir: "/workspace".to_string(),
            workspace: WorkspaceSpec {
                template_id: None,
                max_bytes: 10_485_760,
                max_files: 1000,
                preserve_on_failure: false,
            },
            resources: ResourceLimits {
                cpu_millis: 500,
                memory_bytes: 67_108_864,
                process_limit: 32,
                timeout_seconds: 60,
                max_stdout_bytes: None,
                max_stderr_bytes: None,
            },
            network: NetworkSpec::default(),
            tooling: ToolingSpec::default(),
            environment: HashMap::new(),
            controlled_mounts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn start_and_kill_a_real_container() {
        skip_without_docker!();
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());
        let spec = sleep_spec("cage-test-start-kill", 30);

        let handle = runtime.create(&spec).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Created
        );

        runtime.start(&handle).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Running
        );

        runtime.kill(&handle, KillReason::Timeout).await.unwrap();
        // Docker transitions a killed container to "exited", not a
        // separate "killed" state — this crate's own SandboxStatus::Exited
        // covers it (the KillReason carried into logs/receipts is what
        // records *why*).
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Exited
        );

        runtime.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn two_sandboxes_have_isolated_mounted_workspaces() {
        skip_without_docker!();
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());

        let mut spec_a = sleep_spec("cage-test-isolation-a", 5);
        spec_a.command = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo secret > /workspace/secret.txt".to_string(),
        ];
        let handle_a = runtime.create(&spec_a).await.unwrap();
        runtime.start(&handle_a).await.unwrap();
        runtime
            .wait_or_kill_on_timeout(&handle_a, Duration::from_secs(5))
            .await
            .unwrap();

        let mut spec_b = sleep_spec("cage-test-isolation-b", 5);
        spec_b.command = vec![
            "sh".to_string(),
            "-c".to_string(),
            "ls /workspace".to_string(),
        ];
        let handle_b = runtime.create(&spec_b).await.unwrap();
        runtime.start(&handle_b).await.unwrap();
        runtime
            .wait_or_kill_on_timeout(&handle_b, Duration::from_secs(5))
            .await
            .unwrap();

        // Sandbox b's workspace directory on the host must not contain
        // anything sandbox a wrote — they're mounted from different host
        // directories entirely.
        let workspace_b = runtime.workspace_dir(&handle_b.sandbox_id).unwrap();
        assert!(!workspace_b.join("secret.txt").exists());

        runtime.destroy(&handle_a).await.unwrap();
        runtime.destroy(&handle_b).await.unwrap();
    }

    #[tokio::test]
    async fn timeout_kills_a_long_running_sandbox() {
        skip_without_docker!();
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());
        let spec = sleep_spec("cage-test-timeout", 60); // would run far longer than the timeout below

        let handle = runtime.create(&spec).await.unwrap();
        runtime.start(&handle).await.unwrap();

        let state = runtime
            .wait_or_kill_on_timeout(&handle, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(state.status, SandboxStatus::TimedOut);

        runtime.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn a_quick_command_is_reported_as_exited_before_the_timeout() {
        skip_without_docker!();
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());
        let mut spec = sleep_spec("cage-test-quick-exit", 0);
        spec.command = vec!["true".to_string()];

        let handle = runtime.create(&spec).await.unwrap();
        runtime.start(&handle).await.unwrap();
        let state = runtime
            .wait_or_kill_on_timeout(&handle, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(state.status, SandboxStatus::Exited);

        runtime.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_spec_is_rejected_before_touching_docker_or_the_filesystem() {
        // No docker skip needed — this must fail at validation, before any
        // docker or filesystem call.
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());
        let mut spec = sleep_spec("cage-test-invalid", 5);
        spec.network.direct_internet = true;

        let err = runtime.create(&spec).await.unwrap_err();
        assert!(matches!(err, CageError::InvalidSpec(_)));
        assert!(!root.path().join("cage-test-invalid").exists());
    }

    #[tokio::test]
    async fn a_real_container_lifecycle_emits_the_full_event_timeline() {
        skip_without_docker!();
        use crate::events::{CageEventType, RecordingEventSink};
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let sink = Arc::new(RecordingEventSink::new());
        let runtime = DockerRuntime::with_event_sink(root.path().to_path_buf(), sink.clone());
        let mut spec = sleep_spec("cage-test-events", 0);
        spec.command = vec!["true".to_string()];

        let handle = runtime.create(&spec).await.unwrap();
        runtime.start(&handle).await.unwrap();
        runtime
            .wait_or_kill_on_timeout(&handle, Duration::from_secs(10))
            .await
            .unwrap();
        runtime.destroy(&handle).await.unwrap();

        let events = sink.events();
        let event_types: Vec<CageEventType> = events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            event_types,
            vec![
                CageEventType::AgentRunStarted,
                CageEventType::ProcessStarted,
                CageEventType::ProcessExited,
                CageEventType::AgentRunFinished,
            ]
        );
        for event in &events {
            assert_eq!(event.run_id, spec.run_id);
            assert_eq!(event.sandbox_id, handle.sandbox_id);
        }
    }

    /// Daemon-level regression for host-Docker security review: the
    /// container HostConfig must reflect cap-drop ALL, no-new-privileges,
    /// and network none (not just the argv we built client-side).
    #[tokio::test]
    async fn created_container_hostconfig_enforces_isolation() {
        skip_without_docker!();
        let root = tempfile::tempdir().unwrap();
        let runtime = DockerRuntime::new(root.path().to_path_buf());
        let mut spec = sleep_spec("cage-test-hostconfig", 30);
        // Prefer read-only path so tmpfs hardening is also exercised when
        // the image supports it; alpine rootfs works with --read-only + /tmp.
        spec.image.read_only_rootfs = true;
        spec.command = vec!["sleep".to_string(), "30".to_string()];

        let handle = runtime.create(&spec).await.unwrap();
        let isolation = docker_cli::inspect_isolation(&handle.backend_id)
            .await
            .unwrap();
        // network \t CapDrop JSON \t SecurityOpt JSON \t Privileged
        let parts: Vec<&str> = isolation.split('\t').collect();
        assert!(
            parts.len() >= 4,
            "unexpected inspect_isolation output: {isolation}"
        );
        assert_eq!(
            parts[0], "none",
            "NetworkMode must be none; got {isolation}"
        );
        let cap_drop = parts[1].to_ascii_uppercase();
        assert!(
            cap_drop.contains("ALL"),
            "CapDrop must include ALL; got {isolation}"
        );
        let sec_opt = parts[2].to_ascii_lowercase();
        assert!(
            sec_opt.contains("no-new-privileges"),
            "SecurityOpt must include no-new-privileges; got {isolation}"
        );
        assert_eq!(
            parts[3].to_ascii_lowercase(),
            "false",
            "Privileged must be false; got {isolation}"
        );

        runtime.destroy(&handle).await.unwrap();
    }
}
