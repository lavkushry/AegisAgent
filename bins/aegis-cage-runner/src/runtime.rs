//! Phase 4.1 (Agent Cage): the `SandboxRuntime` trait
//! (`docs/AegisAgent_Agent_Cage.md`, section 5) — the abstraction every
//! concrete backend (Docker first, then Kubernetes/gVisor/Kata/Firecracker)
//! implements. The cage runner talks to this trait only; it never assumes
//! Docker (or any other backend) directly, so swapping backends doesn't
//! touch call sites.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CageError;
use crate::spec::SandboxSpec;

/// An opaque handle to a created sandbox. Runtimes attach their own
/// backend-specific identifier (container ID, pod name, ...) in
/// `backend_id`; callers never parse or depend on its format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxHandle {
    pub sandbox_id: String,
    pub backend_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    Created,
    Running,
    Paused,
    Exited,
    Killed,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    pub status: SandboxStatus,
    pub exit_code: Option<i32>,
}

/// Why a sandbox is being killed — attached to the evidence trail so a
/// forensic review doesn't have to guess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillReason {
    SignedCommand { command_id: String },
    Timeout,
    PolicyViolation { reason: String },
    OperatorRequest { actor: String },
}

/// A point-in-time capture of a sandbox's evidence-relevant state —
/// preserved on quarantine or suspicious behavior (Agent Cage doc, 8.3).
/// File manifest hashing and full evidence-graph attachment land with the
/// SOC/evidence graph phase; this is the shape the cage runner produces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSnapshot {
    pub sandbox_id: String,
    pub captured_at: DateTime<Utc>,
    pub file_manifest_hashes: HashMap<String, String>,
    pub last_status: SandboxStatus,
}

#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    async fn create(&self, spec: &SandboxSpec) -> Result<SandboxHandle, CageError>;
    async fn start(&self, handle: &SandboxHandle) -> Result<(), CageError>;
    async fn pause(&self, handle: &SandboxHandle) -> Result<(), CageError>;
    async fn resume(&self, handle: &SandboxHandle) -> Result<(), CageError>;
    async fn kill(&self, handle: &SandboxHandle, reason: KillReason) -> Result<(), CageError>;
    async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, CageError>;
    async fn snapshot(&self, handle: &SandboxHandle) -> Result<EvidenceSnapshot, CageError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), CageError>;
}

#[cfg(test)]
pub(crate) mod mock {
    //! A trivial in-memory `SandboxRuntime` used by this crate's own tests
    //! and available to `aegis-cage-runner`'s eventual gateway-facing
    //! wiring for tests that don't need a real container backend. Not a
    //! substitute for the Docker implementation (Phase 4.2).

    use super::*;
    use std::sync::Mutex;

    pub struct MockRuntime {
        states: Mutex<HashMap<String, SandboxState>>,
    }

    impl MockRuntime {
        pub fn new() -> Self {
            Self {
                states: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MockRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl SandboxRuntime for MockRuntime {
        async fn create(&self, spec: &SandboxSpec) -> Result<SandboxHandle, CageError> {
            spec.validate()?;
            let handle = SandboxHandle {
                sandbox_id: spec.sandbox_id.clone(),
                backend_id: format!("mock-{}", spec.sandbox_id),
                created_at: Utc::now(),
            };
            self.states.lock().unwrap().insert(
                handle.sandbox_id.clone(),
                SandboxState {
                    status: SandboxStatus::Created,
                    exit_code: None,
                },
            );
            Ok(handle)
        }

        async fn start(&self, handle: &SandboxHandle) -> Result<(), CageError> {
            let mut states = self.states.lock().unwrap();
            let state = states
                .get_mut(&handle.sandbox_id)
                .ok_or_else(|| CageError::NotFound(handle.sandbox_id.clone()))?;
            state.status = SandboxStatus::Running;
            Ok(())
        }

        async fn pause(&self, handle: &SandboxHandle) -> Result<(), CageError> {
            let mut states = self.states.lock().unwrap();
            let state = states
                .get_mut(&handle.sandbox_id)
                .ok_or_else(|| CageError::NotFound(handle.sandbox_id.clone()))?;
            state.status = SandboxStatus::Paused;
            Ok(())
        }

        async fn resume(&self, handle: &SandboxHandle) -> Result<(), CageError> {
            let mut states = self.states.lock().unwrap();
            let state = states
                .get_mut(&handle.sandbox_id)
                .ok_or_else(|| CageError::NotFound(handle.sandbox_id.clone()))?;
            state.status = SandboxStatus::Running;
            Ok(())
        }

        async fn kill(&self, handle: &SandboxHandle, _reason: KillReason) -> Result<(), CageError> {
            let mut states = self.states.lock().unwrap();
            let state = states
                .get_mut(&handle.sandbox_id)
                .ok_or_else(|| CageError::NotFound(handle.sandbox_id.clone()))?;
            state.status = SandboxStatus::Killed;
            Ok(())
        }

        async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, CageError> {
            self.states
                .lock()
                .unwrap()
                .get(&handle.sandbox_id)
                .cloned()
                .ok_or_else(|| CageError::NotFound(handle.sandbox_id.clone()))
        }

        async fn snapshot(&self, handle: &SandboxHandle) -> Result<EvidenceSnapshot, CageError> {
            let status = self.status(handle).await?.status;
            Ok(EvidenceSnapshot {
                sandbox_id: handle.sandbox_id.clone(),
                captured_at: Utc::now(),
                file_manifest_hashes: HashMap::new(),
                last_status: status,
            })
        }

        async fn destroy(&self, handle: &SandboxHandle) -> Result<(), CageError> {
            self.states.lock().unwrap().remove(&handle.sandbox_id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockRuntime;
    use super::*;
    use crate::spec::{ImageSpec, ResourceLimits, WorkspaceSpec};

    fn sample_spec() -> SandboxSpec {
        SandboxSpec {
            tenant_id: "tenant_a".to_string(),
            run_id: "run_1".to_string(),
            agent_id: "anon".to_string(),
            sandbox_id: "sandbox_1".to_string(),
            mode: "observe".to_string(),
            image: ImageSpec {
                image_ref: "ghcr.io/example/agent:sha256-abc".to_string(),
                digest: "sha256:abc".to_string(),
                read_only_rootfs: true,
            },
            command: vec!["python".to_string(), "agent.py".to_string()],
            working_dir: "/workspace".to_string(),
            workspace: WorkspaceSpec {
                template_id: None,
                max_bytes: 104_857_600,
                max_files: 10_000,
                preserve_on_failure: false,
            },
            resources: ResourceLimits {
                cpu_millis: 1000,
                memory_bytes: 1_073_741_824,
                process_limit: 128,
                timeout_seconds: 900,
                max_stdout_bytes: None,
                max_stderr_bytes: None,
            },
            network: Default::default(),
            tooling: Default::default(),
            environment: Default::default(),
            controlled_mounts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn full_lifecycle_round_trip() {
        let runtime = MockRuntime::new();
        let handle = runtime.create(&sample_spec()).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Created
        );

        runtime.start(&handle).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Running
        );

        runtime.pause(&handle).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Paused
        );

        runtime.resume(&handle).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Running
        );

        runtime.kill(&handle, KillReason::Timeout).await.unwrap();
        assert_eq!(
            runtime.status(&handle).await.unwrap().status,
            SandboxStatus::Killed
        );

        let snapshot = runtime.snapshot(&handle).await.unwrap();
        assert_eq!(snapshot.last_status, SandboxStatus::Killed);

        runtime.destroy(&handle).await.unwrap();
        assert!(runtime.status(&handle).await.is_err());
    }

    #[tokio::test]
    async fn create_rejects_an_invalid_spec() {
        let runtime = MockRuntime::new();
        let mut spec = sample_spec();
        spec.network.direct_internet = true;
        let err = runtime.create(&spec).await.unwrap_err();
        assert!(matches!(err, CageError::InvalidSpec(_)));
    }

    #[tokio::test]
    async fn operations_on_unknown_handle_return_not_found() {
        let runtime = MockRuntime::new();
        let bogus = SandboxHandle {
            sandbox_id: "does-not-exist".to_string(),
            backend_id: "mock-does-not-exist".to_string(),
            created_at: Utc::now(),
        };
        assert!(matches!(
            runtime.start(&bogus).await.unwrap_err(),
            CageError::NotFound(_)
        ));
    }
}
