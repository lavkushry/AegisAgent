//! Phase 4.1 (Agent Cage): `SandboxSpec` — the request shape for
//! `POST /v1/agent-cage/runs` (`docs/AegisAgent_Agent_Cage.md`, section 7),
//! and the forbidden-mount / forbidden-credential validation that makes the
//! cage's default-deny filesystem/credential posture (section 8.1) a
//! property enforced in code rather than just documented.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::CageError;

/// Host paths that must never be reachable from inside a sandbox regardless
/// of what a caller requests — mounting any of these (as a controlled
/// mount's `target_path`, which is where inside the sandbox it would
/// appear) defeats the cage's isolation guarantees outright. Checked as a
/// path-prefix match so `/var/run/docker.sock/anything` is caught too.
const FORBIDDEN_MOUNT_PATH_PREFIXES: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/root/.ssh",
    "/root/.aws",
    "/root/.kube",
    "/root/.config/gcloud",
    "/home", // no host home directory, per section 8.1
    "/etc/kubernetes",
];

/// Environment variable name patterns that indicate a raw credential is
/// being injected directly rather than provisioned through the tool
/// broker / MCP gateway / egress proxy's own credential handling. Matched
/// case-insensitively against the full variable name.
const FORBIDDEN_ENV_NAME_SUBSTRINGS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "TOKEN",
    "API_KEY",
];

/// A small, explicit allowlist of `AEGIS_*`/proxy-config style variable
/// names that would otherwise trip the substring check above but are
/// intentionally not secrets (e.g. `AEGIS_RUN_ID`, `HTTP_PROXY`).
fn is_explicitly_allowed_env_name(name: &str) -> bool {
    matches!(
        name,
        "AEGIS_RUN_ID" | "AEGIS_SANDBOX_ID" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSpec {
    #[serde(rename = "ref")]
    pub image_ref: String,
    pub digest: String,
    #[serde(default = "default_true")]
    pub read_only_rootfs: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSpec {
    #[serde(default)]
    pub template_id: Option<String>,
    pub max_bytes: u64,
    pub max_files: u64,
    #[serde(default)]
    pub preserve_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub process_limit: u32,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub max_stdout_bytes: Option<u64>,
    #[serde(default)]
    pub max_stderr_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSpec {
    /// Must be `false` — direct internet access bypasses the egress proxy
    /// entirely, which is never allowed for a cage sandbox.
    #[serde(default)]
    pub direct_internet: bool,
    #[serde(default)]
    pub egress_proxy_url: Option<String>,
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolingSpec {
    #[serde(default)]
    pub tool_broker_url: Option<String>,
    #[serde(default)]
    pub mcp_gateway_url: Option<String>,
}

/// A source that isn't an arbitrary host path — this closed set is itself
/// what makes "no host filesystem by default" a schema-level guarantee
/// rather than something validation has to catch after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountSourceType {
    GitSnapshot,
    Artifact,
    SecretlessConfig,
    Tmpfs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlledMount {
    pub mount_id: String,
    pub source_type: MountSourceType,
    pub target_path: String,
    #[serde(default = "default_true")]
    pub read_only: bool,
    pub reason: String,
    pub approved_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub tenant_id: String,
    pub run_id: String,
    pub agent_id: String,
    pub sandbox_id: String,
    /// `observe` | `enforce` | `lockdown`.
    pub mode: String,
    pub image: ImageSpec,
    pub command: Vec<String>,
    pub working_dir: String,
    pub workspace: WorkspaceSpec,
    pub resources: ResourceLimits,
    #[serde(default)]
    pub network: NetworkSpec,
    #[serde(default)]
    pub tooling: ToolingSpec,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub controlled_mounts: Vec<ControlledMount>,
}

impl SandboxSpec {
    /// Validate structural sanity plus the cage's non-negotiable
    /// invariants: no direct internet, no forbidden mount paths, no raw
    /// credential environment variables. Fails closed — any violation is
    /// an error, never a silently-dropped field.
    pub fn validate(&self) -> Result<(), CageError> {
        if self.image.image_ref.trim().is_empty() {
            return Err(CageError::InvalidSpec("image.ref must not be empty".into()));
        }
        if self.command.is_empty() {
            return Err(CageError::InvalidSpec("command must not be empty".into()));
        }
        if self.resources.timeout_seconds == 0 {
            return Err(CageError::InvalidSpec(
                "resources.timeout_seconds must be greater than zero".into(),
            ));
        }
        if self.network.direct_internet {
            return Err(CageError::InvalidSpec(
                "network.direct_internet must be false — all egress goes through the egress proxy"
                    .into(),
            ));
        }

        self.validate_mounts()?;
        self.validate_environment()?;
        Ok(())
    }

    fn validate_mounts(&self) -> Result<(), CageError> {
        for mount in &self.controlled_mounts {
            for forbidden in FORBIDDEN_MOUNT_PATH_PREFIXES {
                if mount.target_path.starts_with(forbidden) {
                    return Err(CageError::InvalidSpec(format!(
                        "controlled mount {:?} targets forbidden path {:?}",
                        mount.mount_id, mount.target_path
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_environment(&self) -> Result<(), CageError> {
        for name in self.environment.keys() {
            if is_explicitly_allowed_env_name(name) {
                continue;
            }
            let upper = name.to_ascii_uppercase();
            for forbidden in FORBIDDEN_ENV_NAME_SUBSTRINGS {
                if upper.contains(forbidden) {
                    return Err(CageError::InvalidSpec(format!(
                        "environment variable {name:?} looks like a raw credential and cannot be injected directly"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_spec() -> SandboxSpec {
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
                max_stdout_bytes: Some(10_485_760),
                max_stderr_bytes: Some(10_485_760),
            },
            network: NetworkSpec::default(),
            tooling: ToolingSpec::default(),
            environment: HashMap::new(),
            controlled_mounts: Vec::new(),
        }
    }

    #[test]
    fn minimal_spec_validates_cleanly() {
        minimal_spec().validate().unwrap();
    }

    #[test]
    fn empty_image_ref_is_rejected() {
        let mut spec = minimal_spec();
        spec.image.image_ref = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn direct_internet_is_rejected() {
        let mut spec = minimal_spec();
        spec.network.direct_internet = true;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn no_docker_socket_mount_is_allowed() {
        let mut spec = minimal_spec();
        spec.controlled_mounts.push(ControlledMount {
            mount_id: "mnt_1".to_string(),
            source_type: MountSourceType::Tmpfs,
            target_path: "/var/run/docker.sock".to_string(),
            read_only: true,
            reason: "trying to sneak in docker control".to_string(),
            approved_by: "attacker".to_string(),
        });
        let err = spec.validate().unwrap_err();
        assert!(matches!(err, CageError::InvalidSpec(_)));
    }

    #[test]
    fn no_host_filesystem_mount_by_default() {
        // No controlled_mounts at all — the default case.
        let spec = minimal_spec();
        assert!(spec.controlled_mounts.is_empty());
        spec.validate().unwrap();

        // Explicitly trying to reach the host home directory is rejected.
        let mut with_home_mount = minimal_spec();
        with_home_mount.controlled_mounts.push(ControlledMount {
            mount_id: "mnt_2".to_string(),
            source_type: MountSourceType::Tmpfs,
            target_path: "/home/operator/.bashrc".to_string(),
            read_only: true,
            reason: "wants host home dir".to_string(),
            approved_by: "attacker".to_string(),
        });
        assert!(with_home_mount.validate().is_err());
    }

    #[test]
    fn ssh_agent_and_cloud_credential_mounts_are_rejected() {
        for path in [
            "/root/.ssh/id_rsa",
            "/root/.aws/credentials",
            "/root/.kube/config",
        ] {
            let mut spec = minimal_spec();
            spec.controlled_mounts.push(ControlledMount {
                mount_id: "mnt".to_string(),
                source_type: MountSourceType::SecretlessConfig,
                target_path: path.to_string(),
                read_only: true,
                reason: "test".to_string(),
                approved_by: "test".to_string(),
            });
            assert!(spec.validate().is_err(), "expected {path} to be rejected");
        }
    }

    #[test]
    fn legitimate_controlled_mount_is_allowed() {
        let mut spec = minimal_spec();
        spec.controlled_mounts.push(ControlledMount {
            mount_id: "mnt_3".to_string(),
            source_type: MountSourceType::GitSnapshot,
            target_path: "/workspace/input".to_string(),
            read_only: true,
            reason: "needed for benchmark input".to_string(),
            approved_by: "policy".to_string(),
        });
        spec.validate().unwrap();
    }

    #[test]
    fn no_raw_credential_env_var_names() {
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "STRIPE_API_KEY",
            "SSH_PRIVATE_KEY",
        ] {
            let mut spec = minimal_spec();
            spec.environment
                .insert(name.to_string(), "value".to_string());
            let err = spec.validate().unwrap_err();
            assert!(
                matches!(err, CageError::InvalidSpec(_)),
                "expected {name} to be rejected"
            );
        }
    }

    #[test]
    fn allowed_env_var_names_pass() {
        let mut spec = minimal_spec();
        spec.environment
            .insert("AEGIS_RUN_ID".to_string(), "run_1".to_string());
        spec.environment.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        spec.validate().unwrap();
    }

    #[test]
    fn empty_command_is_rejected() {
        let mut spec = minimal_spec();
        spec.command.clear();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let mut spec = minimal_spec();
        spec.resources.timeout_seconds = 0;
        assert!(spec.validate().is_err());
    }
}
