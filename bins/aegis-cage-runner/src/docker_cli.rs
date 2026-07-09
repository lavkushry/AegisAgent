//! Phase 4.2 (Agent Cage): a thin async wrapper over the `docker` CLI.
//! Shelling out rather than linking a Docker Engine API client keeps this
//! crate's dependency footprint small and the exact command line auditable
//! at a glance — every flag that enforces an isolation guarantee (no
//! Docker socket, no direct internet, resource limits) is visible in one
//! place ([`build_create_args`]).

use tokio::process::Command;

use crate::error::CageError;
use crate::runtime::{SandboxState, SandboxStatus};
use crate::spec::SandboxSpec;
use std::path::Path;

async fn run_docker(args: &[String]) -> Result<String, CageError> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| CageError::Runtime(format!("failed to invoke docker: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CageError::Runtime(format!(
            "docker {} failed: {}",
            args.first().map(String::as_str).unwrap_or(""),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `true` if the `docker` CLI is installed and a daemon is reachable.
/// Callers use this to skip Docker-dependent tests in environments without
/// a daemon (this crate's own CI-independent local dev) rather than fail.
pub async fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Every flag here maps directly to an isolation guarantee from
/// `docs/AegisAgent_Agent_Cage.md` section 8: `--network none` (no direct
/// internet — the spec itself already forbids `direct_internet: true`, this
/// is defense in depth at the runtime layer too), no `-v
/// /var/run/docker.sock`, no host paths beyond the isolated workspace,
/// `--read-only` when the image requests it, and best-effort resource caps
/// so one sandbox can't starve the host.
fn build_create_args(
    spec: &SandboxSpec,
    container_name: &str,
    workspace_dir: &Path,
) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--network".to_string(),
        "none".to_string(),
        "--pids-limit".to_string(),
        spec.resources.process_limit.to_string(),
        "--memory".to_string(),
        spec.resources.memory_bytes.to_string(),
        "--cpus".to_string(),
        format!("{:.3}", spec.resources.cpu_millis as f64 / 1000.0),
    ];

    if spec.image.read_only_rootfs {
        args.push("--read-only".to_string());
    }

    args.push("-v".to_string());
    args.push(format!("{}:{}", workspace_dir.display(), spec.working_dir));
    args.push("-w".to_string());
    args.push(spec.working_dir.clone());

    for (key, value) in &spec.environment {
        args.push("-e".to_string());
        args.push(format!("{key}={value}"));
    }

    // `--` marks the end of docker-create's own flags: without it, an
    // `image_ref` or leading `command` token starting with `-` (e.g.
    // "--privileged") is parsed as a docker CLI flag instead of the image
    // name, letting a tenant-supplied spec silently override the isolation
    // flags set above (see security review, cage-runner execution loop PR).
    args.push("--".to_string());
    args.push(spec.image.image_ref.clone());
    args.extend(spec.command.iter().cloned());
    args
}

/// `docker create` — allocates the container without starting it, so the
/// caller controls exactly when it begins running. Returns the backend
/// container ID.
pub async fn create(
    spec: &SandboxSpec,
    container_name: &str,
    workspace_dir: &Path,
) -> Result<String, CageError> {
    let args = build_create_args(spec, container_name, workspace_dir);
    run_docker(&args).await
}

pub async fn start(container_id: &str) -> Result<(), CageError> {
    run_docker(&["start".to_string(), container_id.to_string()])
        .await
        .map(|_| ())
}

pub async fn pause(container_id: &str) -> Result<(), CageError> {
    run_docker(&["pause".to_string(), container_id.to_string()])
        .await
        .map(|_| ())
}

pub async fn unpause(container_id: &str) -> Result<(), CageError> {
    run_docker(&["unpause".to_string(), container_id.to_string()])
        .await
        .map(|_| ())
}

pub async fn kill(container_id: &str) -> Result<(), CageError> {
    run_docker(&["kill".to_string(), container_id.to_string()])
        .await
        .map(|_| ())
}

/// Remove the container. `-f` so this also works on a still-running
/// container (destroy doesn't require a prior kill).
pub async fn remove(container_id: &str) -> Result<(), CageError> {
    run_docker(&["rm".to_string(), "-f".to_string(), container_id.to_string()])
        .await
        .map(|_| ())
}

pub async fn inspect_status(container_id: &str) -> Result<SandboxState, CageError> {
    let output = run_docker(&[
        "inspect".to_string(),
        "--format".to_string(),
        "{{.State.Status}}\t{{.State.ExitCode}}".to_string(),
        container_id.to_string(),
    ])
    .await?;
    let (status_str, exit_code_str) = output
        .split_once('\t')
        .ok_or_else(|| CageError::Runtime(format!("unexpected docker inspect output: {output}")))?;

    let status = match status_str {
        "created" => SandboxStatus::Created,
        "running" => SandboxStatus::Running,
        "paused" => SandboxStatus::Paused,
        // "exited", "dead", "removing", "restarting" all mean "not running
        // anymore" for this skeleton's purposes.
        _ => SandboxStatus::Exited,
    };
    let exit_code = exit_code_str.trim().parse::<i32>().ok();

    Ok(SandboxState {
        status,
        exit_code: if status == SandboxStatus::Exited {
            exit_code
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ImageSpec, NetworkSpec, ResourceLimits, ToolingSpec, WorkspaceSpec};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn spec_with(image_ref: &str, command: Vec<&str>) -> SandboxSpec {
        SandboxSpec {
            tenant_id: "tenant_a".to_string(),
            run_id: "run_1".to_string(),
            agent_id: "anon".to_string(),
            sandbox_id: "sandbox_1".to_string(),
            mode: "observe".to_string(),
            image: ImageSpec {
                image_ref: image_ref.to_string(),
                digest: "sha256:abc".to_string(),
                read_only_rootfs: true,
            },
            command: command.into_iter().map(str::to_string).collect(),
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
            network: NetworkSpec::default(),
            tooling: ToolingSpec::default(),
            environment: HashMap::new(),
            controlled_mounts: Vec::new(),
        }
    }

    /// Regression test for the argument-injection finding from the
    /// cage-runner execution-loop security review: without a `--`
    /// end-of-options marker, an `image_ref`/`command` starting with `-`
    /// would be parsed as docker CLI flags (e.g. `--privileged`) instead of
    /// positional image/command arguments, silently overriding the
    /// isolation flags set earlier in `build_create_args`.
    #[test]
    fn end_of_options_marker_precedes_the_image_ref() {
        let spec = spec_with("--privileged", vec!["--pid=host", "alpine"]);
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));

        let dash_dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("build_create_args must include a `--` end-of-options marker");
        assert_eq!(
            args[dash_dash_pos + 1],
            "--privileged",
            "image_ref must immediately follow the `--` marker"
        );
        assert_eq!(args[dash_dash_pos + 2], "--pid=host");
        assert_eq!(args[dash_dash_pos + 3], "alpine");
    }

    #[test]
    fn normal_image_ref_and_command_are_placed_after_the_marker() {
        let spec = spec_with("alpine:latest", vec!["sleep", "5"]);
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));

        let dash_dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&args[dash_dash_pos + 1..], &["alpine:latest", "sleep", "5"]);
    }
}
