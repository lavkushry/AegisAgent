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

/// Proxy env keys the cage **forces** when `egress_proxy_url` is set.
/// Tenant-supplied values for these keys are stripped and replaced so a
/// compromised agent cannot point itself at a different proxy or clear them.
const FORCED_PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// How the sandbox reaches the egress proxy (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
struct EgressNetworkPlan {
    /// Docker `--network` value: `none` (no egress) or `bridge` (proxy path).
    docker_network: &'static str,
    /// Proxy URL injected into the container (loopback rewritten for Docker).
    proxy_url: Option<String>,
    /// When true, add `host.docker.internal:host-gateway` so containers can
    /// reach a proxy bound on the host loopback.
    add_host_gateway: bool,
}

/// Plan forced egress for a validated [`SandboxSpec`].
///
/// | `egress_proxy_url` | Docker network | Proxy env |
/// |--------------------|----------------|-----------|
/// | unset              | `none`         | none (no egress at all) |
/// | set                | `bridge`       | forced HTTP(S)_PROXY to that URL |
///
/// Residual: with `bridge`, a malicious process can still open raw sockets
/// that bypass HTTP_PROXY. Hard network isolation (internal netns + sidecar,
/// or always-on transparent proxy) remains a follow-up. Soft forced egress
/// still beats open internet: cooperative HTTP clients and most agent SDKs
/// honor the injected proxy, and `direct_internet` stays forbidden.
fn plan_egress_network(spec: &SandboxSpec) -> EgressNetworkPlan {
    let raw = spec
        .network
        .egress_proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match raw {
        None => EgressNetworkPlan {
            docker_network: "none",
            proxy_url: None,
            add_host_gateway: false,
        },
        Some(url) => {
            let (container_url, add_host_gateway) = rewrite_loopback_proxy_for_container(url);
            EgressNetworkPlan {
                docker_network: "bridge",
                proxy_url: Some(container_url),
                add_host_gateway,
            }
        }
    }
}

/// Map host-loopback proxy URLs to `host.docker.internal` so a container on
/// the Docker bridge can reach a proxy listening on the host (compose
/// `network_mode: host`, local `aegis-egress-proxy` on 127.0.0.1:8888).
fn rewrite_loopback_proxy_for_container(proxy_url: &str) -> (String, bool) {
    const LOOPBACK_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];
    for scheme in ["http://", "https://"] {
        let Some(rest) = proxy_url.strip_prefix(scheme) else {
            continue;
        };
        for host in LOOPBACK_HOSTS {
            if rest == *host
                || rest.starts_with(&format!("{host}:"))
                || rest.starts_with(&format!("{host}/"))
            {
                let after_host = &rest[host.len()..];
                return (format!("{scheme}host.docker.internal{after_host}"), true);
            }
        }
    }
    (proxy_url.to_string(), false)
}

/// Every flag here maps directly to an isolation guarantee from
/// `docs/AegisAgent_Agent_Cage.md` section 8 and the host-Docker security
/// review (`docs/AegisAgent_Cage_Docker_Security.md`):
///
/// - `--network none` — no direct internet (spec also forbids
///   `direct_internet: true`; this is defense in depth at the runtime)
/// - `--cap-drop ALL` — no Linux capabilities inside the sandbox
/// - `--security-opt no-new-privileges:true` — block setuid/file-cap
///   elevation after exec
/// - no `-v /var/run/docker.sock`, no host paths beyond the isolated
///   workspace
/// - `--read-only` + a small `/tmp` tmpfs when the image requests a
///   read-only rootfs
/// - best-effort resource caps so one sandbox can't starve the host
///
/// Residual (documented): the **runner** process still needs host
/// `docker.sock` access to create these sandboxes — that is root-equivalent
/// on the runner node and is not mitigated by these sandbox flags.
fn build_create_args(
    spec: &SandboxSpec,
    container_name: &str,
    workspace_dir: &Path,
    egress: &EgressNetworkPlan,
) -> Vec<String> {
    let egress = plan_egress_network(spec);

    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--network".to_string(),
        "none".to_string(),
        // Drop every Linux capability. Sandboxes must not keep NET_ADMIN,
        // SYS_ADMIN, etc. even if the image USER is root.
        "--cap-drop".to_string(),
        "ALL".to_string(),
        // Prevent setuid binaries / file capabilities from elevating after
        // exec (complements cap-drop for root-looking images).
        "--security-opt".to_string(),
        "no-new-privileges:true".to_string(),
        "--pids-limit".to_string(),
        spec.resources.process_limit.to_string(),
        "--memory".to_string(),
        spec.resources.memory_bytes.to_string(),
        "--cpus".to_string(),
        format!("{:.3}", spec.resources.cpu_millis as f64 / 1000.0),
    ];

    if egress.add_host_gateway {
        args.push("--add-host".to_string());
        args.push("host.docker.internal:host-gateway".to_string());
    }

    if spec.image.read_only_rootfs {
        args.push("--read-only".to_string());
        // Writable scratch space that still blocks exec of dropped binaries
        // and setuid bits. Size is intentionally small — work product goes
        // on the isolated workspace volume, not /tmp.
        args.push("--tmpfs".to_string());
        args.push("/tmp:rw,nosuid,nodev,noexec,size=64m".to_string());
    }

    args.push("-v".to_string());
    args.push(format!("{}:{}", workspace_dir.display(), spec.working_dir));
    args.push("-w".to_string());
    args.push(spec.working_dir.clone());

    // Tenant env first, but drop keys we will force below so a compromised
    // agent cannot clear or retarget the proxy.
    for (key, value) in &spec.environment {
        if FORCED_PROXY_ENV_KEYS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        {
            continue;
        }
        args.push("-e".to_string());
        args.push(format!("{key}={value}"));
    }

    if let Some(proxy_url) = &egress.proxy_url {
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            args.push("-e".to_string());
            args.push(format!("{key}={proxy_url}"));
        }
        // Empty NO_PROXY: do not let the workload bypass the proxy for
        // "local" destinations by default.
        args.push("-e".to_string());
        args.push("NO_PROXY=".to_string());
        args.push("-e".to_string());
        args.push("no_proxy=".to_string());

        if !spec.network.allowed_destinations.is_empty() {
            args.push("-e".to_string());
            args.push(format!(
                "AEGIS_EGRESS_ALLOWED_DESTINATIONS={}",
                spec.network.allowed_destinations.join(",")
            ));
        }
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
/// caller controls exactly when it begins running. Returns
/// `(container_id, optional_network_name_to_cleanup)`.
pub async fn create(
    spec: &SandboxSpec,
    container_name: &str,
    workspace_dir: &Path,
) -> Result<(String, Option<String>), CageError> {
    let egress = plan_egress_network(spec);
    if egress.create_isolated_network {
        create_egress_network(&egress.docker_network).await?;
    }
    let args = build_create_args(spec, container_name, workspace_dir, &egress);
    match run_docker(&args).await {
        Ok(id) => {
            let net = if egress.create_isolated_network {
                Some(egress.docker_network)
            } else {
                None
            };
            Ok((id, net))
        }
        Err(e) => {
            if egress.create_isolated_network {
                let _ = remove_network(&egress.docker_network).await;
            }
            Err(e)
        }
    }
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

/// HostConfig isolation fields used by Docker-daemon e2e checks (cap drop,
/// security opt, network mode). Format is tab-separated so callers can
/// assert without depending on full JSON.
pub async fn inspect_isolation(container_id: &str) -> Result<String, CageError> {
    run_docker(&[
        "inspect".to_string(),
        "--format".to_string(),
        "{{.HostConfig.NetworkMode}}\t{{json .HostConfig.CapDrop}}\t{{json .HostConfig.SecurityOpt}}\t{{.HostConfig.Privileged}}".to_string(),
        container_id.to_string(),
    ])
    .await
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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec),
        );

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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec),
        );

        let dash_dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&args[dash_dash_pos + 1..], &["alpine:latest", "sleep", "5"]);
    }

    /// Host-Docker security review (2026-07): sandbox create must always
    /// drop capabilities and block privilege escalation, independent of
    /// the tenant-supplied image or command.
    #[test]
    fn create_args_always_drop_all_caps_and_no_new_privileges() {
        let spec = spec_with("alpine:latest", vec!["true"]);
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));
        let flags_before_image: Vec<&str> = args
            .iter()
            .take_while(|a| a.as_str() != "--")
            .map(String::as_str)
            .collect();

        assert!(
            flags_before_image
                .windows(2)
                .any(|w| w == ["--cap-drop", "ALL"]),
            "expected --cap-drop ALL before image; got {flags_before_image:?}"
        );
        assert!(
            flags_before_image
                .windows(2)
                .any(|w| w == ["--security-opt", "no-new-privileges:true"]),
            "expected --security-opt no-new-privileges:true; got {flags_before_image:?}"
        );
        assert!(
            flags_before_image
                .windows(2)
                .any(|w| w == ["--network", "none"]),
            "expected --network none; got {flags_before_image:?}"
        );
    }

    #[test]
    fn create_args_never_enable_privileged_or_host_namespaces_as_flags() {
        let spec = spec_with("alpine:latest", vec!["true"]);
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));
        let flags_before_image: Vec<&str> = args
            .iter()
            .take_while(|a| a.as_str() != "--")
            .map(String::as_str)
            .collect();

        for forbidden in [
            "--privileged",
            "--pid=host",
            "--network=host",
            "--ipc=host",
            "--uts=host",
            "--userns=host",
        ] {
            assert!(
                !flags_before_image
                    .iter()
                    .any(|a| *a == forbidden || a.starts_with(&format!("{forbidden}="))),
                "isolation flags must not include {forbidden}; got {flags_before_image:?}"
            );
        }
        // Socket must never be mounted into the *sandbox* (runner host is separate).
        assert!(
            !flags_before_image.iter().any(|a| a.contains("docker.sock")),
            "sandbox must not mount docker.sock; got {flags_before_image:?}"
        );
    }

    #[test]
    fn read_only_rootfs_adds_tmpfs_scratch_and_read_only_flag() {
        let mut spec = spec_with("alpine:latest", vec!["true"]);
        spec.image.read_only_rootfs = true;
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));
        let flags_before_image: Vec<&str> = args
            .iter()
            .take_while(|a| a.as_str() != "--")
            .map(String::as_str)
            .collect();

        assert!(flags_before_image.contains(&"--read-only"));
        assert!(
            flags_before_image
                .windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1].starts_with("/tmp:") && w[1].contains("noexec")),
            "expected /tmp tmpfs with noexec; got {flags_before_image:?}"
        );
    }

    #[test]
    fn writable_rootfs_skips_read_only_and_tmpfs() {
        let mut spec = spec_with("alpine:latest", vec!["true"]);
        spec.image.read_only_rootfs = false;
        let args = build_create_args(&spec, "test-container", &PathBuf::from("/tmp/workspace"));
        let flags_before_image: Vec<&str> = args
            .iter()
            .take_while(|a| a.as_str() != "--")
            .map(String::as_str)
            .collect();

        assert!(!flags_before_image.contains(&"--read-only"));
        assert!(!flags_before_image.contains(&"--tmpfs"));
        // Hardening still applies when rootfs is writable.
        assert!(flags_before_image
            .windows(2)
            .any(|w| w == ["--cap-drop", "ALL"]));
    }
}
