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
    /// Docker `--network` value: `none` (no egress) or a dedicated
    /// per-sandbox bridge name (proxy path).
    docker_network: String,
    /// Proxy URL injected into the container (host rewritten to the
    /// sidecar container's name — see [`rewrite_proxy_for_sidecar`]).
    proxy_url: Option<String>,
    /// When true, `docker_network` names a dedicated network this sandbox's
    /// caller must create before `docker create` and remove on cleanup
    /// (rather than a built-in Docker network like `none`).
    create_isolated_network: bool,
}

/// Plan forced egress for a validated [`SandboxSpec`].
///
/// | `egress_proxy_url` set? | `egress_proxy_container` configured? | Docker network | Proxy env |
/// |---|---|---|---|
/// | no | — | `none` | none (no egress at all) |
/// | yes | no | dedicated internal, no-masquerade bridge | none — fail closed, see below |
/// | yes | yes | dedicated internal, no-masquerade bridge, **with the proxy container joined to it** | forced HTTP(S)_PROXY to `http://<container>:<port>` |
///
/// The dedicated bridge is created `--internal` (Docker never wires it to an
/// external route) *and* with IP masquerade disabled — belt and suspenders,
/// since `--internal` alone is the primitive that actually withholds
/// outbound routing (masquerade-off by itself only breaks the NAT return
/// path, not the initial outbound leg: a plain UDP/TCP socket can still send
/// packets out and rely on an upstream device to NAT them).
///
/// `--internal` also means the sandbox has **no route to the host at all**
/// — not just no internet. `host.docker.internal:host-gateway` does not
/// exist on an `--internal` network (verified: a container there gets
/// "Network unreachable" resolving it), so a host-run proxy process is
/// unreachable no matter how it's addressed. The only thing an `--internal`
/// network *can* reach is another container joined to that same network —
/// so the proxy must run as a container and be explicitly connected
/// (`docker network connect`) to each sandbox's dedicated bridge as a
/// peer. Without `egress_proxy_container` configured, a forced-egress
/// sandbox simply gets no proxy connectivity — fail closed (isolated but
/// non-functional) rather than silently falling back to an unreachable
/// host address that looks configured but never works.
///
/// Residual: `--cap-drop ALL` already removes `CAP_NET_RAW`, so the residual
/// vector here is ordinary (non-raw) sockets to any address reachable from
/// the internal bridge — by construction, only the joined proxy container.
/// An attacker who controls the proxy's own onward path, or a destination
/// the proxy explicitly allows, is out of scope for this Docker-level
/// control — `allowed_destinations` enforcement lives in the proxy itself.
fn plan_egress_network(
    spec: &SandboxSpec,
    egress_proxy_container: Option<&str>,
) -> EgressNetworkPlan {
    let raw = spec
        .network
        .egress_proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match raw {
        None => EgressNetworkPlan {
            docker_network: "none".to_string(),
            proxy_url: None,
            create_isolated_network: false,
        },
        Some(url) => {
            let proxy_url = egress_proxy_container.and_then(|c| rewrite_proxy_for_sidecar(url, c));
            EgressNetworkPlan {
                docker_network: format!("aegis-cage-egress-{}", spec.sandbox_id),
                proxy_url,
                create_isolated_network: true,
            }
        }
    }
}

/// Create a dedicated `--internal` bridge network (no external route — the
/// actual isolation primitive) with IP masquerade also disabled (defense in
/// depth against the NAT return path) so containers attached to it can reach
/// only the bridge gateway / host, never the public Internet.
async fn create_egress_network(name: &str) -> Result<(), CageError> {
    run_docker(&[
        "network".to_string(),
        "create".to_string(),
        "--driver".to_string(),
        "bridge".to_string(),
        "--internal".to_string(),
        "-o".to_string(),
        "com.docker.network.bridge.enable_ip_masquerade=false".to_string(),
        name.to_string(),
    ])
    .await
    .map(|_| ())
}

/// Remove a dedicated egress network created by [`create_egress_network`].
pub async fn remove_network(name: &str) -> Result<(), CageError> {
    run_docker(&["network".to_string(), "rm".to_string(), name.to_string()])
        .await
        .map(|_| ())
}

/// Join an already-running container (the egress-proxy sidecar) to a
/// sandbox's dedicated `--internal` bridge, so the sandbox's forced-egress
/// traffic has exactly one reachable peer. Idempotent-ish: Docker errors if
/// already connected, but callers only invoke this once per fresh network.
pub async fn connect_container_to_network(network: &str, container: &str) -> Result<(), CageError> {
    run_docker(&[
        "network".to_string(),
        "connect".to_string(),
        network.to_string(),
        container.to_string(),
    ])
    .await
    .map(|_| ())
}

/// Undo [`connect_container_to_network`] before [`remove_network`] — Docker
/// refuses to remove a network that still has a container attached.
pub async fn disconnect_container_from_network(
    network: &str,
    container: &str,
) -> Result<(), CageError> {
    run_docker(&[
        "network".to_string(),
        "disconnect".to_string(),
        network.to_string(),
        container.to_string(),
    ])
    .await
    .map(|_| ())
}

/// Rewrite a proxy URL's host to the egress-proxy sidecar container's name,
/// keeping the original scheme and port (and any path). Docker's embedded
/// DNS resolves a container by name on any network it's joined to — once
/// [`connect_container_to_network`] has attached the proxy to the sandbox's
/// bridge, `http://<container>:<port>` resolves there regardless of what
/// host the operator originally wrote (typically `127.0.0.1`, the address
/// the proxy binds to on its own home network).
fn rewrite_proxy_for_sidecar(proxy_url: &str, container: &str) -> Option<String> {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = proxy_url.strip_prefix(scheme) {
            let after_host = rest.find([':', '/']).map(|i| &rest[i..]).unwrap_or("");
            return Some(format!("{scheme}{container}{after_host}"));
        }
    }
    None
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
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--network".to_string(),
        egress.docker_network.clone(),
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
///
/// `egress_proxy_container`, when the spec requests forced egress, is
/// joined to the sandbox's fresh `--internal` bridge as a peer (see
/// [`plan_egress_network`] for why that's the only way the sandbox can
/// reach it at all).
pub async fn create(
    spec: &SandboxSpec,
    container_name: &str,
    workspace_dir: &Path,
    egress_proxy_container: Option<&str>,
) -> Result<(String, Option<String>), CageError> {
    let egress = plan_egress_network(spec, egress_proxy_container);
    if egress.create_isolated_network {
        create_egress_network(&egress.docker_network).await?;
        if let Some(proxy_container) = egress_proxy_container {
            if let Err(e) =
                connect_container_to_network(&egress.docker_network, proxy_container).await
            {
                let _ = remove_network(&egress.docker_network).await;
                return Err(e);
            }
        }
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
                if let Some(proxy_container) = egress_proxy_container {
                    let _ =
                        disconnect_container_from_network(&egress.docker_network, proxy_container)
                            .await;
                }
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

    #[test]
    fn plan_egress_network_is_none_and_not_isolated_without_a_proxy_url() {
        let spec = spec_with("alpine:latest", vec!["true"]);
        let plan = plan_egress_network(&spec, None);
        assert_eq!(plan.docker_network, "none");
        assert!(plan.proxy_url.is_none());
        assert!(!plan.create_isolated_network);
    }

    #[test]
    fn plan_egress_network_isolates_but_fails_closed_without_a_sidecar_container() {
        // egress_proxy_url alone, with no egress_proxy_container configured
        // for this runtime, gets the isolated bridge (so it's not
        // accidentally --network none either) but no proxy env at all —
        // there is nothing on that bridge for it to reach.
        let mut spec = spec_with("alpine:latest", vec!["true"]);
        spec.network.egress_proxy_url = Some("http://10.0.0.5:8888".to_string());
        let plan = plan_egress_network(&spec, None);
        assert_ne!(plan.docker_network, "none");
        assert_ne!(plan.docker_network, "bridge");
        assert!(plan.docker_network.contains(&spec.sandbox_id));
        assert!(plan.proxy_url.is_none());
        assert!(plan.create_isolated_network);
    }

    #[test]
    fn plan_egress_network_rewrites_proxy_host_to_the_sidecar_container_name() {
        let mut spec = spec_with("alpine:latest", vec!["true"]);
        spec.network.egress_proxy_url = Some("http://127.0.0.1:8888".to_string());
        let plan = plan_egress_network(&spec, Some("aegis-egress-proxy-e2e"));
        assert_eq!(
            plan.proxy_url.as_deref(),
            Some("http://aegis-egress-proxy-e2e:8888")
        );
        assert!(plan.create_isolated_network);
    }

    #[test]
    fn build_create_args_uses_the_planned_network_and_forces_proxy_env() {
        let mut spec = spec_with("alpine:latest", vec!["true"]);
        spec.network.egress_proxy_url = Some("http://10.0.0.5:8888".to_string());
        spec.environment
            .insert("HTTP_PROXY".to_string(), "http://attacker:1".to_string());
        let plan = plan_egress_network(&spec, Some("aegis-egress-proxy-e2e"));
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan,
        );

        let network_pos = args.iter().position(|a| a == "--network").unwrap();
        assert_eq!(args[network_pos + 1], plan.docker_network);
        assert_ne!(args[network_pos + 1], "none");

        assert!(args
            .windows(2)
            .any(|w| w == ["-e", "HTTP_PROXY=http://aegis-egress-proxy-e2e:8888"]));
        assert!(!args.iter().any(|a| a.contains("attacker")));
    }

    #[test]
    fn rewrite_proxy_for_sidecar_preserves_path_and_rejects_unknown_scheme() {
        assert_eq!(
            rewrite_proxy_for_sidecar("http://127.0.0.1:8888/probe", "proxy-c"),
            Some("http://proxy-c:8888/probe".to_string())
        );
        assert_eq!(
            rewrite_proxy_for_sidecar("https://10.0.0.5", "proxy-c"),
            Some("https://proxy-c".to_string())
        );
        assert_eq!(
            rewrite_proxy_for_sidecar("ftp://127.0.0.1:8888", "proxy-c"),
            None
        );
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
            &plan_egress_network(&spec, None),
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
            &plan_egress_network(&spec, None),
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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec, None),
        );
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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec, None),
        );
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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec, None),
        );
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
        let args = build_create_args(
            &spec,
            "test-container",
            &PathBuf::from("/tmp/workspace"),
            &plan_egress_network(&spec, None),
        );
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
