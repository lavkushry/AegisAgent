# Agent Cage — Host Docker Security Review

**Scope:** `aegis-cage-runner` Docker-first sandbox path  
**Code:** `bins/aegis-cage-runner/src/docker_cli.rs`, `spec.rs`, `docker_runtime.rs`  
**Packaging:** `bins/aegis-cage-runner/Dockerfile`, `helm/aegis-cage-runner/`, compose profile `cage`  
**Date:** 2026-07  

This review separates **sandbox isolation** (what a claimed unknown agent can do *inside* its container) from **runner host risk** (what the process that *creates* sandboxes can do on the node). The two must not be conflated in claims or operator docs.

---

## 1. Threat model (Docker-first)

| Actor | Goal | Primary surface |
|-------|------|-----------------|
| Untrusted / prompt-injected agent workload | Escape sandbox, reach host, open network, steal secrets | Container created by `docker create` |
| Malicious or buggy tenant-supplied `SandboxSpec` | Override isolation flags, mount host secrets, inject privileged create flags | Claim payload → `SandboxSpec::validate` + `build_create_args` |
| Compromised cage-runner process / image | Full Docker Engine API via socket | Host `/var/run/docker.sock` mounted into the **runner** pod/container |
| Co-tenant on same Docker host | Cross-container interference, resource exhaustion | Shared engine; mitigated only by resource caps + network none |

Out of scope for this review: gVisor/Firecracker/Kata backends, forced egress proxy netns, sensor host kill path (separate Wave A items).

---

## 2. Guarantees enforced in code today

### 2.1 Spec validation (`spec.rs`)

Fail-closed before any Docker call:

| Check | Effect |
|-------|--------|
| `network.direct_internet == true` | Rejected |
| Controlled mount target under forbidden prefixes (`docker.sock`, `.ssh`, `.aws`, `.kube`, `/home`, …) | Rejected |
| Env names matching secret-like substrings (with small allowlist) | Rejected |
| `image_ref` starting with `-` | Rejected (blocks CLI flag smuggling at the image token) |

Controlled mounts are **not** passed to `docker create` yet (empty wiring). Schema allowlists source types only (`git_snapshot` / `artifact` / `secretless_config` / `tmpfs`) — never arbitrary host paths.

### 2.2 `docker create` flags (`build_create_args`)

Always applied (unit-tested):

| Flag | Isolation intent |
|------|------------------|
| `--network none` | No bridge/host egress from the sandbox |
| `--cap-drop ALL` | No Linux capabilities even if image runs as root |
| `--security-opt no-new-privileges:true` | Block setuid / file-cap privilege gain after exec |
| `--pids-limit` / `--memory` / `--cpus` | Resource caps from the run spec |
| Workspace `-v` only under runner-managed workspace root | No host home / credentials by default |
| `--` end-of-options before `image_ref` + `command` | Tenant tokens cannot become Docker CLI flags (`--privileged`, etc.) |

When `image.read_only_rootfs` (default true):

| Flag | Isolation intent |
|------|------------------|
| `--read-only` | Immutable rootfs |
| `--tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m` | Small scratch without exec of dropped tools |

Explicitly **not** set: `--privileged`, host PID/IPC/UTS/network/user namespaces, `docker.sock` mounts into the sandbox.

### 2.3 Runner packaging posture

| Surface | Current default | Notes |
|---------|-----------------|-------|
| Compose `cage` profile | Mounts host `docker.sock` | Opt-in profile; not default full stack |
| Helm chart | `dockerSocket.enabled: true`, hostPath Socket | Required for Docker backend |
| Helm `securityContext` | `allowPrivilegeEscalation: false`, drop ALL caps on **runner** container | Socket still implies engine control |
| Helm `dockerGroupGid` | Optional supplemental group | Prefer non-root + matching GID over root |

---

## 3. Residual risks (do not claim closed)

### R1 — Host `docker.sock` is root-equivalent on the runner node

Anyone who can talk to the Docker API on that socket can start privileged containers, mount the host root, or escape. Mounting the socket into the cage-runner container (compose/Helm) is an **operator trust decision**: treat the runner image, config, and API token as highly privileged.

**Mitigations (operator):**

- Pin image digests; restrict who can deploy the chart.
- Prefer `dockerGroupGid` + non-root UID over running the runner as root when the node documents the docker group GID.
- NetworkPolicy / node isolation so only the runner needs the socket.
- Longer term: rootless Docker, Docker socket proxy with allowlisted API verbs, or non-Docker backends (gVisor/Firecracker/Kata/K8s Jobs without host socket).

### R2 — Sandbox image may still run as root UID

`--cap-drop ALL` + `no-new-privileges` greatly reduce root-inside-container power, but UID 0 still has different VFS/DAC semantics than a non-root user. We do **not** force `--user` today because many agent images assume root for package tools.

**Follow-up:** optional `run_as_user` / `run_as_non_root` in `SandboxSpec` with a safe default once image policy lands.

### R3 — Shared kernel (Docker, not VM)

Standard container isolation is not a hardware boundary. Kernel CVEs, misconfigured host seccomp/AppArmor defaults, or privileged sibling containers on the same host remain in scope for a compromised sandbox **plus** a host flaw.

**Follow-up:** gVisor/Firecracker/Kata backends per `docs/AegisAgent_Agent_Cage.md`.

### R4 — Network is “none”, not “proxy-forced”

`--network none` blocks all egress. Product goal of *forced egress via proxy* (allowed destinations only) is **not** implemented as a netns/sidecar path yet. Enabling network later must re-run this review (no silent “bridge + hope”).

### R5 — Docker finish/kill e2e exists; full product narrative still partial

Claim/heartbeat without Docker: `cage_run_lifecycle_*`, `scripts/cage-smoke.sh`.  
Real Docker path: `scripts/cage-docker-e2e.sh` (+ CI job `Cage Docker E2E`) runs alpine finish + signed kill through gateway + runner against a live engine. HostConfig isolation is also asserted in `docker_runtime` tests when a daemon is present.

Still open: forced egress (allowed destinations via proxy, not only `--network none`) and sensor host enforce as a single “untrusted → incident” story.

### R6 — Runner image ships Docker CLI against host engine

The image intentionally includes the Docker client and expects a mounted socket (not DinD). Supply-chain and least-privilege of that client binary matter; `dockerd` is stripped from the image where possible.

---

## 4. Operator checklist

Before enabling the `cage` profile or installing `helm/aegis-cage-runner`:

1. Confirm gateway has `AEGIS_COMMAND_SIGNING_KEY` and runner `gateway_public_key_hex` matches.
2. Treat runner `api_token` as high privilege (can claim and run tenant sandboxes).
3. Document the node’s docker group GID; set `dockerGroupGid` and tighten `securityContext` when possible.
4. Do not expose the runner pod to untrusted networks beyond the gateway.
5. Do not claim “unknown-agent production control” until R4/R5 (and sensor enforce) close Wave A.

---

## 5. Regression tests

| Test | File |
|------|------|
| `--` precedes malicious `image_ref` / command | `docker_cli::tests::end_of_options_marker_precedes_the_image_ref` |
| Always `--cap-drop ALL` + `no-new-privileges` + `--network none` | `create_args_always_drop_all_caps_and_no_new_privileges` |
| No privileged/host-ns flags; no sock mount in sandbox args | `create_args_never_enable_privileged_or_host_namespaces_as_flags` |
| Read-only rootfs ⇒ `--read-only` + noexec `/tmp` tmpfs | `read_only_rootfs_adds_tmpfs_scratch_and_read_only_flag` |
| Forbidden mounts / env / direct_internet | `spec.rs` unit tests |

```bash
cargo test -p aegis-cage-runner --lib docker_cli
```

---

## 6. Status for product claims

| Claim | Allowed after this review? |
|-------|----------------------------|
| Sandbox create defaults are defense-in-depth hardened and unit-tested | **Yes** |
| Spec cannot request direct internet or forbidden mounts/env | **Yes** |
| Runner host is safe because sandboxes drop caps | **No** (R1) |
| Unknown-agent production control complete | **No** (Wave A: e2e, forced egress, sensor enforce) |
