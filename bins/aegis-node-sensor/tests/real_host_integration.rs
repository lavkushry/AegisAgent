//! Proves the Wave A collectors against a real live Linux host, not the
//! synthetic `/proc` trees the unit tests in each collector module use.
//! CI's `ubuntu-latest` runner is itself a real Linux VM, so these tests
//! exercise the actual production entrypoints (`scan_host_aegis_processes`,
//! `ProcessCollector::poll`, `NetCollector::poll`, `FsCollector::poll`) against
//! real child processes, a real SIGTERM/SIGKILL, a real established TCP
//! socket, and a real open file descriptor -- not the `*_in(root: &Path)`
//! test-only helpers that read a tempdir fixture instead of `/proc`.
//!
//! This closes the "not yet proven against a real live host" caveat named in
//! `docs/current-vs-roadmap.md` for the node sensor's collectors -- for the
//! definition of "real host" a CI runner satisfies (a real Linux kernel's
//! `/proc`, real signals, real sockets). It does not prove behavior on an
//! arbitrary long-lived production host under production load; that remains
//! a separate, larger follow-up.
//!
//! Linux-only: every collector here is a documented no-op on other
//! platforms, matching each module's own doc comment.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use aegis_node_sensor::fs_collector::FsCollector;
use aegis_node_sensor::gateway_client::RuntimeEventPayload;
use aegis_node_sensor::net_collector::NetCollector;
use aegis_node_sensor::process_collector::{scan_host_aegis_processes, ProcessCollector};
use aegis_node_sensor::process_enforcer::{process_alive, ProcessEnforcer};
use aegis_node_sensor::secret_collector::SecretCollector;
use aegis_node_sensor::spool::{Lane, SpoolQueue};

fn unique_run_id(tag: &str) -> String {
    format!(
        "real-host-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    )
}

fn spawn_sleep_with_run_id(run_id: &str) -> Child {
    Command::new("sleep")
        .arg("20")
        .env("AEGIS_RUN_ID", run_id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn real sleep child")
}

#[test]
fn process_collector_discovers_a_real_child_via_the_actual_proc_filesystem() {
    let run_id = unique_run_id("proc");
    let mut child = spawn_sleep_with_run_id(&run_id);
    let pid = child.id() as i32;

    // Real /proc/<pid>/environ, populated by the kernel for a real child --
    // not the tempdir fixture `scan_proc_fs`'s own unit tests use.
    let found = scan_host_aegis_processes();
    let hit = found.iter().find(|p| p.pid == pid);
    assert!(
        hit.is_some(),
        "expected pid {pid} with AEGIS_RUN_ID={run_id} to be discovered via real /proc"
    );
    assert_eq!(hit.unwrap().run_id, run_id);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn process_collector_poll_registers_with_enforcer_and_can_kill_a_real_child() {
    let run_id = unique_run_id("poll-kill");
    let mut child = spawn_sleep_with_run_id(&run_id);
    let pid = child.id() as i32;

    let enforcer = Arc::new(ProcessEnforcer::new());
    let collector = ProcessCollector::new(enforcer.clone());
    let spool_dir = tempfile::tempdir().unwrap();
    let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();

    collector.poll(&spool);

    assert_eq!(enforcer.pid_for(&run_id), Some(pid));

    let rec = spool
        .read_next(Lane::Normal)
        .unwrap()
        .expect("process_started event spooled for the real child");
    let payload: RuntimeEventPayload = serde_json::from_slice(&rec.payload).unwrap();
    assert_eq!(payload.event_type, "process_started");
    assert_eq!(payload.run_id.as_deref(), Some(run_id.as_str()));

    // Real SIGTERM (escalating to SIGKILL) against a real live host process.
    enforcer.kill_run(&run_id).unwrap();
    let _ = child.wait();
    assert!(!process_alive(pid));
}

#[test]
fn net_collector_reports_a_real_established_tcp_connection() {
    let run_id = unique_run_id("net");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(5));
            drop(stream);
        }
    });

    // bash's /dev/tcp pseudo-device opens a real TCP socket from a real
    // child process without depending on netcat being on the runner image.
    let Ok(mut child) = Command::new("bash")
        .arg("-c")
        .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{port}; sleep 5"))
        .env("AEGIS_RUN_ID", &run_id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("bash not available -- skipping real TCP socket test");
        return;
    };

    // Give the connection a moment to reach ESTABLISHED in /proc/net/tcp.
    std::thread::sleep(Duration::from_millis(500));

    let collector = NetCollector::new();
    let spool_dir = tempfile::tempdir().unwrap();
    let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
    collector.poll(&spool);

    let rec = spool
        .read_next(Lane::Normal)
        .unwrap()
        .expect("network_connection event spooled for the real socket");
    let payload: RuntimeEventPayload = serde_json::from_slice(&rec.payload).unwrap();
    assert_eq!(payload.event_type, "network_connection");
    assert_eq!(payload.run_id.as_deref(), Some(run_id.as_str()));
    assert!(payload
        .reason
        .as_deref()
        .unwrap()
        .contains(&format!("remote=127.0.0.1:{port}")));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fs_collector_reports_a_real_open_file_descriptor() {
    let run_id = unique_run_id("fs");
    let path = std::env::temp_dir().join(format!("aegis-sensor-real-host-{run_id}.txt"));
    let path_str = path.to_string_lossy().into_owned();

    let Ok(mut child) = Command::new("bash")
        .arg("-c")
        .arg(format!("exec 3<>'{path_str}'; sleep 5"))
        .env("AEGIS_RUN_ID", &run_id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("bash not available -- skipping real file descriptor test");
        return;
    };

    std::thread::sleep(Duration::from_millis(300));

    let collector = FsCollector::new();
    let spool_dir = tempfile::tempdir().unwrap();
    let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
    collector.poll(&spool);

    let rec = spool
        .read_next(Lane::Normal)
        .unwrap()
        .expect("fs_open event spooled for the real file descriptor");
    let payload: RuntimeEventPayload = serde_json::from_slice(&rec.payload).unwrap();
    assert_eq!(payload.event_type, "fs_open");
    assert_eq!(payload.run_id.as_deref(), Some(run_id.as_str()));
    assert!(payload.reason.as_deref().unwrap().contains(&path_str));

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn secret_collector_reports_only_the_env_name_never_the_value_for_a_real_child() {
    let run_id = unique_run_id("secret");
    let secret_value = "definitely-not-a-real-secret-value-12345";
    let mut child = Command::new("sleep")
        .arg("20")
        .env("AEGIS_RUN_ID", &run_id)
        .env("GITHUB_TOKEN", secret_value)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn real sleep child with a secret-like env var");
    let pid = child.id() as i32;

    let collector = SecretCollector::new();
    let spool_dir = tempfile::tempdir().unwrap();
    let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
    collector.poll(&spool);

    let rec = spool
        .read_next(Lane::Normal)
        .unwrap()
        .expect("secret_signal event spooled for the real child's real /proc/<pid>/environ");
    let payload: RuntimeEventPayload = serde_json::from_slice(&rec.payload).unwrap();
    assert_eq!(payload.event_type, "secret_signal");
    assert_eq!(payload.run_id.as_deref(), Some(run_id.as_str()));
    let reason = payload.reason.as_deref().unwrap();
    assert!(reason.contains(&format!("pid={pid}")));
    assert!(reason.contains("GITHUB_TOKEN"));
    // The whole point of the collector: the value never leaves the host.
    assert!(!reason.contains(secret_value));

    let _ = child.kill();
    let _ = child.wait();
}
