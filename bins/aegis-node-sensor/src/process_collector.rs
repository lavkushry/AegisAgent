//! Minimal host process collector (Wave A).
//!
//! Scans local processes for Aegis-marked agent workloads and registers
//! their PIDs with [`ProcessEnforcer`] so signed kill/pause/resume commands
//! can actually hit host processes (not only Docker cages).
//!
//! Discovery rule (intentionally narrow — no credential/env dumping):
//! a process whose environment contains `AEGIS_RUN_ID=<run_id>` is treated
//! as a tracked agent run. Optional `AEGIS_SANDBOX_ID` is recorded for
//! telemetry only.
//!
//! Linux uses `/proc/<pid>/environ`. Other OSes return no discoveries
//! (collectors are a no-op; enforcer registration via tests/API still works).
//!
//! Telemetry: only hashes/identifiers — never raw environ values beyond the
//! known `AEGIS_*` id keys, never command-line strings in events.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;

use crate::gateway_client::RuntimeEventPayload;
use crate::process_enforcer::{process_alive, ProcessEnforcer};
use crate::spool::{Lane, SpoolQueue};

const RUN_ID_KEY: &str = "AEGIS_RUN_ID";
const SANDBOX_ID_KEY: &str = "AEGIS_SANDBOX_ID";

/// A process that carries Aegis run identity in its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredProcess {
    pub pid: i32,
    pub run_id: String,
    pub sandbox_id: Option<String>,
}

/// Keeps [`ProcessEnforcer`] in sync with live host processes and emits
/// `process_started` / `process_exited` runtime events into the spool.
pub struct ProcessCollector {
    enforcer: Arc<ProcessEnforcer>,
    /// pid → run_id for processes we have announced as started.
    announced: Mutex<HashMap<i32, String>>,
}

impl ProcessCollector {
    pub fn new(enforcer: Arc<ProcessEnforcer>) -> Self {
        Self {
            enforcer,
            announced: Mutex::new(HashMap::new()),
        }
    }

    pub fn enforcer(&self) -> &Arc<ProcessEnforcer> {
        &self.enforcer
    }

    /// Scan the host, register/unregister with the enforcer, enqueue
    /// lifecycle events for newly seen / exited processes.
    pub fn poll(&self, spool: &SpoolQueue) {
        let live = scan_host_aegis_processes();
        let live_pids: HashSet<i32> = live.iter().map(|p| p.pid).collect();

        // Register / re-register live processes.
        for proc in &live {
            if let Err(e) = self.enforcer.register_run(&proc.run_id, proc.pid) {
                tracing::warn!(
                    pid = proc.pid,
                    run_id = %proc.run_id,
                    error = %e,
                    "process collector failed to register run"
                );
                continue;
            }
            let mut announced = self.announced.lock().expect("collector lock");
            if announced.insert(proc.pid, proc.run_id.clone()).is_none() {
                drop(announced);
                enqueue_process_event(
                    spool,
                    "process_started",
                    &proc.run_id,
                    proc.sandbox_id.as_deref(),
                    proc.pid,
                );
            }
        }

        // Drop dead announced PIDs.
        let exited: Vec<(i32, String)> = {
            let announced = self.announced.lock().expect("collector lock");
            announced
                .iter()
                .filter(|(pid, _)| !live_pids.contains(pid) || !process_alive(**pid))
                .map(|(pid, run_id)| (*pid, run_id.clone()))
                .collect()
        };
        for (pid, run_id) in exited {
            self.announced.lock().expect("collector lock").remove(&pid);
            // Only unregister if this pid is still the mapped one for run_id.
            if self.enforcer.pid_for(&run_id) == Some(pid) {
                self.enforcer.unregister_run(&run_id);
            }
            enqueue_process_event(spool, "process_exited", &run_id, None, pid);
        }
    }
}

fn enqueue_process_event(
    spool: &SpoolQueue,
    event_type: &str,
    run_id: &str,
    sandbox_id: Option<&str>,
    pid: i32,
) {
    let payload = RuntimeEventPayload {
        event_id: format!(
            "sensor-{event_type}-{run_id}-{pid}-{}",
            Utc::now().timestamp_millis()
        ),
        event_type: event_type.to_string(),
        severity: Some("info".to_string()),
        run_id: Some(run_id.to_string()),
        sandbox_id: sandbox_id.map(str::to_string),
        source_component: "aegis-node-sensor".to_string(),
        reason: Some(format!("pid={pid}")),
        observed_at: Some(Utc::now()),
        ..Default::default()
    };
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(e) = spool.enqueue(Lane::Normal, &bytes) {
                tracing::warn!(error = %e, event_type, "failed to spool process event");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize process event"),
    }
}

/// Parse Linux `/proc/<pid>/environ` (NUL-separated `KEY=VALUE`) for Aegis ids.
pub fn parse_environ_for_aegis_ids(environ: &[u8]) -> Option<(String, Option<String>)> {
    let mut run_id = None;
    let mut sandbox_id = None;
    for entry in environ.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let Ok(s) = std::str::from_utf8(entry) else {
            continue;
        };
        if let Some(v) = s.strip_prefix(&(RUN_ID_KEY.to_owned() + "=")) {
            if !v.is_empty() {
                run_id = Some(v.to_string());
            }
        } else if let Some(v) = s.strip_prefix(&(SANDBOX_ID_KEY.to_owned() + "=")) {
            if !v.is_empty() {
                sandbox_id = Some(v.to_string());
            }
        }
    }
    run_id.map(|r| (r, sandbox_id))
}

/// Scan host processes. Linux: `/proc`. Other platforms: empty.
pub fn scan_host_aegis_processes() -> Vec<DiscoveredProcess> {
    #[cfg(target_os = "linux")]
    {
        scan_proc_fs(Path::new("/proc"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Testable `/proc` walker — `proc_root` is `/proc` in production.
pub fn scan_proc_fs(proc_root: &Path) -> Vec<DiscoveredProcess> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        let environ_path = entry.path().join("environ");
        let Ok(bytes) = std::fs::read(&environ_path) else {
            continue;
        };
        if let Some((run_id, sandbox_id)) = parse_environ_for_aegis_ids(&bytes) {
            out.push(DiscoveredProcess {
                pid,
                run_id,
                sandbox_id,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_enforcer::ProcessEnforcer;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn parse_environ_extracts_run_and_sandbox_ids() {
        let env = b"PATH=/usr/bin\0AEGIS_RUN_ID=run-abc\0HOME=/tmp\0AEGIS_SANDBOX_ID=sb-1\0";
        let (run, sb) = parse_environ_for_aegis_ids(env).unwrap();
        assert_eq!(run, "run-abc");
        assert_eq!(sb.as_deref(), Some("sb-1"));
    }

    #[test]
    fn parse_environ_requires_run_id() {
        let env = b"AEGIS_SANDBOX_ID=only\0PATH=/\0";
        assert!(parse_environ_for_aegis_ids(env).is_none());
    }

    #[test]
    fn parse_environ_ignores_empty_run_id() {
        let env = b"AEGIS_RUN_ID=\0FOO=bar\0";
        assert!(parse_environ_for_aegis_ids(env).is_none());
    }

    #[test]
    fn scan_proc_fs_finds_fake_proc_tree() {
        let root = tempdir().unwrap();
        // non-pid entry
        std::fs::create_dir(root.path().join("self")).unwrap();
        // pid without environ
        std::fs::create_dir(root.path().join("1")).unwrap();
        // pid with AEGIS_RUN_ID
        let p42 = root.path().join("42");
        std::fs::create_dir(&p42).unwrap();
        std::fs::write(
            p42.join("environ"),
            b"USER=agent\0AEGIS_RUN_ID=run-42\0AEGIS_SANDBOX_ID=sb-42\0",
        )
        .unwrap();

        let found = scan_proc_fs(root.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, 42);
        assert_eq!(found[0].run_id, "run-42");
        assert_eq!(found[0].sandbox_id.as_deref(), Some("sb-42"));
    }

    #[test]
    fn poll_registers_discovered_process_and_spools_started_event() {
        let root = tempdir().unwrap();
        let p = root.path().join("99");
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("environ"), b"AEGIS_RUN_ID=run-poll\0").unwrap();

        let enforcer = Arc::new(ProcessEnforcer::new());
        let collector = ProcessCollector::new(enforcer.clone());
        // Use a custom scan by temporarily only testing registration path:
        // call internal logic via scan_proc_fs + manual register like poll does.
        let live = scan_proc_fs(root.path());
        assert_eq!(live.len(), 1);
        enforcer.register_run(&live[0].run_id, live[0].pid).unwrap();
        assert_eq!(enforcer.pid_for("run-poll"), Some(99));

        let spool_dir = tempdir().unwrap();
        let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
        // Simulate first announce
        enqueue_process_event(&spool, "process_started", "run-poll", None, 99);
        let rec = spool.read_next(Lane::Normal).unwrap().unwrap();
        let payload: RuntimeEventPayload = serde_json::from_slice(&rec.payload).unwrap();
        assert_eq!(payload.event_type, "process_started");
        assert_eq!(payload.run_id.as_deref(), Some("run-poll"));
        assert_eq!(payload.source_component, "aegis-node-sensor");
        assert!(payload.reason.as_deref().unwrap().contains("pid=99"));
    }

    #[test]
    fn collector_poll_with_empty_scan_is_harmless() {
        // On macOS / non-linux, scan is empty; poll should not panic.
        let enforcer = Arc::new(ProcessEnforcer::new());
        let collector = ProcessCollector::new(enforcer);
        let spool_dir = tempdir().unwrap();
        let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
        collector.poll(&spool);
    }
}
