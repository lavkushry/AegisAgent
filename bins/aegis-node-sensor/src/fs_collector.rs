//! Minimal host filesystem collector (Wave A).
//!
//! For processes marked with `AEGIS_RUN_ID`, inspect open file descriptors
//! and emit `fs_open` events for **path strings only** (no file contents).
//! Skips `/proc`, `/sys`, `/dev` noise and pure sockets (handled by net
//! collector).
//!
//! Linux: `/proc/<pid>/fd` readlink. Other OSes: no-op.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;

use crate::gateway_client::RuntimeEventPayload;
use crate::process_collector::{scan_host_aegis_processes, DiscoveredProcess};
use crate::spool::{Lane, SpoolQueue};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FsKey {
    run_id: String,
    path: String,
}

pub struct FsCollector {
    seen: Mutex<HashSet<FsKey>>,
}

impl FsCollector {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn poll(&self, spool: &SpoolQueue) {
        for proc in scan_host_aegis_processes() {
            for path in open_paths_for_pid(proc.pid) {
                if !is_reportable_path(&path) {
                    continue;
                }
                let key = FsKey {
                    run_id: proc.run_id.clone(),
                    path: path.clone(),
                };
                let mut seen = self.seen.lock().expect("fs collector lock");
                if !seen.insert(key) {
                    continue;
                }
                drop(seen);
                enqueue_fs_event(spool, &proc, &path);
            }
        }
    }
}

impl Default for FsCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn enqueue_fs_event(spool: &SpoolQueue, proc: &DiscoveredProcess, path: &str) {
    let payload = RuntimeEventPayload {
        event_id: format!(
            "sensor-fs-{}-{}-{}",
            proc.run_id,
            simple_path_token(path),
            Utc::now().timestamp_millis()
        ),
        event_type: "fs_open".to_string(),
        severity: Some("info".to_string()),
        run_id: Some(proc.run_id.clone()),
        sandbox_id: proc.sandbox_id.clone(),
        source_component: "aegis-node-sensor".to_string(),
        reason: Some(format!("pid={} path={}", proc.pid, path)),
        observed_at: Some(Utc::now()),
        ..Default::default()
    };
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(e) = spool.enqueue(Lane::Normal, &bytes) {
                tracing::warn!(error = %e, "failed to spool fs_open event");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize fs_open event"),
    }
}

fn simple_path_token(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(64)
        .collect()
}

/// Paths we bother reporting (not kernel pseudo-fs / devices / sockets).
pub fn is_reportable_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with("socket:") || path.starts_with("pipe:") {
        return false;
    }
    if path.starts_with("anon_inode:") || path == "." || path == ".." {
        return false;
    }
    let skip_prefixes = ["/proc/", "/sys/", "/dev/", "/run/systemd/"];
    if skip_prefixes.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    // Absolute paths only — relative/broken links are noisy.
    path.starts_with('/')
}

fn open_paths_for_pid(pid: i32) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        open_paths_for_pid_in(Path::new("/proc"), pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Testable fd walk.
pub fn open_paths_for_pid_in(proc_root: &Path, pid: i32) -> Vec<String> {
    let mut out = Vec::new();
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        let s = link.to_string_lossy().into_owned();
        if is_reportable_path(&s) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn is_reportable_path_filters_noise() {
        assert!(is_reportable_path("/workspace/out.txt"));
        assert!(is_reportable_path("/tmp/agent.log"));
        assert!(!is_reportable_path("/proc/1/fd/0"));
        assert!(!is_reportable_path("/sys/fs/cgroup"));
        assert!(!is_reportable_path("/dev/null"));
        assert!(!is_reportable_path("socket:[1]"));
        assert!(!is_reportable_path("pipe:[2]"));
    }

    #[test]
    fn open_paths_for_pid_in_fake_proc() {
        let root = tempdir().unwrap();
        let fd = root.path().join("9").join("fd");
        fs::create_dir_all(&fd).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let _ = symlink("/workspace/data.bin", fd.join("3"));
            let _ = symlink("/proc/self/fd/0", fd.join("0"));
            let _ = symlink("socket:[1]", fd.join("4"));
            let paths = open_paths_for_pid_in(root.path(), 9);
            assert_eq!(paths, vec!["/workspace/data.bin".to_string()]);
        }
    }

    #[test]
    fn poll_empty_is_harmless() {
        let c = FsCollector::new();
        let d = tempdir().unwrap();
        let spool = SpoolQueue::open(d.path(), 1_000_000).unwrap();
        c.poll(&spool);
    }
}
