//! Minimal host secret-signal collector (Wave A).
//!
//! Scans **metadata only** for Aegis-marked processes:
//! - environment **variable names** (never values) matching secret-like patterns
//! - open file **paths** whose basename looks credential-shaped
//!
//! Emits `secret_signal` events with the signal kind + key/basename only.
//! Never logs or ships secret material (CWE-532).

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;

use crate::fs_collector::is_reportable_path;
#[cfg(target_os = "linux")]
use crate::fs_collector::open_paths_for_pid_in;
use crate::gateway_client::RuntimeEventPayload;
use crate::process_collector::{scan_host_aegis_processes, DiscoveredProcess};
use crate::spool::{Lane, SpoolQueue};

/// Substrings (case-insensitive) that mark an env **name** as secret-like.
const SECRET_ENV_NAME_MARKERS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CREDENTIAL",
    "AUTH_KEY",
];

/// Basenames that often hold credentials (path-only signal).
const SECRET_PATH_BASENAMES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials",
    "credentials.json",
    ".env",
    ".env.local",
    ".netrc",
    "kubeconfig",
    "service-account.json",
];

const SECRET_PATH_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks"];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SecretKey {
    run_id: String,
    kind: String,
    signal: String,
}

pub struct SecretCollector {
    seen: Mutex<HashSet<SecretKey>>,
}

impl SecretCollector {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn poll(&self, spool: &SpoolQueue) {
        for proc in scan_host_aegis_processes() {
            for name in env_names_for_pid(proc.pid) {
                if !is_secret_like_env_name(&name) {
                    continue;
                }
                self.emit_once(spool, &proc, "secret_env_name", &name);
            }
            for path in open_paths_for_host_pid(proc.pid) {
                if let Some(sig) = secret_path_signal(&path) {
                    self.emit_once(spool, &proc, "secret_path", &sig);
                }
            }
        }
    }

    fn emit_once(&self, spool: &SpoolQueue, proc: &DiscoveredProcess, kind: &str, signal: &str) {
        let key = SecretKey {
            run_id: proc.run_id.clone(),
            kind: kind.to_string(),
            signal: signal.to_string(),
        };
        let mut seen = self.seen.lock().expect("secret collector lock");
        if !seen.insert(key) {
            return;
        }
        drop(seen);
        enqueue_secret_event(spool, proc, kind, signal);
    }
}

impl Default for SecretCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn enqueue_secret_event(spool: &SpoolQueue, proc: &DiscoveredProcess, kind: &str, signal: &str) {
    let payload = RuntimeEventPayload {
        event_id: format!(
            "sensor-secret-{}-{}-{}-{}",
            proc.run_id,
            kind,
            signal
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(48)
                .collect::<String>(),
            Utc::now().timestamp_millis()
        ),
        event_type: "secret_signal".to_string(),
        severity: Some("medium".to_string()),
        run_id: Some(proc.run_id.clone()),
        sandbox_id: proc.sandbox_id.clone(),
        source_component: "aegis-node-sensor".to_string(),
        // Names/paths only — never values.
        reason: Some(format!("pid={} kind={} signal={}", proc.pid, kind, signal)),
        redaction_status: Some("names_only".to_string()),
        observed_at: Some(Utc::now()),
        ..Default::default()
    };
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(e) = spool.enqueue(Lane::Normal, &bytes) {
                tracing::warn!(error = %e, "failed to spool secret_signal event");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize secret_signal event"),
    }
}

/// `true` if an environment **variable name** looks secret-bearing.
pub fn is_secret_like_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    // Allow non-secret AEGIS identity markers.
    if matches!(
        upper.as_str(),
        "AEGIS_RUN_ID" | "AEGIS_SANDBOX_ID" | "AEGIS_TENANT_ID"
    ) {
        return false;
    }
    SECRET_ENV_NAME_MARKERS.iter().any(|m| upper.contains(m))
}

/// If path is credential-shaped, return a short signal string (basename or
/// suffix), not full path content.
pub fn secret_path_signal(path: &str) -> Option<String> {
    if !is_reportable_path(path) {
        return None;
    }
    let base = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let base_l = base.to_ascii_lowercase();
    if SECRET_PATH_BASENAMES
        .iter()
        .any(|b| base_l == *b || base_l.ends_with(&format!(".{b}")))
    {
        return Some(base.to_string());
    }
    for suf in SECRET_PATH_SUFFIXES {
        if base_l.ends_with(suf) {
            return Some(format!("*{suf}"));
        }
    }
    None
}

fn env_names_for_pid(pid: i32) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        env_names_for_pid_in(Path::new("/proc"), pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Parse `/proc/<pid>/environ` for **names only**.
pub fn env_names_for_pid_in(proc_root: &Path, pid: i32) -> Vec<String> {
    let path = proc_root.join(pid.to_string()).join("environ");
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    parse_environ_names(&bytes)
}

pub fn parse_environ_names(environ: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for entry in environ.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let Ok(s) = std::str::from_utf8(entry) else {
            continue;
        };
        let name = s.split('=').next().unwrap_or("");
        if !name.is_empty() {
            names.push(name.to_string());
        }
    }
    names
}

fn open_paths_for_host_pid(pid: i32) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn secret_like_env_names() {
        assert!(is_secret_like_env_name("AWS_SECRET_ACCESS_KEY"));
        assert!(is_secret_like_env_name("github_token"));
        assert!(is_secret_like_env_name("DB_PASSWORD"));
        assert!(!is_secret_like_env_name("AEGIS_RUN_ID"));
        assert!(!is_secret_like_env_name("PATH"));
        assert!(!is_secret_like_env_name("HOME"));
    }

    #[test]
    fn secret_path_signals() {
        assert_eq!(
            secret_path_signal("/home/agent/.ssh/id_rsa").as_deref(),
            Some("id_rsa")
        );
        assert_eq!(secret_path_signal("/tmp/app/.env").as_deref(), Some(".env"));
        assert_eq!(
            secret_path_signal("/workspace/tls/server.pem").as_deref(),
            Some("*.pem")
        );
        assert!(secret_path_signal("/workspace/readme.txt").is_none());
        assert!(secret_path_signal("/proc/1/environ").is_none());
    }

    #[test]
    fn parse_environ_names_strips_values() {
        let env = b"PATH=/usr/bin\0AWS_SECRET_ACCESS_KEY=supersecret\0AEGIS_RUN_ID=r1\0";
        let names = parse_environ_names(env);
        assert!(names.contains(&"PATH".to_string()));
        assert!(names.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(names.contains(&"AEGIS_RUN_ID".to_string()));
        // Ensure we never treat the value as a name.
        assert!(!names.iter().any(|n| n.contains("supersecret")));
    }

    #[test]
    fn env_names_for_pid_in_fake_proc() {
        let root = tempdir().unwrap();
        let p = root.path().join("3");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("environ"), b"FOO=1\0GITHUB_TOKEN=x\0").unwrap();
        let names = env_names_for_pid_in(root.path(), 3);
        assert_eq!(names, vec!["FOO".to_string(), "GITHUB_TOKEN".to_string()]);
    }

    #[test]
    fn poll_empty_is_harmless() {
        let c = SecretCollector::new();
        let d = tempdir().unwrap();
        let spool = SpoolQueue::open(d.path(), 1_000_000).unwrap();
        c.poll(&spool);
    }
}
