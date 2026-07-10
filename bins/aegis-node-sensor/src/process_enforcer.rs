//! Host process enforcement for signed control commands.
//!
//! The sensor keeps an in-memory map of `run_id` → host PID for agent
//! workloads it is responsible for on this node (unknown agents on bare
//! metal / host processes — Docker cages are enforced by
//! `aegis-cage-runner` instead).
//!
//! Kill / pause / resume / quarantine map onto POSIX signals:
//! - kill: SIGTERM, brief wait, then SIGKILL if still alive
//! - pause: SIGSTOP
//! - resume: SIGCONT
//! - quarantine: same as kill (stop execution; workspace evidence is a
//!   separate path when collectors land)
//!
//! Missing targets are treated as already-terminal (ACK / Ok) so control
//! is idempotent — matching `docs/AegisAgent_Control_Command_Protocol.md`
//! § kill_run semantics for already-dead runs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnforceError {
    #[error("process {pid} signal {signal} failed: {detail}")]
    SignalFailed {
        pid: i32,
        signal: i32,
        detail: String,
    },
    #[error("invalid pid {0}")]
    InvalidPid(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    Paused,
    Killed,
}

#[derive(Debug, Clone)]
struct TrackedRun {
    pid: i32,
    state: RunState,
}

/// Thread-safe registry + signal applicator for host PIDs owned by this sensor.
#[derive(Debug, Default)]
pub struct ProcessEnforcer {
    runs: Mutex<HashMap<String, TrackedRun>>,
}

impl ProcessEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Associate a host PID with a cage/host run id. Replaces any previous
    /// registration for the same `run_id`.
    pub fn register_run(&self, run_id: impl Into<String>, pid: i32) -> Result<(), EnforceError> {
        if pid <= 0 {
            return Err(EnforceError::InvalidPid(pid));
        }
        self.runs.lock().expect("process enforcer lock").insert(
            run_id.into(),
            TrackedRun {
                pid,
                state: RunState::Running,
            },
        );
        Ok(())
    }

    pub fn unregister_run(&self, run_id: &str) -> Option<i32> {
        self.runs
            .lock()
            .expect("process enforcer lock")
            .remove(run_id)
            .map(|r| r.pid)
    }

    pub fn has_run(&self, run_id: &str) -> bool {
        self.runs
            .lock()
            .expect("process enforcer lock")
            .contains_key(run_id)
    }

    pub fn pid_for(&self, run_id: &str) -> Option<i32> {
        self.runs
            .lock()
            .expect("process enforcer lock")
            .get(run_id)
            .map(|r| r.pid)
    }

    pub fn state_for(&self, run_id: &str) -> Option<RunState> {
        self.runs
            .lock()
            .expect("process enforcer lock")
            .get(run_id)
            .map(|r| r.state)
    }

    pub fn tracked_run_ids(&self) -> Vec<String> {
        self.runs
            .lock()
            .expect("process enforcer lock")
            .keys()
            .cloned()
            .collect()
    }

    /// Kill one run. Idempotent if missing or already killed.
    pub fn kill_run(&self, run_id: &str) -> Result<(), EnforceError> {
        let pid = {
            let mut map = self.runs.lock().expect("process enforcer lock");
            match map.get_mut(run_id) {
                None => return Ok(()),
                Some(tracked) if tracked.state == RunState::Killed => return Ok(()),
                Some(tracked) => {
                    tracked.state = RunState::Killed;
                    tracked.pid
                }
            }
        };
        self.kill_pid(pid)
    }

    /// Pause (SIGSTOP). Missing / already killed → Ok (idempotent).
    pub fn pause_run(&self, run_id: &str) -> Result<(), EnforceError> {
        let pid = {
            let mut map = self.runs.lock().expect("process enforcer lock");
            match map.get_mut(run_id) {
                None => return Ok(()),
                Some(tracked) if tracked.state == RunState::Killed => return Ok(()),
                Some(tracked) if tracked.state == RunState::Paused => return Ok(()),
                Some(tracked) => {
                    tracked.state = RunState::Paused;
                    tracked.pid
                }
            }
        };
        send_signal(pid, libc::SIGSTOP)
    }

    /// Resume (SIGCONT). Missing / killed → Ok.
    pub fn resume_run(&self, run_id: &str) -> Result<(), EnforceError> {
        let pid = {
            let mut map = self.runs.lock().expect("process enforcer lock");
            match map.get_mut(run_id) {
                None => return Ok(()),
                Some(tracked) if tracked.state == RunState::Killed => return Ok(()),
                Some(tracked) => {
                    tracked.state = RunState::Running;
                    tracked.pid
                }
            }
        };
        send_signal(pid, libc::SIGCONT)
    }

    /// Quarantine = stop execution (kill). Workspace freeze is follow-up work.
    pub fn quarantine_run(&self, run_id: &str) -> Result<(), EnforceError> {
        self.kill_run(run_id)
    }

    /// Kill every registered run (sensor-scoped containment).
    pub fn kill_all_registered(&self) -> Result<(), EnforceError> {
        let ids: Vec<String> = self.tracked_run_ids();
        for id in ids {
            self.kill_run(&id)?;
        }
        Ok(())
    }

    fn kill_pid(&self, pid: i32) -> Result<(), EnforceError> {
        // Already dead → success (ESRCH).
        match send_signal(pid, libc::SIGTERM) {
            Ok(()) => {}
            Err(EnforceError::SignalFailed { detail, .. })
                if detail.contains("No such process") =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        // Brief grace, then escalate — control-plane kill must not leave
        // a hung agent forever (full grace_period from command payload
        // is future work; 200ms is enough for unit tests and local SIGTERM).
        std::thread::sleep(Duration::from_millis(200));
        if process_alive(pid) {
            match send_signal(pid, libc::SIGKILL) {
                Ok(()) => {}
                Err(EnforceError::SignalFailed { detail, .. })
                    if detail.contains("No such process") => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn send_signal(pid: i32, signal: i32) -> Result<(), EnforceError> {
    if pid <= 0 {
        return Err(EnforceError::InvalidPid(pid));
    }
    // Use the `kill` CLI rather than `libc::kill` so we stay out of `unsafe`
    // (Semgrep rust.lang.security.unsafe-usage). Arguments are always
    // integer PIDs we registered ourselves — never shell-interpolated.
    let flag = match signal {
        s if s == libc::SIGTERM => "-TERM",
        s if s == libc::SIGKILL => "-KILL",
        s if s == libc::SIGSTOP => "-STOP",
        s if s == libc::SIGCONT => "-CONT",
        other => {
            return Err(EnforceError::SignalFailed {
                pid,
                signal: other,
                detail: format!("unsupported signal {other}"),
            });
        }
    };
    let output = std::process::Command::new("kill")
        .args([flag, &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| EnforceError::SignalFailed {
            pid,
            signal,
            detail: e.to_string(),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Already-dead is success for control-plane kill (idempotent).
        if detail.contains("No such process") || detail.contains("no such process") {
            return Ok(());
        }
        Err(EnforceError::SignalFailed {
            pid,
            signal,
            detail: if detail.is_empty() {
                format!("kill exited {}", output.status)
            } else {
                detail
            },
        })
    }
}

/// `true` if a process with `pid` exists (`kill -0`).
pub fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn spawn_sleep() -> std::process::Child {
        Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[test]
    fn kill_run_terminates_a_real_child_process() {
        let mut child = spawn_sleep();
        let pid = child.id() as i32;
        let enforcer = ProcessEnforcer::new();
        enforcer.register_run("run-kill", pid).unwrap();

        enforcer.kill_run("run-kill").unwrap();
        let status = child.wait().expect("wait");
        assert!(!status.success() || status.code().is_none());
        assert!(!process_alive(pid));
        assert_eq!(enforcer.state_for("run-kill"), Some(RunState::Killed));
    }

    #[test]
    fn kill_missing_run_is_idempotent_ok() {
        let enforcer = ProcessEnforcer::new();
        enforcer.kill_run("never-registered").unwrap();
    }

    #[test]
    fn pause_and_resume_use_stop_and_cont() {
        let mut child = spawn_sleep();
        let pid = child.id() as i32;
        let enforcer = ProcessEnforcer::new();
        enforcer.register_run("run-pause", pid).unwrap();

        enforcer.pause_run("run-pause").unwrap();
        assert_eq!(enforcer.state_for("run-pause"), Some(RunState::Paused));
        // Process still exists while stopped.
        assert!(process_alive(pid));

        enforcer.resume_run("run-pause").unwrap();
        assert_eq!(enforcer.state_for("run-pause"), Some(RunState::Running));
        assert!(process_alive(pid));

        enforcer.kill_run("run-pause").unwrap();
        let _ = child.wait();
    }

    #[test]
    fn quarantine_kills_like_kill_run() {
        let mut child = spawn_sleep();
        let pid = child.id() as i32;
        let enforcer = ProcessEnforcer::new();
        enforcer.register_run("run-q", pid).unwrap();
        enforcer.quarantine_run("run-q").unwrap();
        let _ = child.wait();
        assert!(!process_alive(pid));
    }

    #[test]
    fn kill_all_registered_clears_multiple_children() {
        let mut a = spawn_sleep();
        let mut b = spawn_sleep();
        let enforcer = ProcessEnforcer::new();
        enforcer.register_run("a", a.id() as i32).unwrap();
        enforcer.register_run("b", b.id() as i32).unwrap();
        enforcer.kill_all_registered().unwrap();
        let _ = a.wait();
        let _ = b.wait();
        assert!(!process_alive(a.id() as i32));
        assert!(!process_alive(b.id() as i32));
    }

    #[test]
    fn register_rejects_non_positive_pid() {
        let enforcer = ProcessEnforcer::new();
        assert_eq!(
            enforcer.register_run("x", 0).unwrap_err(),
            EnforceError::InvalidPid(0)
        );
    }
}
