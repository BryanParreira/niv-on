//! Automated response playbooks (SOAR-style): when an alert matches a
//! playbook's trigger, its actions run — desktop notification, packet
//! evidence, open an investigation, tag the device, raise its priority, or
//! run your own script (e.g. to block the device on the router).

use crate::engine::{Alert, Priority, Severity};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Trigger: alerts at least this severe...
    pub min_severity: Severity,
    /// ...from these rules (empty = any rule)...
    #[serde(default)]
    pub rules: Vec<String>,
    /// ...on IoT devices only.
    #[serde(default)]
    pub iot_only: bool,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Action {
    /// Desktop notification.
    Notify,
    /// Save a pcap of the device's recent packets.
    Evidence,
    /// Move the alert to "in progress" and assign it.
    Investigate {
        owner: String,
    },
    Tag {
        tag: String,
    },
    Priority {
        priority: Priority,
    },
    /// Run a program with NIV_* environment variables (30 s timeout).
    Script {
        path: String,
    },
}

impl Playbook {
    pub fn matches(&self, a: &Alert, iot: bool) -> bool {
        self.enabled
            && a.severity >= self.min_severity
            && (self.rules.is_empty() || self.rules.iter().any(|r| r == &a.rule))
            && (!self.iot_only || iot)
            && a.rule != "test"
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLog {
    pub ts: DateTime<Utc>,
    pub playbook: String,
    pub alert_id: u64,
    pub alert_title: String,
    pub results: Vec<String>,
    pub ok: bool,
}

static LOG: OnceLock<Mutex<VecDeque<RunLog>>> = OnceLock::new();

fn log() -> &'static Mutex<VecDeque<RunLog>> {
    LOG.get_or_init(|| Mutex::new(VecDeque::new()))
}

pub fn record(entry: RunLog) {
    let mut l = log().lock();
    l.push_front(entry);
    l.truncate(200);
}

pub fn history() -> Vec<RunLog> {
    log().lock().iter().cloned().collect()
}

/// Run a script with alert context in the environment; returns a status line.
pub fn run_script(path: &str, env: &[(&str, String)]) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("no script configured".into());
    }
    let mut cmd = Command::new(path);
    for (k, v) in env {
        cmd.env(k, v);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{path}: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child
                    .wait_with_output()
                    .map(|o| {
                        String::from_utf8_lossy(if o.stdout.is_empty() {
                            &o.stderr
                        } else {
                            &o.stdout
                        })
                        .trim()
                        .chars()
                        .take(200)
                        .collect::<String>()
                    })
                    .unwrap_or_default();
                return if status.success() {
                    Ok(format!(
                        "script ok{}",
                        if out.is_empty() {
                            String::new()
                        } else {
                            format!(": {out}")
                        }
                    ))
                } else {
                    Err(format!("script exited with {status}: {out}"))
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Ok(None) => {
                let _ = child.kill();
                return Err("script timed out after 30 s".into());
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(sev: Severity, rule: &str) -> Alert {
        serde_json::from_value(serde_json::json!({
            "id": 1, "ts": Utc::now(), "severity": sev, "rule": rule, "title": "t", "message": "m",
            "device": null, "deviceLabel": null, "remote": null, "port": null, "value": null, "acknowledged": false
        }))
        .unwrap()
    }

    #[test]
    fn trigger_matching() {
        let pb = Playbook {
            id: "x".into(),
            name: "x".into(),
            enabled: true,
            min_severity: Severity::High,
            rules: vec!["arp-spoof".into()],
            iot_only: false,
            actions: vec![Action::Notify],
        };
        assert!(pb.matches(&alert(Severity::Critical, "arp-spoof"), false));
        assert!(!pb.matches(&alert(Severity::Medium, "arp-spoof"), false));
        assert!(!pb.matches(&alert(Severity::Critical, "new-device"), false));
        let json = serde_json::to_string(&Action::Priority {
            priority: Priority::High,
        })
        .unwrap();
        assert_eq!(json, r#"{"type":"priority","priority":"high"}"#);
    }

    #[cfg(unix)]
    #[test]
    fn scripts_get_alert_context() {
        assert!(run_script("", &[]).is_err());
        let dir = std::env::temp_dir().join(format!("niv-pb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("s.sh");
        std::fs::write(&script, "#!/bin/sh\necho \"blocked $NIV_DEVICE_MAC\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = run_script(
            script.to_str().unwrap(),
            &[("NIV_DEVICE_MAC", "aa:bb:cc:dd:ee:ff".into())],
        )
        .unwrap();
        assert_eq!(out, "script ok: blocked aa:bb:cc:dd:ee:ff");
        let _ = std::fs::remove_dir_all(dir);
    }
}
