//! User-configurable capture and detection settings (persisted to disk).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Live capture from a network interface via libpcap.
    Live,
    /// Built-in traffic generator with scripted anomalies (demo / testing).
    Simulator,
    /// Replay a .pcap / .pcapng file.
    File,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CaptureSettings {
    pub source: Source,
    pub interface: Option<String>,
    /// Put the card in RF monitor mode (raw 802.11 + radiotap).
    pub monitor_mode: bool,
    pub promiscuous: bool,
    /// Fixed channel to listen on (ignored while hopping).
    pub channel: Option<u16>,
    pub hop: bool,
    pub hop_channels: Vec<u16>,
    pub hop_dwell_ms: u64,
    /// Optional BPF filter, e.g. `not type ctl`.
    pub bpf_filter: String,
    pub file_path: Option<String>,
}

impl Default for CaptureSettings {
    fn default() -> Self {
        CaptureSettings {
            source: Source::Simulator,
            interface: None,
            monitor_mode: true,
            promiscuous: true,
            channel: Some(6),
            hop: false,
            hop_channels: vec![1, 6, 11],
            hop_dwell_ms: 500,
            bpf_filter: String::new(),
            file_path: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuleSettings {
    /// How long after a device is first seen its behavior is treated as the
    /// "normal" baseline. Use hours/days for real deployments.
    pub learning_minutes: u32,

    pub new_destination: bool,
    /// Only raise new-destination alerts for IoT-class devices (laptops and
    /// phones legitimately reach new hosts all the time).
    pub new_destination_iot_only: bool,

    pub unusual_time: bool,
    pub quiet_hours_enabled: bool,
    pub quiet_start_hour: u8,
    pub quiet_end_hour: u8,

    pub volume_spike: bool,
    /// Alert when a 10 s window exceeds `factor` x the device's learned peak.
    pub spike_factor: f64,
    /// ...and at least this many bytes (avoids alerts on tiny baselines).
    pub spike_min_bytes: u64,

    pub connection_burst: bool,
    /// TCP connection attempts (SYN) or distinct destinations per 10 s.
    pub syn_threshold: u32,

    pub unexpected_port: bool,
    pub risky_ports: Vec<u16>,

    pub deauth_flood: bool,
    /// Deauth/disassoc frames from one transmitter per 10 s.
    pub deauth_threshold: u32,

    pub new_device: bool,
}

impl Default for RuleSettings {
    fn default() -> Self {
        RuleSettings {
            learning_minutes: 2,
            new_destination: true,
            new_destination_iot_only: true,
            unusual_time: true,
            quiet_hours_enabled: false,
            quiet_start_hour: 0,
            quiet_end_hour: 6,
            volume_spike: true,
            spike_factor: 4.0,
            spike_min_bytes: 1_000_000,
            connection_burst: true,
            syn_threshold: 40,
            unexpected_port: true,
            // telnet, ssh, smb, rdp, adb, TR-069, IRC, common backdoor/Mirai ports
            risky_ports: vec![23, 2323, 22, 445, 3389, 5555, 7547, 6667, 4444, 37215, 52869],
            deauth_flood: true,
            deauth_threshold: 30,
            new_device: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub capture: CaptureSettings,
    pub rules: RuleSettings,
}

impl RuleSettings {
    pub fn in_quiet_hours(&self, hour: u32) -> bool {
        let (s, e) = (self.quiet_start_hour as u32, self.quiet_end_hour as u32);
        if s == e {
            false
        } else if s < e {
            hour >= s && hour < e
        } else {
            hour >= s || hour < e // wraps midnight, e.g. 22 -> 6
        }
    }
}
