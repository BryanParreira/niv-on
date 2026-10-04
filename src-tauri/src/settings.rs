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
    /// Stream from a Linux sensor (e.g. Raspberry Pi + ALFA adapter) over SSH.
    Remote,
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
    pub remote: RemoteSensor,
}

/// A Linux box with a monitor-capable adapter, reached with key-based SSH.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RemoteSensor {
    /// `user@host` (an SSH config alias works too).
    pub host: String,
    pub port: u16,
    /// Capture interface on the sensor, e.g. `wlan1`.
    pub iface: String,
    /// Put the interface in monitor mode before capturing.
    pub monitor: bool,
    pub channel: u16,
    pub hop: bool,
    /// Replace the generated command entirely (advanced).
    pub custom_command: String,
}

impl Default for RemoteSensor {
    fn default() -> Self {
        RemoteSensor {
            host: String::new(),
            port: 22,
            iface: "wlan1".into(),
            monitor: true,
            channel: 6,
            hop: false,
            custom_command: String::new(),
        }
    }
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
            remote: RemoteSensor::default(),
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

    /// Contact with an indicator on the watchlist (IP, CIDR or domain).
    pub threat_intel: bool,
    /// Indicators of compromise, one per entry: `203.0.113.7`, `198.51.100.0/24`, `evil.example`.
    pub watchlist: Vec<String>,
    /// Algorithmically generated (DGA-like) domain names in DNS / TLS.
    pub suspicious_domains: bool,
    /// ARP spoofing / gateway impersonation and rogue IPv6 router advertisements.
    pub spoofing: bool,
    /// Raise a correlated "risk threshold" alert when a device's risk score
    /// reaches this value from at least two different rules (0 = off).
    pub risk_threshold: u32,
    /// Suricata / Snort signature matching.
    pub ids: bool,
    /// Compare each device with the other devices of its type.
    pub peer_groups: bool,
    /// TLS (JA3) and DHCP fingerprint changes after learning.
    pub fingerprint_drift: bool,
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
            risky_ports: vec![
                23, 2323, 22, 445, 3389, 5555, 7547, 6667, 4444, 37215, 52869,
            ],
            deauth_flood: true,
            deauth_threshold: 30,
            new_device: true,
            threat_intel: true,
            watchlist: vec![],
            suspicious_domains: true,
            spoofing: true,
            risk_threshold: 100,
            ids: true,
            peer_groups: true,
            fingerprint_drift: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub capture: CaptureSettings,
    pub rules: RuleSettings,
    pub library: Library,
    pub data: DataSettings,
    pub playbooks: Vec<crate::playbook::Playbook>,
}

/// Storage, threat feeds, evidence and reports.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DataSettings {
    /// Days of connection / DNS history to keep (0 = forever).
    pub retention_days: u32,
    /// Enabled threat-intel feed ids (see `intel::FEEDS`).
    pub feeds: Vec<String>,
    /// Refresh feeds and the CISA KEV catalog once a day.
    pub auto_update_intel: bool,
    /// Save a pcap automatically for high / critical alerts.
    pub auto_evidence: bool,
    /// `off`, `daily` or `weekly`.
    pub report_schedule: String,
    pub last_report: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for DataSettings {
    fn default() -> Self {
        DataSettings {
            retention_days: 30,
            feeds: crate::intel::FEEDS
                .iter()
                .map(|f| f.id.to_string())
                .collect(),
            auto_update_intel: true,
            auto_evidence: true,
            report_schedule: "off".into(),
            last_report: None,
        }
    }
}

/// Searches the user built: saved searches, dashboard panels and detections.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Library {
    pub saved_searches: Vec<SavedSearch>,
    pub panels: Vec<Panel>,
    pub detections: Vec<Detection>,
    pub lookups: Vec<Lookup>,
}

/// A CSV lookup table (e.g. MAC -> owner, room, department) joinable in searches.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lookup {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedSearch {
    pub name: String,
    pub query: String,
}

/// One dashboard panel: a search rendered as a chart, table or single value.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Panel {
    pub id: String,
    pub title: String,
    pub query: String,
    /// `table`, `bar`, `line` or `single`.
    pub viz: String,
    /// `1` (third) or `2` (two thirds) grid columns.
    #[serde(default = "one")]
    pub width: u8,
}

fn one() -> u8 {
    1
}

/// A saved search run every minute; any result raises an alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub id: String,
    pub name: String,
    pub query: String,
    pub severity: crate::engine::Severity,
    pub enabled: bool,
    /// Don't re-alert for the same device within this many minutes.
    #[serde(default = "hour")]
    pub throttle_minutes: u32,
}

fn hour() -> u32 {
    60
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
