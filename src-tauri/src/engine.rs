//! Device profiling, behavioral baselines and the anomaly-detection rules.
//!
//! Every decoded packet goes through [`Engine::process`]. Per device we keep:
//! * identity: MAC, vendor (OUI), randomized-MAC flag, auto class, user tag
//! * radio: RSSI (last + smoothed), channel, AP role, SSIDs, connection history
//! * traffic: frame counts, tx/rx volume, per-second history, hour-of-day histogram
//! * network behavior: remote destinations (IP + DNS/SNI name), service ports
//! * a **baseline**: everything observed during the first `learning_minutes`
//!   after the device appears. After that, deviations raise alerts.

use crate::fingerprint::{self, ClientHello};
use crate::ids::{self, RuleSet};
use crate::intel::{Hit, Intel, Kev};
use crate::model::{is_local_ip, FrameKind, Hint, IpNet, Mac, PacketInfo, Transport};
use crate::oui::{classify, is_iot_class, ClassHints, OuiDb};
use crate::settings::RuleSettings;
use chrono::{DateTime, Duration, Local, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Length of the sliding window used by the rate-based rules.
pub const WINDOW_SECS: i64 = 10;
/// Global traffic graph history (seconds).
const TRAFFIC_HISTORY: usize = 600;
/// Per-device throughput history (seconds).
const DEVICE_HISTORY: i64 = 300;
const MAX_ALERTS: usize = 2000;
/// Memory bounds for long captures on busy networks.
const MAX_DESTINATIONS: usize = 3000;
const MAX_DEVICES: usize = 5000;
const MAX_LIST: usize = 64;
const FEED_LEN: usize = 500;
/// Minimum seconds between repeated alerts of the same rate rule per device.
const RATE_ALERT_COOLDOWN: i64 = 60;
/// Ports that every device uses for plumbing; never "unexpected".
const INFRA_PORTS: &[u16] = &[
    53, 67, 68, 123, 137, 138, 139, 546, 547, 1900, 3702, 5353, 5355,
];
/// Registered UDP services above 1024 that are safe to recognise without a handshake.
const UDP_SERVICES: &[u16] = &[1194, 1900, 3478, 4500, 5060, 5353, 5683, 51820];
/// Distinct internet hosts a MAC must relay before it is treated as a router
/// (when no authoritative router identity is known).
const FORWARD_MIN: usize = 5;
/// Minimum seconds between spoofing / conflict alerts for the same device.
const SPOOF_ALERT_COOLDOWN: i64 = 300;
/// Minimum seconds between correlated risk-threshold alerts per device.
const RISK_ALERT_COOLDOWN: i64 = 3600;
/// Risk contributions halve every this many hours.
const RISK_HALF_LIFE_H: f64 = 24.0;
/// A flow with no packets for this long is closed and logged.
const FLOW_IDLE_SECS: i64 = 60;
const MAX_FLOWS: usize = 20_000;
/// Minimum seconds between alerts for the same signature on one device.
const IDS_COOLDOWN: i64 = 600;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: u64,
    pub ts: DateTime<Utc>,
    pub severity: Severity,
    /// Rule identifier, e.g. `new-destination`.
    pub rule: String,
    pub title: String,
    pub message: String,
    pub device: Option<Mac>,
    pub device_label: Option<String>,
    pub remote: Option<String>,
    pub port: Option<u16>,
    /// Rule-specific measurement (bytes in window, frame count, ...).
    pub value: Option<f64>,
    pub acknowledged: bool,
    /// MITRE ATT&CK technique this detection maps to, e.g. `T1046`.
    #[serde(default)]
    pub mitre_id: Option<String>,
    #[serde(default)]
    pub mitre_name: Option<String>,
    #[serde(default)]
    pub tactic: Option<String>,
    /// Incident-review workflow state.
    #[serde(default)]
    pub status: AlertStatus,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
    /// Severity adjusted by the device's asset priority (computed for views).
    #[serde(default)]
    pub urgency: Option<Severity>,
    /// Path of the packet-evidence pcap saved for this alert.
    #[serde(default)]
    pub evidence: Option<String>,
    /// The packet that triggered the alert: who, to whom, how, and what it carried.
    #[serde(default)]
    pub context: Option<AlertContext>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertContext {
    /// Application protocol as decoded (DNS, TLS, HTTP, ARP, 802.11 mgmt...).
    pub protocol: String,
    /// One-line decode of the packet.
    pub summary: String,
    pub transport: Option<String>,
    pub src_mac: Option<Mac>,
    pub dst_mac: Option<Mac>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// Known service name of the server port.
    pub service: Option<String>,
    /// DNS / TLS name of the remote side, when known.
    pub domain: Option<String>,
    /// `outbound` (to the internet), `inbound` (from the internet) or `local`.
    pub direction: String,
    pub frame_len: u32,
    /// Printable excerpt of the payload (non-printable bytes as dots).
    pub payload: Option<String>,
    pub payload_hex: Option<String>,
    /// Rate rules fire on the packet that crossed the threshold, not a single request.
    pub aggregate: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertStatus {
    #[default]
    New,
    InProgress,
    Resolved,
    FalsePositive,
}

impl AlertStatus {
    pub fn closed(self) -> bool {
        matches!(self, AlertStatus::Resolved | AlertStatus::FalsePositive)
    }
    fn label(self) -> &'static str {
        match self {
            AlertStatus::New => "new",
            AlertStatus::InProgress => "in progress",
            AlertStatus::Resolved => "resolved",
            AlertStatus::FalsePositive => "false positive",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub ts: DateTime<Utc>,
    pub text: String,
}

/// How much a device matters (Splunk ES asset priority).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl Priority {
    fn risk_factor(self) -> f64 {
        match self {
            Priority::Low => 0.5,
            Priority::Medium => 1.0,
            Priority::High => 1.5,
            Priority::Critical => 2.0,
        }
    }
}

/// Urgency = severity shifted by asset priority (low -1, high +1, critical +2).
pub fn urgency(s: Severity, p: Priority) -> Severity {
    const ORDER: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let delta: i32 = match p {
        Priority::Low => -1,
        Priority::Medium => 0,
        Priority::High => 1,
        Priority::Critical => 2,
    };
    ORDER[(s as i32 + delta).clamp(0, 4) as usize]
}

/// MITRE ATT&CK mapping for each detection: (technique id, name, tactic).
pub fn attack(rule: &str) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match rule {
        "new-destination" => ("T1071", "Application Layer Protocol", "Command and Control"),
        "threat-intel" => ("T1071", "Application Layer Protocol", "Command and Control"),
        "suspicious-domain" => (
            "T1568.002",
            "Domain Generation Algorithms",
            "Command and Control",
        ),
        "unexpected-port" => ("T1571", "Non-Standard Port", "Command and Control"),
        "risky-port" => ("T1021", "Remote Services", "Lateral Movement"),
        "connection-burst" => ("T1046", "Network Service Discovery", "Discovery"),
        "volume-spike" => (
            "T1048",
            "Exfiltration Over Alternative Protocol",
            "Exfiltration",
        ),
        "unusual-time" => ("T1029", "Scheduled Transfer", "Exfiltration"),
        "deauth-flood" => ("T1498", "Network Denial of Service", "Impact"),
        "new-device" => ("T1200", "Hardware Additions", "Initial Access"),
        "arp-spoof" | "ip-conflict" => ("T1557.002", "ARP Cache Poisoning", "Credential Access"),
        "rogue-router" => ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        "fingerprint-change" | "identity-change" => ("T1036", "Masquerading", "Defense Evasion"),
        "peer-anomaly" => ("T1595", "Active Scanning", "Reconnaissance"),
        _ => return None,
    })
}

impl Alert {
    fn tag_attack(&mut self) {
        if let Some((id, name, tactic)) = attack(&self.rule) {
            self.mitre_id = Some(id.into());
            self.mitre_name = Some(name.into());
            self.tactic = Some(tactic.into());
        }
    }
}

fn set_status(a: &mut Alert, s: AlertStatus, ts: DateTime<Utc>) {
    if a.status != s {
        a.notes.push(Note {
            ts,
            text: format!("Status: {} → {}", a.status.label(), s.label()),
        });
        a.status = s;
    }
    a.acknowledged = s.closed();
}

/// Risk points an open alert contributes before decay (Splunk-style RBA).
fn severity_points(s: Severity) -> f64 {
    match s {
        Severity::Info => 2.0,
        Severity::Low => 5.0,
        Severity::Medium => 15.0,
        Severity::High => 35.0,
        Severity::Critical => 60.0,
    }
}

struct Draft {
    severity: Severity,
    rule: &'static str,
    title: String,
    message: String,
    device: Option<Mac>,
    remote: Option<String>,
    port: Option<u16>,
    value: Option<f64>,
    ts: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FrameCounts {
    pub management: u64,
    pub control: u64,
    pub data: u64,
    pub ethernet: u64,
}

impl FrameCounts {
    fn add(&mut self, k: FrameKind) {
        match k {
            FrameKind::Management => self.management += 1,
            FrameKind::Control => self.control += 1,
            FrameKind::Data => self.data += 1,
            FrameKind::Ethernet => self.ethernet += 1,
        }
    }
    pub fn total(&self) -> u64 {
        self.management + self.control + self.data + self.ethernet
    }
}

/// A (device, access point) association observed on air.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub bssid: Mac,
    pub ssid: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub frames: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Destination {
    pub ip: IpAddr,
    pub domain: Option<String>,
    pub external: bool,
    pub ports: BTreeSet<u16>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub packets: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub in_baseline: bool,
    #[serde(default)]
    pub alerted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Baseline {
    pub learning_started: DateTime<Utc>,
    pub learning_until: DateTime<Utc>,
    /// Local hours-of-day in which the device was active while learning.
    pub hours: [bool; 24],
    pub destinations: BTreeSet<IpAddr>,
    /// Registrable domains (e.g. `ecobee.com`) - robust to CDN IP rotation.
    pub domains: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    /// Largest 10 s byte count seen while learning.
    pub peak_window_bytes: u64,
    pub avg_window_bytes: f64,
    pub windows: u64,
    /// TLS client fingerprints (JA4) seen while learning.
    #[serde(default)]
    pub tls: BTreeSet<String>,
}

impl Baseline {
    fn new(start: DateTime<Utc>, minutes: u32) -> Self {
        Baseline {
            learning_started: start,
            learning_until: start + Duration::minutes(minutes as i64),
            hours: [false; 24],
            destinations: BTreeSet::new(),
            domains: BTreeSet::new(),
            ports: BTreeSet::new(),
            peak_window_bytes: 0,
            avg_window_bytes: 0.0,
            windows: 0,
            tls: BTreeSet::new(),
        }
    }

    pub fn learning(&self, ts: DateTime<Utc>) -> bool {
        ts < self.learning_until
    }

    /// Hour-of-day profile is only meaningful after a full day of learning.
    fn hours_valid(&self) -> bool {
        self.learning_until - self.learning_started >= Duration::hours(24)
    }
}

/// Volatile per-device counters for the rate rules (not persisted).
#[derive(Debug, Default, Clone)]
struct Live {
    win_start: i64,
    win_bytes: u64,
    win_syns: u32,
    win_dests: HashSet<IpAddr>,
    spike_alerted: i64,
    burst_alerted: i64,
    hour_key: i64,
    hour_bytes: u64,
    hour_syns: u32,
    unusual_alerted_hour: i64,
    newdest_alerted: i64,
    deauth_win_start: i64,
    deauth_count: u32,
    deauth_alerted: i64,
    spoof_alerted: i64,
    risk_alerted: i64,
    dga_alerted: i64,
    /// Signature id -> last alert second.
    ids_alerted: HashMap<u32, i64>,
    /// Internet hosts whose traffic this MAC relayed (router heuristic).
    forwarded: HashSet<IpAddr>,
    /// (unix second, bytes) - sparse
    history: VecDeque<(i64, u64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub mac: Mac,
    pub vendor: Option<String>,
    pub randomized: bool,
    pub name: Option<String>,
    pub tag: Option<String>,
    #[serde(default)]
    pub notes: String,
    pub auto_class: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub rssi: Option<i8>,
    pub rssi_avg: Option<f32>,
    pub channel: Option<u16>,
    pub is_ap: bool,
    #[serde(default)]
    pub on_network: bool,
    pub frames: FrameCounts,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    /// SSIDs this device advertises (APs).
    pub ssids: BTreeSet<String>,
    /// SSIDs this device has probed for (stations) - reveals networks it knows.
    pub probed_ssids: BTreeSet<String>,
    pub connections: Vec<Connection>,
    pub ips: BTreeSet<IpAddr>,
    pub destinations: BTreeMap<String, Destination>,
    /// Service port -> packets exchanged as a client.
    pub ports: BTreeMap<u16, u64>,
    /// Packets per local hour-of-day.
    pub hourly: [u64; 24],
    pub baseline: Baseline,
    #[serde(default)]
    pub alerted_ports: BTreeSet<u16>,
    /// Best hostname learned (DHCP, mDNS).
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub hostnames: BTreeSet<String>,
    /// DHCP vendor class - reveals OS/firmware (`android-dhcp-14`, `MSFT 5.0`).
    #[serde(default)]
    pub vendor_class: Option<String>,
    /// mDNS / DNS-SD services the device advertises.
    #[serde(default)]
    pub services: BTreeSet<String>,
    /// UPnP SERVER headers and HTTP User-Agents.
    #[serde(default)]
    pub banners: BTreeSet<String>,
    /// Routes traffic to the internet for other devices.
    #[serde(default)]
    pub is_gateway: bool,
    /// Indicators (watchlist hits, suspicious domains) already alerted on.
    #[serde(default)]
    pub flagged: BTreeSet<String>,
    #[serde(default)]
    pub priority: Priority,
    /// DHCP option 55 parameter request list (client fingerprint).
    #[serde(default)]
    pub dhcp_params: Option<String>,
    /// TLS client fingerprints: JA4 -> details. (JA4 sorts ciphers and
    /// extensions, so it stays stable when browsers shuffle them; JA3 doesn't.)
    #[serde(default)]
    pub tls: BTreeMap<String, TlsFingerprint>,
    /// Ports this device serves (it answered from them) -> packets.
    #[serde(default)]
    pub server_ports: BTreeMap<u16, u64>,
    /// Cleartext / legacy protocols seen: telnet, ftp, http, mqtt, smbv1, legacy-tls...
    #[serde(default)]
    pub insecure: BTreeSet<String>,
    /// DNS resolvers this device queries.
    #[serde(default)]
    pub resolvers: BTreeSet<IpAddr>,
    #[serde(skip)]
    live: Live,
}

impl Device {
    fn new(mac: Mac, ts: DateTime<Utc>, vendor: Option<String>, learning_minutes: u32) -> Self {
        let auto_class = classify(&ClassHints {
            vendor: vendor.as_deref(),
            is_ap: false,
            is_gateway: false,
            hostnames: &[],
            services: &[],
            vendor_class: None,
            banners: &[],
            randomized: mac.is_local(),
            domains: &[],
            ports: &[],
            probes_many_ssids: false,
            os: None,
        });
        Device {
            mac,
            vendor,
            randomized: mac.is_local(),
            name: None,
            tag: None,
            notes: String::new(),
            auto_class: auto_class.into(),
            first_seen: ts,
            last_seen: ts,
            rssi: None,
            rssi_avg: None,
            channel: None,
            is_ap: false,
            on_network: false,
            frames: FrameCounts::default(),
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            ssids: BTreeSet::new(),
            probed_ssids: BTreeSet::new(),
            connections: Vec::new(),
            ips: BTreeSet::new(),
            destinations: BTreeMap::new(),
            ports: BTreeMap::new(),
            hourly: [0; 24],
            baseline: Baseline::new(ts, learning_minutes),
            alerted_ports: BTreeSet::new(),
            hostname: None,
            hostnames: BTreeSet::new(),
            vendor_class: None,
            services: BTreeSet::new(),
            banners: BTreeSet::new(),
            is_gateway: false,
            flagged: BTreeSet::new(),
            priority: Priority::default(),
            dhcp_params: None,
            tls: BTreeMap::new(),
            server_ports: BTreeMap::new(),
            insecure: BTreeSet::new(),
            resolvers: BTreeSet::new(),
            live: Live::default(),
        }
    }

    pub fn class(&self) -> &str {
        self.tag
            .as_deref()
            .filter(|t| !t.is_empty())
            .unwrap_or(&self.auto_class)
    }

    pub fn is_iot(&self) -> bool {
        is_iot_class(self.class())
    }

    /// Operating system family from the DHCP fingerprint.
    pub fn os(&self) -> Option<&'static str> {
        fingerprint::dhcp_os(
            self.dhcp_params.as_deref().unwrap_or(""),
            self.vendor_class.as_deref(),
        )
    }

    pub fn label(&self) -> String {
        if let Some(n) = self.name.as_deref().filter(|n| !n.is_empty()) {
            return n.to_string();
        }
        if let Some(h) = &self.hostname {
            return h.clone();
        }
        let m = self.mac.to_string();
        format!("{} ·{}", self.class(), &m[9..])
    }

    fn touch(&mut self, ts: DateTime<Utc>) {
        if ts > self.last_seen {
            self.last_seen = ts;
        }
    }

    fn update_rssi(&mut self, r: i8) {
        self.rssi = Some(r);
        self.rssi_avg = Some(match self.rssi_avg {
            Some(a) => a * 0.9 + r as f32 * 0.1,
            None => r as f32,
        });
    }

    fn record_connection(&mut self, bssid: Mac, ssid: Option<String>, ts: DateTime<Utc>) {
        if let Some(c) = self.connections.iter_mut().find(|c| c.bssid == bssid) {
            c.last_seen = ts;
            c.frames += 1;
            if c.ssid.is_none() {
                c.ssid = ssid;
            }
        } else {
            if self.connections.len() < MAX_LIST {
                self.connections.push(Connection {
                    bssid,
                    ssid,
                    first_seen: ts,
                    last_seen: ts,
                    frames: 1,
                });
            }
        }
    }

    fn add_history(&mut self, ts: DateTime<Utc>, bytes: u64) {
        let sec = ts.timestamp();
        let h = &mut self.live.history;
        match h.back_mut() {
            Some((t, b)) if *t == sec => *b += bytes,
            Some((t, _)) if *t > sec => {
                if let Some(e) = h.iter_mut().rev().find(|(t, _)| *t == sec) {
                    e.1 += bytes;
                }
            }
            _ => h.push_back((sec, bytes)),
        }
        while h.front().is_some_and(|(t, _)| *t < sec - DEVICE_HISTORY) {
            h.pop_front();
        }
    }

    fn apply_hint(&mut self, h: &Hint) {
        fn add(set: &mut BTreeSet<String>, v: &str) {
            if set.len() < MAX_LIST {
                set.insert(v.to_string());
            }
        }
        match h {
            // Apple & co. announce UUIDs / hex IDs as instance names - not names.
            Hint::Hostname(n) if looks_like_id(n) => {}
            Hint::Hostname(n) => {
                add(&mut self.hostnames, n);
                // Prefer DHCP/mDNS host names over DNS-SD instance labels:
                // the first one seen wins unless a "nicer" one (with spaces) arrives.
                if self.hostname.is_none()
                    || (n.contains(' ') && !self.hostname.as_deref().unwrap_or("").contains(' '))
                {
                    self.hostname = Some(n.clone());
                }
            }
            Hint::VendorClass(v) => self.vendor_class = Some(v.clone()),
            Hint::Service(v) => add(&mut self.services, v),
            Hint::Server(v) | Hint::UserAgent(v) => add(&mut self.banners, v),
            Hint::DhcpParams(v) => self.dhcp_params = Some(v.clone()),
        }
    }

    /// Current connected SSID (most recently active association).
    pub fn current_ssid(&self) -> Option<String> {
        self.connections
            .iter()
            .max_by_key(|c| c.last_seen)
            .and_then(|c| c.ssid.clone())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPoint {
    pub t: i64,
    pub bytes: u64,
    pub packets: u64,
    pub management: u64,
    pub control: u64,
    pub data: u64,
    pub ethernet: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub frames: FrameCounts,
    pub with_ip: u64,
    pub protected: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsFingerprint {
    pub ja3: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
    pub sni: Option<String>,
    pub legacy: bool,
}

/// One logged connection (Zeek conn.log style).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Flow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub mac: Mac,
    pub local_ip: IpAddr,
    pub local_port: Option<u16>,
    pub remote_ip: IpAddr,
    pub remote_port: Option<u16>,
    pub proto: String,
    /// Service port when the device is the client.
    pub service: Option<u16>,
    pub domain: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets: u64,
    pub external: bool,
    /// The device opened the connection.
    pub outbound: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FlowKey(Mac, IpAddr, Option<u16>, IpAddr, Option<u16>, u8);

/// One answered DNS lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    pub ts: DateTime<Utc>,
    pub mac: Mac,
    pub query: String,
    pub answers: Vec<String>,
    /// 0 = NOERROR, 3 = NXDOMAIN.
    pub rcode: u8,
    pub resolver: IpAddr,
}

// ---------------------------------------------------------------------------
// UI views
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub mac: Mac,
    pub label: String,
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub tag: Option<String>,
    pub auto_class: String,
    pub class: String,
    pub is_iot: bool,
    pub randomized: bool,
    pub is_ap: bool,
    pub rssi: Option<i8>,
    pub rssi_avg: Option<f32>,
    pub channel: Option<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub frames: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub ssid: Option<String>,
    pub ips: Vec<IpAddr>,
    pub destinations: usize,
    pub learning: bool,
    pub open_alerts: usize,
    /// Bytes over the last 10 s - drives "top talkers".
    pub recent_bytes: u64,
    pub hostname: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    pub services: usize,
    /// 0-100 risk score from open alerts, decayed over time.
    pub risk: u32,
    pub priority: Priority,
    pub os: Option<String>,
    /// Exposure / vulnerability findings and the worst one's severity.
    pub findings: usize,
    pub exposure: Option<Severity>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskPart {
    /// Rule id (alerts) or finding title (exposures).
    pub source: String,
    pub kind: &'static str,
    pub points: f64,
    pub count: usize,
    pub severity: Severity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDetail {
    #[serde(flatten)]
    pub device: Device,
    pub label: String,
    pub class: String,
    pub is_iot: bool,
    pub learning: bool,
    pub learning_progress: f64,
    pub history: Vec<(i64, u64)>,
    pub alerts: Vec<Alert>,
    pub is_self: bool,
    pub risk: u32,
    pub os: Option<String>,
    pub findings: Vec<crate::exposure::Finding>,
    pub risk_parts: Vec<RiskPart>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct Engine {
    pub devices: HashMap<Mac, Device>,
    pub alerts: VecDeque<Alert>,
    pub next_alert_id: u64,
    pub rules: RuleSettings,
    pub totals: Totals,
    pub traffic: VecDeque<TrafficPoint>,
    /// Latest timestamp observed (packet time) - the engine's clock.
    pub clock: DateTime<Utc>,
    pub started: DateTime<Utc>,
    /// IP -> name learned from DNS answers and TLS SNI.
    dns: HashMap<IpAddr, String>,
    pub oui: OuiDb,
    /// Alerts raised since the last drain (pushed to the UI as events).
    fresh: Vec<Alert>,
    pub dirty: bool,
    /// MACs / IPs of the capturing host (from the selected interface).
    pub self_macs: HashSet<Mac>,
    pub self_ips: HashSet<IpAddr>,
    /// Default gateway reported by the OS routing table.
    pub gateway_ip: Option<IpAddr>,
    /// Router addresses learned from DHCP replies on the wire.
    pub router_ips: HashSet<IpAddr>,
    /// The router's MAC(s), once known (OS ARP cache, workspace, first ARP).
    /// Any other MAC claiming a router IP is impersonating it.
    pub gateway_macs: HashSet<Mac>,
    /// MACs that sent IPv6 router advertisements with a non-zero lifetime.
    ra_routers: HashSet<Mac>,
    /// Subnets of this network. Addresses inside are LAN peers even when they
    /// are publicly routable (campus networks, global IPv6 prefixes).
    pub lan_nets: Vec<IpNet>,
    /// IPv4 -> (MAC, last claimed) from ARP, for spoofing / conflict detection.
    arp_table: HashMap<Ipv4Addr, (Mac, DateTime<Utc>)>,
    intel: Intel,
    pub ids: Arc<RuleSet>,
    pub kev: Arc<Kev>,
    flows: HashMap<FlowKey, Flow>,
    pending_flows: Vec<Flow>,
    pending_dns: Vec<DnsRecord>,
    /// Suppress "new device" alerts while an active discovery scan runs.
    pub quiet_new_until: Option<DateTime<Utc>>,
    pub feed: VecDeque<FeedItem>,
    /// Monotonic across sessions so the UI's incremental feed never repeats.
    feed_seq: u64,
    ticks: u64,
    /// This computer's hostname, used to name its own device entry.
    pub self_hostname: Option<String>,
}

/// One line in the live frame feed.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedItem {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: FrameKind,
    pub protocol: String,
    pub src: Option<Mac>,
    pub dst: Option<Mac>,
    pub rssi: Option<i8>,
    pub channel: Option<u16>,
    pub len: u32,
    pub info: String,
}

impl Engine {
    pub fn new(rules: RuleSettings, oui: OuiDb) -> Self {
        let now = Utc::now();
        Engine {
            devices: HashMap::new(),
            alerts: VecDeque::new(),
            next_alert_id: 1,
            intel: Intel::compile(&rules.watchlist),
            ids: Arc::new(RuleSet::default()),
            kev: Arc::new(Kev::default()),
            flows: HashMap::new(),
            pending_flows: Vec::new(),
            pending_dns: Vec::new(),
            rules,
            totals: Totals::default(),
            traffic: VecDeque::new(),
            clock: now,
            started: now,
            dns: HashMap::new(),
            oui,
            fresh: Vec::new(),
            dirty: false,
            self_macs: HashSet::new(),
            self_ips: HashSet::new(),
            gateway_ip: None,
            router_ips: HashSet::new(),
            gateway_macs: HashSet::new(),
            ra_routers: HashSet::new(),
            lan_nets: Vec::new(),
            arp_table: HashMap::new(),
            quiet_new_until: None,
            feed: VecDeque::new(),
            feed_seq: 0,
            ticks: 0,
            self_hostname: None,
        }
    }

    /// Restore devices and alerts saved from a previous session.
    pub fn restore(&mut self, devices: Vec<Device>, alerts: Vec<Alert>, next_id: u64) {
        for mut d in devices {
            // Router status is re-derived from authoritative evidence every
            // session; older versions persisted false positives.
            d.is_gateway = self.gateway_macs.contains(&d.mac);
            // Re-derive "external" with what we now know about this LAN.
            for x in d.destinations.values_mut() {
                x.external = !self.is_lan(&x.ip);
            }
            self.devices.insert(d.mac, d);
        }
        self.alerts = alerts.into();
        for a in self.alerts.iter_mut() {
            if a.mitre_id.is_none() {
                a.tag_attack();
            }
            // Older versions only had "acknowledged".
            if a.acknowledged && !a.status.closed() {
                a.status = AlertStatus::Resolved;
            }
            // Earlier versions guessed service ports from link-local / peer
            // traffic (DHCPv6, ephemeral UDP) and raised false alerts.
            if a.rule == "unexpected-port" && !a.status.closed() {
                let link_local = a
                    .remote
                    .as_deref()
                    .and_then(|r| r.parse::<IpAddr>().ok())
                    .is_some_and(|ip| is_link_local(&ip));
                if link_local
                    || a.port
                        .is_some_and(|p| INFRA_PORTS.contains(&p) || p >= 49152)
                {
                    a.status = AlertStatus::FalsePositive;
                    a.acknowledged = true;
                    a.notes.push(Note {
                        ts: Utc::now(),
                        text: "Closed automatically: raised by an earlier version that misread link-local traffic as a new service. This was not a real finding.".into(),
                    });
                }
            }
        }
        self.next_alert_id = next_id.max(self.alerts.iter().map(|a| a.id + 1).max().unwrap_or(1));
    }

    pub fn set_rules(&mut self, rules: RuleSettings) {
        self.rules = rules;
    }

    /// Watchlist + feeds, compiled by the caller.
    pub fn set_intel(&mut self, intel: Intel) {
        self.intel = intel;
    }

    pub fn intel_size(&self) -> usize {
        self.intel.len()
    }

    /// Closed connections and DNS answers since the last call (for the store).
    pub fn drain_records(&mut self) -> (Vec<Flow>, Vec<DnsRecord>) {
        (
            std::mem::take(&mut self.pending_flows),
            std::mem::take(&mut self.pending_dns),
        )
    }

    /// Close every open flow (capture stopped / file finished).
    pub fn flush_flows(&mut self) {
        self.pending_flows
            .extend(self.flows.drain().map(|(_, f)| f));
    }

    /// Connections still open, newest first.
    pub fn open_flows(&self, mac: Option<Mac>) -> Vec<Flow> {
        let mut v: Vec<Flow> = self
            .flows
            .values()
            .filter(|f| mac.is_none_or(|m| f.mac == m))
            .cloned()
            .collect();
        v.sort_by_key(|f| std::cmp::Reverse(f.end));
        v
    }

    fn close_idle_flows(&mut self) {
        let cutoff = self.clock - Duration::seconds(FLOW_IDLE_SECS);
        let idle: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| f.end < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        for k in idle {
            if let Some(f) = self.flows.remove(&k) {
                self.pending_flows.push(f);
            }
        }
        if self.pending_flows.len() > 200_000 {
            self.pending_flows.drain(..100_000); // store not draining; stay bounded
        }
    }

    /// Forget everything learned about the network's identity (new capture).
    pub fn reset_network_identity(&mut self) {
        self.self_macs.clear();
        self.self_ips.clear();
        self.gateway_ip = None;
        self.router_ips.clear();
        self.gateway_macs.clear();
        self.ra_routers.clear();
        self.lan_nets.clear();
        self.arp_table.clear();
    }

    /// Name learned for an address from DNS answers or TLS SNI.
    pub fn name_of(&self, ip: &IpAddr) -> Option<String> {
        self.dns.get(ip).cloned()
    }

    /// Threat-intel feed listing this address or domain, if any.
    pub fn intel_source(&self, ip: Option<&IpAddr>, domain: Option<&str>) -> Option<String> {
        ip.and_then(|i| self.intel.ip(i))
            .or_else(|| domain.and_then(|d| self.intel.domain(d)))
            .map(|h| h.source)
    }

    /// Part of this network (private range or one of its subnets).
    pub fn is_lan(&self, ip: &IpAddr) -> bool {
        is_local_ip(ip) || self.lan_nets.iter().any(|n| n.contains(ip))
    }

    fn learn_lan(&mut self, net: IpNet) {
        if !self.lan_nets.iter().any(|n| n.contains(&net.addr)) && self.lan_nets.len() < 32 {
            self.lan_nets.push(net);
        }
    }

    fn is_router_ip(&self, ip: &IpAddr) -> bool {
        self.gateway_ip.as_ref() == Some(ip) || self.router_ips.contains(ip)
    }

    fn mark_gateway(&mut self, mac: Mac) {
        if let Some(d) = self.devices.get_mut(&mac) {
            if !d.is_gateway {
                d.is_gateway = true;
                self.dirty = true;
            }
        }
    }

    /// Reset per-session counters when a new capture starts.
    pub fn begin_session(&mut self, start: Option<DateTime<Utc>>) {
        let now = start.unwrap_or_else(Utc::now);
        self.started = now;
        self.clock = now;
        self.totals = Totals::default();
        self.traffic.clear();
        self.feed.clear();
        self.arp_table.clear();
        for d in self.devices.values_mut() {
            d.live = Live::default();
        }
    }

    pub fn is_self(&self, d: &Device) -> bool {
        self.self_macs.contains(&d.mac) || d.ips.iter().any(|ip| self.self_ips.contains(ip))
    }

    pub fn clear_all(&mut self) {
        self.feed.clear();
        self.devices.clear();
        self.alerts.clear();
        self.dns.clear();
        self.arp_table.clear();
        self.traffic.clear();
        self.totals = Totals::default();
        self.dirty = true;
    }

    pub fn drain_fresh(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.fresh)
    }

    fn raise(&mut self, d: Draft) {
        let label = d
            .device
            .and_then(|m| self.devices.get(&m))
            .map(|dev| dev.label());
        let mut a = Alert {
            id: self.next_alert_id,
            ts: d.ts,
            severity: d.severity,
            rule: d.rule.into(),
            title: d.title,
            message: d.message,
            device: d.device,
            device_label: label,
            remote: d.remote,
            port: d.port,
            value: d.value,
            acknowledged: false,
            mitre_id: None,
            mitre_name: None,
            tactic: None,
            status: AlertStatus::New,
            owner: None,
            notes: vec![],
            urgency: None,
            evidence: None,
            context: None,
        };
        a.tag_attack();
        if a.rule == "ids-signature" {
            let ct = a
                .value
                .and_then(|sid| self.ids.rules.iter().find(|r| r.sid as f64 == sid))
                .and_then(|r| r.classtype.clone());
            if let Some((id, name, tactic)) = ids::classtype_attack(ct.as_deref()) {
                a.mitre_id = Some(id.into());
                a.mitre_name = Some(name.into());
                a.tactic = Some(tactic.into());
            }
        }
        a.urgency = Some(urgency(
            a.severity,
            d.device
                .and_then(|m| self.devices.get(&m))
                .map(|x| x.priority)
                .unwrap_or_default(),
        ));
        self.next_alert_id += 1;
        self.alerts.push_back(a.clone());
        while self.alerts.len() > MAX_ALERTS {
            self.alerts.pop_front();
        }
        self.fresh.push(a);
        self.dirty = true;
    }

    // -- traffic graph ------------------------------------------------------

    fn bucket(&mut self, sec: i64) -> Option<&mut TrafficPoint> {
        let last = self.traffic.back().map(|b| b.t);
        match last {
            None => self.traffic.push_back(TrafficPoint {
                t: sec,
                ..Default::default()
            }),
            Some(last) if sec > last => {
                let gap = (sec - last).min(TRAFFIC_HISTORY as i64);
                for t in (sec - gap + 1)..=sec {
                    self.traffic.push_back(TrafficPoint {
                        t,
                        ..Default::default()
                    });
                }
                while self.traffic.len() > TRAFFIC_HISTORY {
                    self.traffic.pop_front();
                }
            }
            Some(last) => {
                let back = (last - sec) as usize;
                if back >= self.traffic.len() {
                    return None;
                }
                let idx = self.traffic.len() - 1 - back;
                return self.traffic.get_mut(idx);
            }
        }
        self.traffic.back_mut()
    }

    /// Called once a second while capturing live so the graph keeps moving
    /// even when the air is quiet, and to refresh auto-classification.
    pub fn tick(&mut self, now: Option<DateTime<Utc>>) {
        if let Some(now) = now {
            if now > self.clock {
                self.clock = now;
            }
            self.bucket(now.timestamp());
        }
        self.reclassify();
        self.ticks += 1;
        if self.ticks.is_multiple_of(5) {
            self.close_idle_flows();
        }
        if self.ticks.is_multiple_of(30) {
            self.prune();
        }
        if self.ticks.is_multiple_of(60) {
            self.peer_rules();
        }
    }

    /// Peer-group analysis: a device that behaves very differently from the
    /// other devices of its type stands out even if it was already
    /// misbehaving while its own baseline was learned.
    pub fn peer_rules(&mut self) {
        if !self.rules.peer_groups {
            return;
        }
        let ts = self.clock;
        let mut groups: HashMap<String, Vec<(Mac, [usize; 2])>> = HashMap::new();
        for d in self.devices.values() {
            if !d.on_network
                || d.is_ap
                || d.is_gateway
                || self.is_self(d)
                || d.class() == "Unknown"
                || d.baseline.learning(ts)
            {
                continue;
            }
            let ext = d.destinations.values().filter(|x| x.external).count();
            groups
                .entry(d.class().to_string())
                .or_default()
                .push((d.mac, [ext, d.ports.len()]));
        }
        let mut drafts = vec![];
        for (class, members) in groups.iter().filter(|(_, m)| m.len() >= 3) {
            for (mi, metric) in ["internet hosts", "service ports"].iter().enumerate() {
                let mut vals: Vec<usize> = members.iter().map(|(_, v)| v[mi]).collect();
                vals.sort_unstable();
                let median = vals[vals.len() / 2] as f64;
                for (mac, v) in members {
                    let v = v[mi];
                    if v < 10 || (v as f64) < (median * 5.0).max(median + 10.0) {
                        continue;
                    }
                    let Some(d) = self.devices.get_mut(mac) else {
                        continue;
                    };
                    let key = format!("peer:{mi}");
                    if d.flagged.contains(&key) {
                        continue;
                    }
                    d.flagged.insert(key);
                    drafts.push(Draft {
                        severity: if d.is_iot() { Severity::High } else { Severity::Medium },
                        rule: "peer-anomaly",
                        title: format!("{}: behaves unlike other {class} devices", d.label()),
                        message: format!(
                            "Uses {v} {metric}; the other {} {class} devices use a median of {median:.0}. Devices of one type should behave alike — this one may be compromised or misconfigured.",
                            members.len() - 1
                        ),
                        device: Some(*mac),
                        remote: None,
                        port: None,
                        value: Some(v as f64),
                        ts,
                    });
                }
            }
        }
        self.raise_all(drafts);
    }

    /// Drop transient devices (passers-by probing with random MACs, one-off
    /// corrupted addresses) so long monitor-mode captures stay bounded.
    fn prune(&mut self) {
        let cutoff = self.clock - Duration::minutes(30);
        let alerted: HashSet<Mac> = self.alerts.iter().filter_map(|a| a.device).collect();
        let before = self.devices.len();
        self.devices.retain(|m, d| {
            d.on_network
                || d.tag.is_some()
                || d.name.is_some()
                || d.last_seen >= cutoff
                || d.frames.total() >= 50
                || alerted.contains(m)
        });
        if self.devices.len() > MAX_DEVICES {
            let mut by_age: Vec<(DateTime<Utc>, Mac)> = self
                .devices
                .values()
                .filter(|d| d.tag.is_none() && d.name.is_none())
                .map(|d| (d.last_seen, d.mac))
                .collect();
            by_age.sort();
            for (_, m) in by_age.into_iter().take(self.devices.len() - MAX_DEVICES) {
                self.devices.remove(&m);
            }
        }
        if self.devices.len() != before {
            self.dirty = true;
        }
    }

    /// Re-resolve vendors after the vendor database was updated.
    pub fn refresh_vendors(&mut self) {
        for d in self.devices.values_mut() {
            if let Some(v) = self.oui.lookup(&d.mac) {
                d.vendor = Some(v);
            }
        }
        self.dirty = true;
    }

    fn reclassify(&mut self) {
        for d in self.devices.values_mut() {
            if d.hostname.is_none() && self.self_macs.contains(&d.mac) {
                if let Some(h) = &self.self_hostname {
                    d.hostname = Some(h.clone());
                    d.hostnames.insert(h.clone());
                }
            }
            let domains: Vec<&str> = d
                .destinations
                .values()
                .filter_map(|x| x.domain.as_deref())
                .collect();
            let ports: Vec<u16> = d.ports.keys().copied().collect();
            let hostnames: Vec<&str> = d.hostnames.iter().map(String::as_str).collect();
            let services: Vec<&str> = d.services.iter().map(String::as_str).collect();
            let banners: Vec<&str> = d.banners.iter().map(String::as_str).collect();
            let hints = ClassHints {
                vendor: d.vendor.as_deref(),
                is_ap: d.is_ap,
                is_gateway: d.is_gateway,
                hostnames: &hostnames,
                services: &services,
                vendor_class: d.vendor_class.as_deref(),
                banners: &banners,
                randomized: d.randomized,
                domains: &domains,
                ports: &ports,
                probes_many_ssids: d.probed_ssids.len() >= 2,
                os: d.os(),
            };
            let c = classify(&hints);
            if d.auto_class != c {
                d.auto_class = c.to_string();
            }
        }
    }

    // -- main entry point ---------------------------------------------------

    pub fn process(&mut self, p: &PacketInfo) {
        let ts = p.ts;
        if ts > self.clock {
            self.clock = ts;
        }
        let len = p.len as u64;
        self.totals.packets += 1;
        self.totals.bytes += len;
        self.totals.frames.add(p.kind);
        if p.protected {
            self.totals.protected += 1;
        }
        if p.net.is_some() {
            self.totals.with_ip += 1;
        }
        if let Some(b) = self.bucket(ts.timestamp()) {
            b.packets += 1;
            b.bytes += len;
            match p.kind {
                FrameKind::Management => b.management += 1,
                FrameKind::Control => b.control += 1,
                FrameKind::Data => b.data += 1,
                FrameKind::Ethernet => b.ethernet += 1,
            }
        }

        // Learn names for IPs and the network's routers before attributing traffic.
        if let Some(n) = &p.net {
            if self.dns.len() > 50_000 {
                self.dns.clear();
            }
            for (name, ip) in &n.dns_answers {
                self.dns.insert(*ip, name.clone());
            }
            if let Some(sni) = &n.sni {
                self.dns.insert(n.dst_ip, sni.clone());
            }
            for r in n.routers.iter().filter(|r| is_local_ip(r)) {
                if self.router_ips.len() < 8 {
                    self.router_ips.insert(*r);
                }
            }
            if let Some(ra) = n.router_adv.as_ref().filter(|ra| ra.lifetime > 0) {
                for (pfx, plen) in &ra.prefixes {
                    if (16..=128).contains(plen) && !is_link_local(&IpAddr::V6(*pfx)) {
                        self.learn_lan(IpNet::new(IpAddr::V6(*pfx), *plen));
                    }
                }
            }
            // Link-scoped packets (neighbor discovery, mDNS) never leave the
            // link, so a global IPv6 source on one is a host on this network.
            if let (IpAddr::V6(s), IpAddr::V6(d)) = (n.src_ip, n.dst_ip) {
                let link_scope = is_link_local(&n.dst_ip) || (d.segments()[0] & 0xff0f) == 0xff02;
                if link_scope && (s.segments()[0] & 0xe000) == 0x2000 {
                    let base = Ipv6Addr::from(u128::from(s) & (u128::MAX << 64));
                    self.learn_lan(IpNet::new(IpAddr::V6(base), 64));
                }
            }
        }

        self.push_feed(p);
        let quiet_new = self.quiet_new_until.is_some_and(|q| ts <= q);
        let mut drafts: Vec<Draft> = Vec::new();

        // ARP: authoritative MAC <-> IP binding for LAN devices.
        if let Some(a) = &p.arp {
            if !self.devices.contains_key(&a.sender_mac) {
                let vendor = self.oui.lookup(&a.sender_mac);
                self.devices.insert(
                    a.sender_mac,
                    Device::new(a.sender_mac, ts, vendor, self.rules.learning_minutes),
                );
                self.dirty = true;
            }
            if let Some(d) = self.devices.get_mut(&a.sender_mac) {
                d.ips.insert(IpAddr::V4(a.sender_ip));
                d.touch(ts);
            }
            self.arp_rules(a.sender_mac, a.sender_ip, ts, &mut drafts);
            self.arp_table.insert(a.sender_ip, (a.sender_mac, ts));
        }

        let ap_ssid = p
            .bssid
            .and_then(|b| self.devices.get(&b))
            .and_then(|ap| ap.ssids.iter().next().cloned());
        let warmed_up = ts >= self.started + Duration::minutes(self.rules.learning_minutes as i64);
        let rules = &self.rules;
        let src = p.src.filter(Mac::is_unicast);
        let dst = p.dst.filter(|m| m.is_unicast() && Some(*m) != src);
        let on_net_frame = matches!(p.kind, FrameKind::Data | FrameKind::Ethernet);

        // ---- transmitter ----
        if let Some(mac) = src {
            if p.kind != FrameKind::Control && !self.devices.contains_key(&mac) {
                let vendor = self.oui.lookup(&mac);
                self.devices
                    .insert(mac, Device::new(mac, ts, vendor, rules.learning_minutes));
                self.dirty = true;
            }
            if let Some(d) = self.devices.get_mut(&mac) {
                d.touch(ts);
                d.tx_bytes += len;
                d.tx_packets += 1;
                d.frames.add(p.kind);
                if let Some(r) = p.rssi {
                    d.update_rssi(r);
                }
                if p.channel.is_some() {
                    d.channel = p.channel;
                }
                match p.subtype {
                    "beacon" | "probe-resp" => {
                        d.is_ap = true;
                        if let Some(s) = &p.ssid {
                            d.ssids.insert(s.clone());
                        }
                    }
                    "probe-req" => {
                        if let Some(s) = &p.ssid {
                            d.probed_ssids.insert(s.clone());
                        }
                    }
                    "assoc-req" | "reassoc-req" => {
                        if let Some(b) = p.bssid.filter(|b| *b != mac) {
                            d.record_connection(b, p.ssid.clone().or(ap_ssid.clone()), ts);
                        }
                    }
                    "deauth" | "disassoc" => deauth_rule(d, ts, rules, &mut drafts),
                    _ => {}
                }
                if p.kind == FrameKind::Data && p.to_ds {
                    if let Some(b) = p.bssid.filter(|b| *b != mac) {
                        d.record_connection(b, ap_ssid.clone(), ts);
                    }
                }
                if let Some(n) = &p.net {
                    for h in &n.hints {
                        if let Hint::DhcpParams(v) = h {
                            identity_rule(d, v, ts, rules, &mut drafts);
                        }
                        d.apply_hint(h);
                    }
                }
                if d.probed_ssids.len() > MAX_LIST {
                    if let Some(first) = d.probed_ssids.iter().next().cloned() {
                        d.probed_ssids.remove(&first);
                    }
                }
                if on_net_frame && !d.on_network {
                    d.on_network = true;
                    if rules.new_device && warmed_up && !quiet_new && !d.is_ap {
                        drafts.push(Draft {
                            severity: if d.randomized {
                                Severity::Info
                            } else {
                                Severity::Low
                            },
                            rule: "new-device",
                            title: "New device joined the network".into(),
                            message: format!(
                                "{}{} ({}) started sending traffic{}.",
                                mac,
                                d.hostname
                                    .as_ref()
                                    .map(|h| format!(" \"{h}\""))
                                    .unwrap_or_default(),
                                d.vendor.as_deref().unwrap_or(if d.randomized {
                                    "randomized MAC"
                                } else {
                                    "unknown vendor"
                                }),
                                ap_ssid
                                    .as_ref()
                                    .map(|s| format!(" on \"{s}\""))
                                    .unwrap_or_default()
                            ),
                            device: Some(mac),
                            remote: None,
                            port: None,
                            value: None,
                            ts,
                        });
                    }
                }
                d.add_history(ts, len);
            }
        }

        // ---- receiver ----
        if let Some(mac) = dst {
            if p.kind != FrameKind::Control && !self.devices.contains_key(&mac) {
                let vendor = self.oui.lookup(&mac);
                self.devices
                    .insert(mac, Device::new(mac, ts, vendor, rules.learning_minutes));
                self.dirty = true;
            }
            if let Some(d) = self.devices.get_mut(&mac) {
                d.rx_bytes += len;
                d.rx_packets += 1;
                if p.kind != FrameKind::Control {
                    d.touch(ts);
                }
                if p.kind == FrameKind::Data && p.from_ds {
                    if let Some(b) = p.bssid.filter(|b| *b != mac) {
                        d.record_connection(b, ap_ssid.clone(), ts);
                    }
                }
                d.add_history(ts, len);
            }
        }

        // ---- rate rules for both endpoints ----
        // Only connection attempts that originate on this network count for the
        // sender: inbound SYNs relayed by the router are not the router's doing.
        let local_syn = p
            .net
            .as_ref()
            .is_some_and(|n| n.tcp_syn && self.is_lan(&n.src_ip));
        for mac in [src, dst].into_iter().flatten() {
            if let Some(d) = self.devices.get_mut(&mac) {
                let syn = local_syn && Some(mac) == src;
                rate_rules(d, ts, len, syn, &self.rules, &mut drafts);
            }
        }

        // ---- routers ----
        if let (Some(mac), Some(ra)) = (src, p.net.as_ref().and_then(|n| n.router_adv.as_ref())) {
            if ra.lifetime > 0 {
                self.router_advert(mac, ts, &mut drafts);
            }
        }
        if let Some(n) = &p.net {
            // Frames to/from a known router address carry the router's MAC.
            for (ip, mac) in [(n.src_ip, src), (n.dst_ip, dst)] {
                if let Some(m) = mac.filter(|_| self.is_router_ip(&ip)) {
                    if self.gateway_macs.is_empty() {
                        self.gateway_macs.insert(m);
                    }
                    if self.gateway_macs.contains(&m) {
                        self.mark_gateway(m);
                    }
                }
            }
        }

        // ---- network layer: who is talking to whom ----
        if let Some(n) = &p.net {
            let (sl, dl) = (self.is_lan(&n.src_ip), self.is_lan(&n.dst_ip));
            let unicast = |ip: &IpAddr| match ip {
                IpAddr::V4(v4) => {
                    !(v4.is_multicast()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.octets()[3] == 255)
                }
                IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
            };

            // Router heuristic: the L2 peer of unicast traffic between a LAN
            // host and many different internet hosts is relaying it. Only used
            // until the router's identity is known some other way.
            let lan_side = if sl { &n.src_ip } else { &n.dst_ip };
            if sl != dl && unicast(&n.src_ip) && unicast(&n.dst_ip) && !is_link_local(lan_side) {
                let (peer, remote) = if sl { (dst, n.dst_ip) } else { (src, n.src_ip) };
                let known = !self.gateway_macs.is_empty();
                if let Some(g) = peer.and_then(|m| self.devices.get_mut(&m)) {
                    if !g.is_gateway && g.live.forwarded.len() < FORWARD_MIN {
                        g.live.forwarded.insert(remote);
                        if g.live.forwarded.len() >= FORWARD_MIN && !known {
                            g.is_gateway = true;
                            self.dirty = true;
                        }
                    }
                }
            }

            // DNS log: the asker is the receiver of the response.
            if n.dns_response && n.src_port == Some(53) {
                if let (Some(q), Some(m)) = (&n.dns_query, dst) {
                    if self.pending_dns.len() < 200_000 {
                        self.pending_dns.push(DnsRecord {
                            ts,
                            mac: m,
                            query: q.clone(),
                            answers: n.dns_answers.iter().map(|(_, ip)| ip.to_string()).collect(),
                            rcode: n.dns_rcode,
                            resolver: n.src_ip,
                        });
                    }
                }
            }

            // Signatures.
            if self.rules.ids && !self.ids.is_empty() && !n.payload.is_empty() {
                let proto = match n.transport {
                    Transport::Tcp => ids::Proto::Tcp,
                    Transport::Udp => ids::Proto::Udp,
                    Transport::Icmp => ids::Proto::Icmp,
                    Transport::Other => ids::Proto::Any,
                };
                let pkt = ids::Packet {
                    proto,
                    src: n.src_ip,
                    dst: n.dst_ip,
                    sport: n.src_port.unwrap_or(0),
                    dport: n.dst_port.unwrap_or(0),
                    src_home: sl,
                    dst_home: dl,
                    payload: &n.payload,
                };
                let ruleset = self.ids.clone();
                // Blame the local endpoint: the sender if it's ours, else the target.
                let who = if sl { src } else { dst };
                for r in ruleset.matches(&pkt).into_iter().take(3) {
                    if let Some(d) = who.and_then(|m| self.devices.get_mut(&m)) {
                        ids_rule(d, r, &pkt, ts, &mut drafts);
                    }
                }
            }

            let attribution = match (sl, dl) {
                (true, false) => Some((src, n.src_ip, n.dst_ip, true)),
                (false, true) => Some((dst, n.dst_ip, n.src_ip, false)),
                (true, true) => Some((src, n.src_ip, n.dst_ip, true)),
                (false, false) => None,
            };
            if let Some((Some(mac), local_ip, remote, outbound)) = attribution {
                let external = !self.is_lan(&remote);
                let domain = self.dns.get(&remote).cloned();
                // Names this device looked up or connected to by name.
                let mut names: Vec<&str> = Vec::new();
                if outbound {
                    if let Some(q) = n.dns_query.as_deref().filter(|_| n.dst_port == Some(53)) {
                        names.push(q);
                    }
                    if let Some(s) = n.sni.as_deref() {
                        names.push(s);
                    }
                }
                let mut hits: Vec<(Hit, String)> = Vec::new();
                let mut suspicious: Vec<String> = Vec::new();
                if self.rules.threat_intel && !self.intel.is_empty() {
                    if let Some(hit) = self.intel.ip(&remote).filter(|_| unicast(&remote)) {
                        hits.push((hit, remote.to_string()));
                    }
                    for h in names.iter().copied().chain(domain.as_deref()) {
                        if let Some(hit) = self.intel.domain(h) {
                            hits.push((hit, h.to_string()));
                        }
                    }
                }
                if self.rules.suspicious_domains {
                    suspicious.extend(
                        names
                            .iter()
                            .filter(|h| looks_generated(h))
                            .map(|h| h.to_string()),
                    );
                }
                let rules = &self.rules;
                if let Some(d) = self.devices.get_mut(&mac) {
                    if unicast(&local_ip) && d.ips.len() < MAX_LIST {
                        d.ips.insert(local_ip);
                    }
                    indicator_rules(d, &hits, &suspicious, ts, rules, &mut drafts);
                    if outbound {
                        if let Some(t) = &n.tls {
                            tls_rule(d, t, ts, rules, &mut drafts);
                        }
                        if n.dst_port == Some(53) && d.resolvers.len() < 16 && unicast(&remote) {
                            d.resolvers.insert(remote);
                        }
                    }
                    if unicast(&remote) {
                        let (lp, rp) = if outbound {
                            (n.src_port, n.dst_port)
                        } else {
                            (n.dst_port, n.src_port)
                        };
                        let syn_out = outbound && n.tcp_syn;
                        // The remote port is a "service" when this device is the client.
                        // Only claim a service when it's certain: we saw the TCP SYN, or the
                        // remote port is well-known (< 1024) / a registered UDP service and
                        // ours is ephemeral. Guessing from "lower port wins" mislabels
                        // peer-to-peer and link-local traffic.
                        let service = match (n.transport, lp, rp) {
                            (Transport::Tcp, _, Some(r)) if syn_out => Some(r),
                            (Transport::Tcp, Some(l), Some(r))
                                if r < 1024 && l >= 1024 && !n.tcp_syn =>
                            {
                                Some(r)
                            }
                            (Transport::Udp, Some(l), Some(r))
                                if l >= 1024 && (r < 1024 || UDP_SERVICES.contains(&r)) =>
                            {
                                Some(r)
                            }
                            _ => None,
                        };
                        // ...and its own port is one it serves when it answers from a low port.
                        if outbound && !n.tcp_syn {
                            if let (Some(l), Some(r)) = (lp, rp) {
                                if l < r
                                    && r >= 1024
                                    && (l < 1024
                                        || matches!(
                                            l,
                                            1883 | 2323 | 5555 | 8080 | 8443 | 8554 | 8883
                                        ))
                                    && d.server_ports.len() < 64
                                {
                                    *d.server_ports.entry(l).or_default() += 1;
                                    if let Some(p) = insecure_protocol(l, &n.payload) {
                                        d.insecure.insert(p.into());
                                    }
                                }
                            }
                        }
                        if let Some(p) = service.and_then(|s| insecure_protocol(s, &n.payload)) {
                            d.insecure.insert(p.into());
                        }
                        // Connection log.
                        let proto = match n.transport {
                            Transport::Tcp => 6,
                            Transport::Udp => 17,
                            Transport::Icmp => 1,
                            Transport::Other => 0,
                        };
                        let key = FlowKey(mac, local_ip, lp, remote, rp, proto);
                        if let Some(f) = self.flows.get_mut(&key) {
                            f.end = ts.max(f.end);
                            f.packets += 1;
                            if outbound {
                                f.bytes_out += len;
                            } else {
                                f.bytes_in += len;
                            }
                            if f.domain.is_none() {
                                f.domain = domain.clone();
                            }
                        } else {
                            if self.flows.len() >= MAX_FLOWS {
                                if let Some(old) = self
                                    .flows
                                    .iter()
                                    .min_by_key(|(_, f)| f.end)
                                    .map(|(k, _)| k.clone())
                                {
                                    if let Some(f) = self.flows.remove(&old) {
                                        self.pending_flows.push(f);
                                    }
                                }
                            }
                            self.flows.insert(
                                key,
                                Flow {
                                    start: ts,
                                    end: ts,
                                    mac,
                                    local_ip,
                                    local_port: lp,
                                    remote_ip: remote,
                                    remote_port: rp,
                                    proto: match proto {
                                        6 => "tcp",
                                        17 => "udp",
                                        1 => "icmp",
                                        _ => "ip",
                                    }
                                    .into(),
                                    service,
                                    domain: domain.clone(),
                                    bytes_out: if outbound { len } else { 0 },
                                    bytes_in: if outbound { 0 } else { len },
                                    packets: 1,
                                    external,
                                    outbound,
                                },
                            );
                        }
                        net_rules(
                            d,
                            NetEvent {
                                remote,
                                domain,
                                service,
                                outbound,
                                external,
                                bytes: len,
                                ts,
                            },
                            rules,
                            &mut drafts,
                        );
                    }
                }
            }
        }

        let ctx = (!drafts.is_empty()).then(|| self.packet_context(p));
        self.raise_all_with(drafts, ctx);
    }

    /// Describe the triggering packet for the alert's "what happened" view.
    fn packet_context(&self, p: &PacketInfo) -> AlertContext {
        let (protocol, summary) = describe(p, &self.dns);
        let n = p.net.as_ref();
        let printable = |b: &[u8]| -> String {
            b.iter()
                .take(320)
                .map(|c| {
                    if (0x20..0x7f).contains(c) || *c == b'\n' {
                        *c as char
                    } else {
                        '.'
                    }
                })
                .collect()
        };
        let direction = match n.map(|n| (self.is_lan(&n.src_ip), self.is_lan(&n.dst_ip))) {
            Some((true, false)) => "outbound",
            Some((false, true)) => "inbound",
            _ => "local",
        };
        let server_port = n.and_then(|n| match (n.src_port, n.dst_port) {
            (Some(s), Some(d)) => Some(if n.tcp_syn || d < s { d } else { s }),
            (s, d) => d.or(s),
        });
        AlertContext {
            protocol,
            summary,
            transport: n.map(|n| format!("{:?}", n.transport).to_uppercase()),
            src_mac: p.src,
            dst_mac: p.dst,
            src_ip: n
                .map(|n| n.src_ip.to_string())
                .or_else(|| p.arp.as_ref().map(|a| a.sender_ip.to_string())),
            dst_ip: n
                .map(|n| n.dst_ip.to_string())
                .or_else(|| p.arp.as_ref().map(|a| a.target_ip.to_string())),
            src_port: n.and_then(|n| n.src_port),
            dst_port: n.and_then(|n| n.dst_port),
            service: server_port
                .map(service_name)
                .filter(|s| *s != "unknown service")
                .map(str::to_string),
            domain: n.and_then(|n| {
                n.sni
                    .clone()
                    .or_else(|| n.dns_query.clone())
                    .or_else(|| self.dns.get(&n.dst_ip).cloned())
                    .or_else(|| self.dns.get(&n.src_ip).cloned())
            }),
            direction: direction.into(),
            frame_len: p.len,
            payload: n
                .filter(|n| !n.payload.is_empty() && n.tls.is_none())
                .map(|n| printable(&n.payload)),
            payload_hex: n.filter(|n| !n.payload.is_empty()).map(|n| {
                n.payload
                    .iter()
                    .take(48)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            aggregate: false,
        }
    }

    fn raise_all(&mut self, drafts: Vec<Draft>) {
        self.raise_all_with(drafts, None);
    }

    /// Raise drafts, then correlate: devices whose risk crosses the threshold
    /// from several different detections get one higher-fidelity alert
    /// (Splunk ES risk-based alerting).
    fn raise_all_with(&mut self, drafts: Vec<Draft>, ctx: Option<AlertContext>) {
        if drafts.is_empty() {
            return;
        }
        let touched: BTreeSet<Mac> = drafts.iter().filter_map(|d| d.device).collect();
        for d in drafts {
            let aggregate = matches!(
                d.rule,
                "volume-spike" | "connection-burst" | "unusual-time" | "deauth-flood"
            );
            self.raise(d);
            if let (Some(c), Some(a)) = (&ctx, self.alerts.back_mut()) {
                let mut c = c.clone();
                c.aggregate = aggregate;
                a.context = Some(c.clone());
                if let Some(f) = self.fresh.last_mut() {
                    f.context = Some(c);
                }
            }
        }
        let threshold = self.rules.risk_threshold;
        if threshold == 0 {
            return;
        }
        let risk = self.risk_map();
        for mac in touched {
            let Some((score, rules)) = risk.get(&mac) else {
                continue;
            };
            let ts = self.clock;
            let Some(d) = self.devices.get_mut(&mac) else {
                continue;
            };
            let distinct: Vec<&str> = rules
                .iter()
                .map(String::as_str)
                .filter(|r| *r != "risk-threshold")
                .collect();
            if *score >= threshold
                && distinct.len() >= 2
                && ts.timestamp() - d.live.risk_alerted >= RISK_ALERT_COOLDOWN
            {
                d.live.risk_alerted = ts.timestamp();
                let label = d.label();
                self.raise(Draft {
                    severity: Severity::Critical,
                    rule: "risk-threshold",
                    title: format!("{label}: risk threshold exceeded"),
                    message: format!(
                        "Risk score {score}/100 from {} different detections ({}). Correlated activity like this usually means the device is compromised — isolate it and investigate.",
                        distinct.len(),
                        distinct.join(", ")
                    ),
                    device: Some(mac),
                    remote: None,
                    port: None,
                    value: Some(*score as f64),
                    ts,
                });
            }
        }
    }

    /// Per-device risk score (0-100) and the rules contributing to it.
    pub fn risk_map(&self) -> HashMap<Mac, (u32, BTreeSet<String>)> {
        let mut acc: HashMap<Mac, (f64, BTreeSet<String>)> = HashMap::new();
        for a in self.alerts.iter().filter(|a| !a.acknowledged) {
            let Some(mac) = a.device else { continue };
            let age_h = (self.clock - a.ts).num_seconds().max(0) as f64 / 3600.0;
            let pts = severity_points(a.severity) * 0.5f64.powf(age_h / RISK_HALF_LIFE_H);
            if pts < 0.5 {
                continue;
            }
            let e = acc.entry(mac).or_default();
            e.0 += pts;
            e.1.insert(a.rule.clone());
        }
        // Known weaknesses add risk too (Armis-style "vulnerable" factor).
        for d in self.devices.values() {
            let pts: f64 = crate::exposure::assess(d, &self.kev)
                .iter()
                .map(|f| f.risk_points())
                .sum::<f64>()
                .min(30.0);
            if pts > 0.0 {
                acc.entry(d.mac).or_default().0 += pts;
            }
        }
        acc.into_iter()
            .map(|(mac, (pts, rules))| {
                let d = self.devices.get(&mac);
                let factor = if d.is_some_and(|d| d.is_iot()) {
                    1.25
                } else {
                    1.0
                } * d.map(|d| d.priority.risk_factor()).unwrap_or(1.0);
                let score = (pts * factor).round().min(100.0) as u32;
                (mac, (score, rules))
            })
            .collect()
    }

    /// What a device's risk score is made of: decayed alert points per rule
    /// and exposure points, scaled like `risk_map`.
    pub fn risk_breakdown(&self, mac: &Mac) -> Vec<RiskPart> {
        let Some(d) = self.devices.get(mac) else {
            return vec![];
        };
        let factor = if d.is_iot() { 1.25 } else { 1.0 } * d.priority.risk_factor();
        let mut parts: BTreeMap<String, (f64, usize, Severity)> = BTreeMap::new();
        for a in self
            .alerts
            .iter()
            .filter(|a| !a.acknowledged && a.device == Some(*mac))
        {
            let age_h = (self.clock - a.ts).num_seconds().max(0) as f64 / 3600.0;
            let pts = severity_points(a.severity) * 0.5f64.powf(age_h / RISK_HALF_LIFE_H);
            if pts < 0.5 {
                continue;
            }
            let e = parts.entry(a.rule.clone()).or_insert((0.0, 0, a.severity));
            e.0 += pts * factor;
            e.1 += 1;
            e.2 = e.2.max(a.severity);
        }
        let mut out: Vec<RiskPart> = parts
            .into_iter()
            .map(|(rule, (points, count, worst))| RiskPart {
                source: rule,
                kind: "alert",
                points,
                count,
                severity: worst,
            })
            .collect();
        let mut exp = 0.0;
        for f in crate::exposure::assess(d, &self.kev) {
            let pts = f.risk_points();
            if pts > 0.0 && exp < 30.0 {
                let p = pts.min(30.0 - exp);
                exp += p;
                out.push(RiskPart {
                    source: f.title.clone(),
                    kind: "exposure",
                    points: p * factor,
                    count: 1,
                    severity: f.severity,
                });
            }
        }
        out.sort_by(|a, b| b.points.total_cmp(&a.points));
        out
    }

    /// ARP sender bindings: learn the router, catch anyone impersonating it,
    /// and flag two live devices fighting over one address.
    fn arp_rules(&mut self, mac: Mac, ip: Ipv4Addr, ts: DateTime<Utc>, out: &mut Vec<Draft>) {
        let addr = IpAddr::V4(ip);
        let sec = ts.timestamp();
        if self.is_router_ip(&addr) {
            if self.gateway_macs.is_empty() {
                self.gateway_macs.insert(mac);
            }
            if self.gateway_macs.contains(&mac) {
                self.mark_gateway(mac);
                return;
            }
            let known: Vec<String> = self.gateway_macs.iter().map(Mac::to_string).collect();
            let spoofing = self.rules.spoofing;
            let Some(d) = self.devices.get_mut(&mac) else {
                return;
            };
            if spoofing && sec - d.live.spoof_alerted >= SPOOF_ALERT_COOLDOWN {
                d.live.spoof_alerted = sec;
                out.push(Draft {
                    severity: Severity::Critical,
                    rule: "arp-spoof",
                    title: format!("{} is impersonating the router", d.label()),
                    message: format!(
                        "{mac} ({}) answered ARP for the gateway {ip}, which belongs to {}. This is how man-in-the-middle tools (arpspoof, Ettercap, Bettercap) intercept a whole network's traffic.",
                        d.vendor.as_deref().unwrap_or(if d.randomized { "randomized MAC" } else { "unknown vendor" }),
                        known.join(", ")
                    ),
                    device: Some(mac),
                    remote: Some(addr.to_string()),
                    port: None,
                    value: None,
                    ts,
                });
            }
            return;
        }
        let Some(&(old, seen)) = self.arp_table.get(&ip) else {
            return;
        };
        if old == mac || ts - seen > Duration::seconds(60) || !self.rules.spoofing {
            return;
        }
        // Proxy-ARP (enterprise Wi-Fi controllers) answers for many hosts.
        let proxy = |m: &Mac| {
            self.devices
                .get(m)
                .is_some_and(|d| d.ips.iter().filter(|i| i.is_ipv4()).count() > 2)
        };
        if proxy(&mac) || proxy(&old) || !self.devices.contains_key(&old) {
            return;
        }
        let Some(d) = self.devices.get_mut(&mac) else {
            return;
        };
        if sec - d.live.spoof_alerted >= SPOOF_ALERT_COOLDOWN {
            d.live.spoof_alerted = sec;
            out.push(Draft {
                severity: Severity::Medium,
                rule: "ip-conflict",
                title: format!("{}: IP address conflict on {ip}", d.label()),
                message: format!(
                    "{mac} claimed {ip} while {old} was using it {} s earlier. Either a misconfigured static address or ARP cache poisoning.",
                    (ts - seen).num_seconds()
                ),
                device: Some(mac),
                remote: Some(addr.to_string()),
                port: None,
                value: None,
                ts,
            });
        }
    }

    /// An IPv6 router advertisement with a non-zero lifetime.
    fn router_advert(&mut self, mac: Mac, ts: DateTime<Utc>, out: &mut Vec<Draft>) {
        let legit = self.ra_routers.is_empty()
            || self.ra_routers.contains(&mac)
            || self.gateway_macs.contains(&mac);
        if legit {
            self.ra_routers.insert(mac);
            if self.gateway_macs.is_empty() || self.gateway_macs.contains(&mac) {
                self.mark_gateway(mac);
            }
            return;
        }
        let known: Vec<String> = self.ra_routers.iter().map(Mac::to_string).collect();
        let spoofing = self.rules.spoofing;
        let Some(d) = self.devices.get_mut(&mac) else {
            return;
        };
        let sec = ts.timestamp();
        if spoofing && sec - d.live.spoof_alerted >= SPOOF_ALERT_COOLDOWN {
            d.live.spoof_alerted = sec;
            out.push(Draft {
                severity: Severity::High,
                rule: "rogue-router",
                title: format!("Rogue IPv6 router: {}", d.label()),
                message: format!(
                    "{mac} is advertising itself as an IPv6 default router; the network's router is {}. Rogue router advertisements (e.g. mitm6) redirect IPv6 traffic through an attacker.",
                    known.join(", ")
                ),
                device: Some(mac),
                remote: None,
                port: None,
                value: None,
                ts,
            });
        }
    }

    // -- views & user actions ----------------------------------------------

    pub fn summaries(&self) -> Vec<DeviceSummary> {
        let open: HashMap<Mac, usize> = self
            .alerts
            .iter()
            .filter(|a| !a.acknowledged)
            .filter_map(|a| a.device)
            .fold(HashMap::new(), |mut m, mac| {
                *m.entry(mac).or_default() += 1;
                m
            });
        let now_sec = self.clock.timestamp();
        let risk = self.risk_map();
        let findings: HashMap<Mac, Vec<crate::exposure::Finding>> = self
            .devices
            .values()
            .map(|d| (d.mac, crate::exposure::assess(d, &self.kev)))
            .collect();
        let mut v: Vec<DeviceSummary> = self
            .devices
            .values()
            .map(|d| DeviceSummary {
                mac: d.mac,
                label: d.label(),
                vendor: d.vendor.clone(),
                name: d.name.clone(),
                tag: d.tag.clone(),
                auto_class: d.auto_class.clone(),
                class: d.class().to_string(),
                is_iot: d.is_iot(),
                randomized: d.randomized,
                is_ap: d.is_ap,
                rssi: d.rssi,
                rssi_avg: d.rssi_avg,
                channel: d.channel,
                first_seen: d.first_seen,
                last_seen: d.last_seen,
                frames: d.frames.total(),
                tx_bytes: d.tx_bytes,
                rx_bytes: d.rx_bytes,
                ssid: if d.is_ap {
                    d.ssids.iter().next().cloned()
                } else {
                    d.current_ssid()
                },
                ips: d.ips.iter().copied().collect(),
                destinations: d.destinations.len(),
                learning: d.baseline.learning(self.clock),
                open_alerts: open.get(&d.mac).copied().unwrap_or(0),
                recent_bytes: d
                    .live
                    .history
                    .iter()
                    .filter(|(t, _)| *t > now_sec - WINDOW_SECS)
                    .map(|(_, b)| b)
                    .sum(),
                hostname: d.hostname.clone(),
                is_gateway: d.is_gateway,
                is_self: self.is_self(d),
                services: d.services.len(),
                risk: risk.get(&d.mac).map(|r| r.0).unwrap_or(0),
                priority: d.priority,
                os: d.os().map(str::to_string),
                findings: findings.get(&d.mac).map(|f| f.len()).unwrap_or(0),
                exposure: findings
                    .get(&d.mac)
                    .and_then(|f| f.iter().map(|x| x.severity).max()),
            })
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        v
    }

    pub fn detail(&self, mac: &Mac) -> Option<DeviceDetail> {
        let d = self.devices.get(mac)?;
        let b = &d.baseline;
        let total = (b.learning_until - b.learning_started)
            .num_milliseconds()
            .max(1) as f64;
        let done = (self.clock - b.learning_started).num_milliseconds() as f64;
        Some(DeviceDetail {
            label: d.label(),
            class: d.class().to_string(),
            is_iot: d.is_iot(),
            learning: b.learning(self.clock),
            learning_progress: (done / total).clamp(0.0, 1.0),
            history: d.live.history.iter().copied().collect(),
            alerts: self
                .alerts
                .iter()
                .rev()
                .filter(|a| a.device == Some(*mac))
                .take(100)
                .map(|a| self.view(a))
                .collect(),
            is_self: self.is_self(d),
            risk: self.risk_map().get(mac).map(|r| r.0).unwrap_or(0),
            os: d.os().map(str::to_string),
            findings: crate::exposure::assess(d, &self.kev),
            risk_parts: self.risk_breakdown(mac),
            device: d.clone(),
        })
    }

    pub fn update_device(
        &mut self,
        mac: &Mac,
        name: Option<String>,
        tag: Option<String>,
        notes: Option<String>,
        priority: Option<Priority>,
    ) -> bool {
        let Some(d) = self.devices.get_mut(mac) else {
            return false;
        };
        if let Some(p) = priority {
            d.priority = p;
        }
        if let Some(n) = name {
            d.name = Some(n).filter(|s| !s.trim().is_empty());
        }
        if let Some(t) = tag {
            d.tag = Some(t).filter(|s| !s.trim().is_empty());
        }
        if let Some(n) = notes {
            d.notes = n;
        }
        self.dirty = true;
        true
    }

    pub fn relearn(&mut self, mac: &Mac) -> bool {
        let minutes = self.rules.learning_minutes;
        let now = self.clock;
        let Some(d) = self.devices.get_mut(mac) else {
            return false;
        };
        d.baseline = Baseline::new(now, minutes);
        d.alerted_ports.clear();
        d.flagged.retain(|k| {
            !k.starts_with("ja4:") && !k.starts_with("peer:") && !k.starts_with("dhcp:")
        });
        for dest in d.destinations.values_mut() {
            dest.in_baseline = false;
            dest.alerted = false;
        }
        self.dirty = true;
        true
    }

    pub fn forget(&mut self, mac: &Mac) -> bool {
        self.dirty = true;
        self.devices.remove(mac).is_some()
    }

    pub fn acknowledge(&mut self, id: Option<u64>) {
        let ts = self.clock;
        for a in self.alerts.iter_mut().filter(|a| !a.acknowledged) {
            if id.is_none_or(|i| i == a.id) {
                set_status(a, AlertStatus::Resolved, ts);
            }
        }
        self.dirty = true;
    }

    /// Incident review: change status / owner and append a note on many alerts.
    pub fn update_alerts(
        &mut self,
        ids: &[u64],
        status: Option<AlertStatus>,
        owner: Option<String>,
        note: Option<String>,
    ) -> usize {
        let ts = Utc::now();
        let mut n = 0;
        for a in self.alerts.iter_mut().filter(|a| ids.contains(&a.id)) {
            if let Some(s) = status {
                set_status(a, s, ts);
            }
            if let Some(o) = &owner {
                let o = o.trim();
                a.owner = (!o.is_empty()).then(|| o.to_string());
            }
            if let Some(t) = note.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                if a.notes.len() < 200 {
                    a.notes.push(Note {
                        ts,
                        text: t.chars().take(2000).collect(),
                    });
                }
            }
            n += 1;
        }
        self.dirty = true;
        n
    }

    pub fn set_evidence(&mut self, id: u64, path: String) {
        if let Some(a) = self.alerts.iter_mut().find(|a| a.id == id) {
            a.evidence = Some(path);
            self.dirty = true;
        }
    }

    /// Alert as shown to the UI: urgency reflects the device's current priority.
    pub fn view(&self, a: &Alert) -> Alert {
        let mut a = a.clone();
        let p = a
            .device
            .and_then(|m| self.devices.get(&m))
            .map(|d| d.priority)
            .unwrap_or_default();
        a.urgency = Some(urgency(a.severity, p));
        a
    }

    /// Raise an alert from a user-defined detection (a saved search that
    /// matched). Throttled per detection and device.
    pub fn raise_detection(
        &mut self,
        name: &str,
        severity: Severity,
        message: &str,
        devices: &[Mac],
        throttle_minutes: u32,
    ) -> usize {
        let ts = self.clock.max(Utc::now());
        let title = format!("Detection: {}", name.trim());
        let since = ts - Duration::minutes(throttle_minutes.max(1) as i64);
        let targets: Vec<Option<Mac>> = if devices.is_empty() {
            vec![None]
        } else {
            devices.iter().take(50).copied().map(Some).collect()
        };
        let mut raised = 0;
        for dev in targets {
            let recent = self
                .alerts
                .iter()
                .rev()
                .take_while(|a| a.ts >= since)
                .any(|a| a.rule == "custom-detection" && a.title == title && a.device == dev);
            if recent || dev.is_some_and(|m| !self.devices.contains_key(&m)) {
                continue;
            }
            self.raise(Draft {
                severity,
                rule: "custom-detection",
                title: title.clone(),
                message: message.chars().take(1000).collect(),
                device: dev,
                remote: None,
                port: None,
                value: None,
                ts,
            });
            raised += 1;
        }
        raised
    }

    /// "Mark as normal": fold the alert's subject into the device baseline.
    pub fn accept(&mut self, id: u64) -> Result<(), String> {
        let ts = self.clock;
        let a = self
            .alerts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or("alert not found")?;
        set_status(a, AlertStatus::FalsePositive, ts);
        a.notes.push(Note {
            ts,
            text: "Marked as normal — folded into the device baseline.".into(),
        });
        let (mac, remote, port, value, ts, rule) = (
            a.device,
            a.remote.clone(),
            a.port,
            a.value,
            a.ts,
            a.rule.clone(),
        );
        self.dirty = true;
        let Some(d) = mac.and_then(|m| self.devices.get_mut(&m)) else {
            return Ok(());
        };
        if let Some(ip) = remote.as_deref().and_then(|r| r.parse::<IpAddr>().ok()) {
            d.baseline.destinations.insert(ip);
            if let Some(dest) = d.destinations.get_mut(&ip.to_string()) {
                dest.in_baseline = true;
                if let Some(dom) = &dest.domain {
                    d.baseline.domains.insert(base_domain(dom));
                }
            }
        }
        if let Some(p) = port {
            d.baseline.ports.insert(p);
        }
        match rule.as_str() {
            "volume-spike" => {
                if let Some(v) = value {
                    d.baseline.peak_window_bytes = d.baseline.peak_window_bytes.max(v as u64);
                }
            }
            "unusual-time" => d.baseline.hours[ts.with_timezone(&Local).hour() as usize] = true,
            "suspicious-domain" => {
                if let Some(host) = remote.as_deref() {
                    d.baseline.domains.insert(base_domain(host));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn push_feed(&mut self, p: &PacketInfo) {
        let (protocol, info) = describe(p, &self.dns);
        self.feed_seq += 1;
        let seq = self.feed_seq;
        self.feed.push_back(FeedItem {
            seq,
            ts: p.ts,
            kind: p.kind,
            protocol,
            src: p.src,
            dst: p.dst,
            rssi: p.rssi,
            channel: p.channel,
            len: p.len,
            info,
        });
        while self.feed.len() > FEED_LEN {
            self.feed.pop_front();
        }
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
        self.dirty = true;
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

struct NetEvent {
    remote: IpAddr,
    domain: Option<String>,
    service: Option<u16>,
    outbound: bool,
    /// Outside this network (not a LAN peer).
    external: bool,
    bytes: u64,
    ts: DateTime<Utc>,
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| *c as f64 / n)
        .map(|p| -p * p.log2())
        .sum()
}

/// Registered names that look random but are core infrastructure.
const NOT_DGA: &[&str] = &["3gppnetwork.org"];

/// Heuristic for algorithmically generated (DGA) domains: the registrable
/// label is long, close to maximally random for its length, and doesn't read
/// like words. CDNs randomize subdomains, not the registered name, so only
/// that label is scored.
pub fn looks_generated(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.ends_with(".local") || host.ends_with(".arpa") || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let base = base_domain(&host);
    if NOT_DGA.contains(&base.as_str()) {
        return false;
    }
    let Some(label) = base.split('.').next() else {
        return false;
    };
    if label.len() < 10
        || label.starts_with("xn--")
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    let n = label.len() as f64;
    let digits = label.bytes().filter(u8::is_ascii_digit).count() as f64 / n;
    let vowels = label.bytes().filter(|b| b"aeiouy".contains(b)).count() as f64 / n;
    // Random strings interleave digits and letters; real names cluster them ("123formbuilder").
    let switches = label
        .as_bytes()
        .windows(2)
        .filter(|w| w[0].is_ascii_digit() != w[1].is_ascii_digit())
        .count();
    let mut run = 0;
    let mut max_run = 0;
    for b in label.bytes() {
        if b.is_ascii_alphabetic() && !b"aeiouy".contains(&b) {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    // Entropy can't exceed log2(length), so compare against that ceiling.
    let randomness = entropy(label) / (label.len().min(36) as f64).log2();
    // Words need vowels; random strings have few, plus scattered digits or long consonant runs.
    randomness >= 0.85
        && ((digits >= 0.15 && switches >= 3 && vowels < 0.35)
            || (vowels < 0.25 && (max_run >= 6 || vowels < 0.1)))
}

/// Watchlist matches and generated-looking domains for one device.
fn indicator_rules(
    d: &mut Device,
    hits: &[(Hit, String)],
    suspicious: &[String],
    ts: DateTime<Utc>,
    rules: &RuleSettings,
    out: &mut Vec<Draft>,
) {
    let iot = d.is_iot();
    for (hit, observed) in hits {
        let key = format!("ioc:{}", hit.indicator);
        if d.flagged.contains(&key) || d.flagged.len() >= 512 {
            continue;
        }
        d.flagged.insert(key);
        // Feed severity, raised one step for IoT devices (they have no reason to go there).
        let severity = if iot {
            urgency(hit.severity, Priority::High)
        } else {
            hit.severity
        };
        out.push(Draft {
            severity,
            rule: "threat-intel",
            title: format!("{} contacted a known-bad indicator", d.label()),
            message: format!(
                "Observed {observed}, which matches \"{}\" on {}. Treat the device as potentially compromised until proven otherwise.",
                hit.indicator, hit.source
            ),
            device: Some(d.mac),
            remote: Some(observed.clone()),
            port: None,
            value: None,
            ts,
        });
    }
    if !rules.suspicious_domains {
        return;
    }
    for host in suspicious {
        let base = base_domain(host);
        let key = format!("dga:{base}");
        if d.baseline.domains.contains(&base) || d.flagged.contains(&key) || d.flagged.len() >= 512
        {
            continue;
        }
        d.flagged.insert(key);
        // A DGA tries dozens of names; one alert per burst is enough.
        if ts.timestamp() - d.live.dga_alerted < RATE_ALERT_COOLDOWN * 5 {
            continue;
        }
        d.live.dga_alerted = ts.timestamp();
        let subject = if base == *host {
            host.clone()
        } else {
            format!("{host} (registered name {base})")
        };
        out.push(Draft {
            severity: if iot { Severity::High } else { Severity::Medium },
            rule: "suspicious-domain",
            title: format!("{}: algorithmically generated domain", d.label()),
            message: format!(
                "Looked up {subject} — long and random-looking (entropy {:.1} bits/char), typical of malware domain-generation algorithms used to find command-and-control servers.",
                entropy(base.split('.').next().unwrap_or(&base))
            ),
            device: Some(d.mac),
            remote: Some(host.clone()),
            port: None,
            value: None,
            ts,
        });
    }
}

/// Collapse a hostname to its registrable domain: `a.b.ecobee.com` ->
/// `ecobee.com`, `x.service.co.uk` -> `service.co.uk`.
pub fn base_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_string();
    }
    let sld = labels[n - 2];
    let take = if labels[n - 1].len() == 2
        && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "ac" | "edu")
    {
        3
    } else {
        2
    };
    labels[n.saturating_sub(take)..].join(".")
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 | 2323 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 | 8080 => "HTTP",
        123 => "NTP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        554 | 8554 => "RTSP",
        1883 => "MQTT",
        8883 => "MQTT/TLS",
        3389 => "RDP",
        4444 => "Metasploit default",
        5555 => "Android ADB",
        6667 => "IRC (botnet C2)",
        7547 => "TR-069",
        9001 => "Tor ORPort",
        37215 => "Huawei HG532 exploit",
        52869 => "Realtek UPnP exploit",
        _ => "unknown service",
    }
}

fn net_rules(d: &mut Device, e: NetEvent, rules: &RuleSettings, out: &mut Vec<Draft>) {
    let learning = d.baseline.learning(e.ts);
    let iot = d.is_iot();
    let label = d.label();
    let external = e.external;
    let key = e.remote.to_string();

    if let Some(dom) = &e.domain {
        if learning {
            d.baseline.domains.insert(base_domain(dom));
        }
    }

    if e.outbound {
        d.live.win_dests.insert(e.remote);
    }
    if d.destinations.len() >= MAX_DESTINATIONS && !d.destinations.contains_key(&key) {
        return; // bounded memory; the burst rule still sees win_dests
    }
    let dest = d
        .destinations
        .entry(key.clone())
        .or_insert_with(|| Destination {
            ip: e.remote,
            domain: None,
            external,
            ports: BTreeSet::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            packets: 0,
            first_seen: e.ts,
            last_seen: e.ts,
            in_baseline: false,
            alerted: false,
        });
    if e.domain.is_some() {
        dest.domain = e.domain.clone();
    }
    if e.outbound {
        dest.tx_bytes += e.bytes;
    } else {
        dest.rx_bytes += e.bytes;
    }
    dest.packets += 1;
    dest.last_seen = e.ts;
    if let Some(p) = e.service {
        dest.ports.insert(p);
    }

    if learning {
        d.baseline.destinations.insert(e.remote);
        dest.in_baseline = true;
        if let Some(p) = e.service {
            d.baseline.ports.insert(p);
        }
    } else if !dest.in_baseline {
        let known = d.baseline.destinations.contains(&e.remote)
            || dest
                .domain
                .as_deref()
                .is_some_and(|h| d.baseline.domains.contains(&base_domain(h)));
        if known {
            dest.in_baseline = true;
        } else if rules.new_destination
            && external
            && !dest.alerted
            && (iot || !rules.new_destination_iot_only)
            // one alert per 30 s per device; scans are covered by the burst rule
            && e.ts.timestamp() - d.live.newdest_alerted >= 30
        {
            dest.alerted = true;
            d.live.newdest_alerted = e.ts.timestamp();
            let name = dest
                .domain
                .clone()
                .map(|h| format!(" ({h})"))
                .unwrap_or_else(|| " (no DNS name seen)".into());
            let port = dest.ports.iter().next().copied();
            out.push(Draft {
                severity: if iot {
                    Severity::High
                } else {
                    Severity::Medium
                },
                rule: "new-destination",
                title: format!("{label} communicating with unknown external host"),
                message: format!(
                    "Contacted {}{}{} — not part of the device's learned baseline of {} host(s).",
                    e.remote,
                    name,
                    port.map(|p| format!(" on port {p}/{}", service_name(p)))
                        .unwrap_or_default(),
                    d.baseline.destinations.len()
                ),
                device: Some(d.mac),
                remote: Some(key.clone()),
                port,
                value: None,
                ts: e.ts,
            });
        }
    }

    if let Some(port) = e.service {
        *d.ports.entry(port).or_default() += 1;
        let first_time = !d.alerted_ports.contains(&port);
        if first_time && rules.unexpected_port && rules.risky_ports.contains(&port) {
            d.alerted_ports.insert(port);
            out.push(Draft {
                severity: if iot { Severity::Critical } else { Severity::High },
                rule: "risky-port",
                title: format!("{label} connecting to risky service {}", service_name(port)),
                message: format!(
                    "Outbound connection to {}:{port} ({}). Commonly abused by IoT botnets (e.g. Mirai) or for lateral movement.",
                    e.remote,
                    service_name(port)
                ),
                device: Some(d.mac),
                remote: Some(key.clone()),
                port: Some(port),
                value: None,
                ts: e.ts,
            });
        } else if first_time
            && !learning
            && rules.unexpected_port
            && !d.baseline.ports.contains(&port)
            && !INFRA_PORTS.contains(&port)
            // 49152-65535 is the dynamic range: never a fixed service.
            && port < 49152
            // Routers and APs speak to everything; link-local peers are LAN plumbing.
            && !d.is_gateway
            && !d.is_ap
            && !is_link_local(&e.remote)
        {
            d.alerted_ports.insert(port);
            out.push(Draft {
                severity: if iot {
                    Severity::High
                } else {
                    Severity::Medium
                },
                rule: "unexpected-port",
                title: format!("{label} using an unexpected service port"),
                message: format!(
                    "Connection to {}:{port} ({}). Baseline ports: {}.",
                    e.remote,
                    service_name(port),
                    if d.baseline.ports.is_empty() {
                        "none".to_string()
                    } else {
                        d.baseline
                            .ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                device: Some(d.mac),
                remote: Some(key),
                port: Some(port),
                value: None,
                ts: e.ts,
            });
        }
    }
}

fn rate_rules(
    d: &mut Device,
    ts: DateTime<Utc>,
    bytes: u64,
    syn: bool,
    rules: &RuleSettings,
    out: &mut Vec<Draft>,
) {
    let sec = ts.timestamp();
    let wstart = sec - sec.rem_euclid(WINDOW_SECS);
    let learning = d.baseline.learning(ts);
    let iot = d.is_iot();

    if wstart > d.live.win_start {
        // Close the previous window and fold it into the baseline.
        if d.live.win_start != 0 && learning {
            let b = &mut d.baseline;
            b.windows += 1;
            b.peak_window_bytes = b.peak_window_bytes.max(d.live.win_bytes);
            b.avg_window_bytes += (d.live.win_bytes as f64 - b.avg_window_bytes) / b.windows as f64;
        }
        d.live.win_start = wstart;
        d.live.win_bytes = 0;
        d.live.win_syns = 0;
        d.live.win_dests.clear();
    }
    d.live.win_bytes += bytes;
    if syn {
        d.live.win_syns += 1;
    }

    // Hour-of-day profile
    let local = ts.with_timezone(&Local);
    let hour = local.hour() as usize;
    let hour_key = sec / 3600;
    if hour_key != d.live.hour_key {
        d.live.hour_key = hour_key;
        d.live.hour_bytes = 0;
        d.live.hour_syns = 0;
    }
    d.live.hour_bytes += bytes;
    if syn {
        d.live.hour_syns += 1;
    }
    d.hourly[hour] += 1;
    if learning {
        d.baseline.hours[hour] = true;
    }

    let label = d.label();

    // Connection burst / scan - checked even while learning, so a device
    // that is already compromised doesn't poison its own baseline silently.
    let dests = d.live.win_dests.len() as u32;
    if rules.connection_burst
        && (d.live.win_syns > rules.syn_threshold || dests > rules.syn_threshold)
        && sec - d.live.burst_alerted >= RATE_ALERT_COOLDOWN
    {
        d.live.burst_alerted = sec;
        out.push(Draft {
            severity: Severity::High,
            rule: "connection-burst",
            title: format!("{label}: burst of connection attempts"),
            message: format!(
                "{} TCP connection attempts to {} distinct hosts within {WINDOW_SECS} s — looks like scanning or worm propagation.",
                d.live.win_syns, dests
            ),
            device: Some(d.mac),
            remote: None,
            port: None,
            value: Some(d.live.win_syns.max(dests) as f64),
            ts,
        });
    }

    // Routers and APs relay everyone's traffic; per-device volume and
    // schedule rules would just echo the real culprit's alert.
    if learning || d.is_ap || d.is_gateway {
        return;
    }

    if rules.volume_spike {
        let threshold = ((d.baseline.peak_window_bytes as f64) * rules.spike_factor)
            .max(rules.spike_min_bytes as f64);
        if d.live.win_bytes as f64 > threshold && sec - d.live.spike_alerted >= RATE_ALERT_COOLDOWN
        {
            d.live.spike_alerted = sec;
            let ratio = d.live.win_bytes as f64 / (d.baseline.peak_window_bytes.max(1)) as f64;
            out.push(Draft {
                severity: if iot {
                    Severity::High
                } else {
                    Severity::Medium
                },
                rule: "volume-spike",
                title: format!("{label}: abnormal traffic volume"),
                message: format!(
                    "{} in {WINDOW_SECS} s — {:.1}× the learned peak of {}.",
                    fmt_bytes(d.live.win_bytes),
                    ratio,
                    fmt_bytes(d.baseline.peak_window_bytes)
                ),
                device: Some(d.mac),
                remote: None,
                port: None,
                value: Some(d.live.win_bytes as f64),
                ts,
            });
        }
    }

    if rules.unusual_time && d.live.unusual_alerted_hour != hour_key {
        let b = &d.baseline;
        let outside_profile = b.hours_valid()
            && !b.hours[hour]
            && !b.hours[(hour + 23) % 24]
            && !b.hours[(hour + 1) % 24];
        let quiet = rules.quiet_hours_enabled && rules.in_quiet_hours(hour as u32);
        let heavy =
            d.live.hour_bytes >= rules.spike_min_bytes || d.live.hour_syns >= rules.syn_threshold;
        if (outside_profile || quiet) && heavy {
            d.live.unusual_alerted_hour = hour_key;
            out.push(Draft {
                severity: if iot {
                    Severity::High
                } else {
                    Severity::Medium
                },
                rule: "unusual-time",
                title: format!("{label}: heavy activity at an unusual time"),
                message: format!(
                    "{} and {} connection attempts this hour ({:02}:00) — {}.",
                    fmt_bytes(d.live.hour_bytes),
                    d.live.hour_syns,
                    hour,
                    if quiet {
                        "inside configured quiet hours"
                    } else {
                        "outside the device's normal active hours"
                    }
                ),
                device: Some(d.mac),
                remote: None,
                port: None,
                value: Some(d.live.hour_bytes as f64),
                ts,
            });
        }
    }
}

fn deauth_rule(d: &mut Device, ts: DateTime<Utc>, rules: &RuleSettings, out: &mut Vec<Draft>) {
    let sec = ts.timestamp();
    if sec - d.live.deauth_win_start >= WINDOW_SECS {
        d.live.deauth_win_start = sec;
        d.live.deauth_count = 0;
    }
    d.live.deauth_count += 1;
    if rules.deauth_flood
        && d.live.deauth_count > rules.deauth_threshold
        && sec - d.live.deauth_alerted >= RATE_ALERT_COOLDOWN
    {
        d.live.deauth_alerted = sec;
        out.push(Draft {
            severity: Severity::High,
            rule: "deauth-flood",
            title: "Wi-Fi deauthentication flood detected".into(),
            message: format!(
                "{}+ deauth/disassoc frames in {WINDOW_SECS} s with transmitter {}{}. Possible deauth attack forcing clients off the network (the transmitter address may be spoofed).",
                d.live.deauth_count,
                d.mac,
                d.ssids.iter().next().map(|s| format!(" (\"{s}\")")).unwrap_or_default()
            ),
            device: Some(d.mac),
            remote: None,
            port: None,
            value: Some(d.live.deauth_count as f64),
            ts,
        });
    }
}

/// Cleartext or legacy protocol spoken on a service port.
fn insecure_protocol(port: u16, payload: &[u8]) -> Option<&'static str> {
    Some(match port {
        23 | 2323 => "telnet",
        21 => "ftp",
        69 => "tftp",
        110 => "pop3",
        143 => "imap",
        161 => "snmp",
        1883 => "mqtt",
        80 | 8080
            if [&b"GET "[..], b"POST ", b"PUT ", b"HTTP/1."]
                .iter()
                .any(|m| payload.starts_with(m)) =>
        {
            "http"
        }
        445 if memchr::memmem::find(payload, b"\xffSMB").is_some() => "smbv1",
        _ => return None,
    })
}

/// A device's DHCP client fingerprint changed after learning: likely another
/// device now uses this MAC (spoofing) or the OS was replaced.
fn identity_rule(
    d: &mut Device,
    params: &str,
    ts: DateTime<Utc>,
    rules: &RuleSettings,
    out: &mut Vec<Draft>,
) {
    let Some(old) = d.dhcp_params.clone() else {
        return;
    };
    if old == params || d.baseline.learning(ts) || !rules.fingerprint_drift {
        return;
    }
    let key = format!("dhcp:{params}");
    if d.flagged.contains(&key) || d.flagged.len() >= 512 {
        return;
    }
    d.flagged.insert(key);
    let os = |p: &str| fingerprint::dhcp_os(p, None).unwrap_or("unknown OS");
    out.push(Draft {
        severity: Severity::Medium,
        rule: "identity-change",
        title: format!("{}: device identity changed", d.label()),
        message: format!(
            "DHCP fingerprint changed from {} ({old}) to {} ({params}). Another device may be using this MAC address (spoofing), or the device was reset or replaced.",
            os(&old),
            os(params)
        ),
        device: Some(d.mac),
        remote: None,
        port: None,
        value: None,
        ts,
    });
}

/// Learn TLS client fingerprints; alert when an IoT device starts a TLS
/// client it never used while learning.
fn tls_rule(
    d: &mut Device,
    t: &ClientHello,
    ts: DateTime<Utc>,
    rules: &RuleSettings,
    out: &mut Vec<Draft>,
) {
    let learning = d.baseline.learning(ts);
    let new = !d.tls.contains_key(&t.ja4);
    if new && d.tls.len() >= 32 {
        return;
    }
    let e = d
        .tls
        .entry(t.ja4.clone())
        .or_insert_with(|| TlsFingerprint {
            ja3: t.ja3_hash.clone(),
            first_seen: ts,
            last_seen: ts,
            count: 0,
            sni: t.sni.clone(),
            legacy: t.legacy(),
        });
    e.count += 1;
    e.last_seen = ts;
    if t.legacy() {
        d.insecure.insert("legacy-tls".into());
    }
    if learning {
        d.baseline.tls.insert(t.ja4.clone());
        return;
    }
    if !new
        || !rules.fingerprint_drift
        || !d.is_iot()
        || d.baseline.tls.is_empty()
        || d.baseline.tls.contains(&t.ja4)
    {
        return;
    }
    let key = format!("ja4:{}", t.ja4);
    if !d.flagged.insert(key) {
        return;
    }
    out.push(Draft {
        severity: Severity::Medium,
        rule: "fingerprint-change",
        title: format!("{}: new TLS client fingerprint", d.label()),
        message: format!(
            "Started a TLS client never seen while learning (JA4 {}, JA3 {}){}. IoT firmware rarely changes its TLS stack — new software, a firmware update, or malware.",
            t.ja4,
            t.ja3_hash,
            t.sni.as_ref().map(|s| format!(" connecting to {s}")).unwrap_or_default()
        ),
        device: Some(d.mac),
        remote: t.sni.clone(),
        port: None,
        value: None,
        ts,
    });
}

/// A signature matched traffic of this device.
fn ids_rule(
    d: &mut Device,
    r: &ids::Rule,
    p: &ids::Packet,
    ts: DateTime<Utc>,
    out: &mut Vec<Draft>,
) {
    let sec = ts.timestamp();
    if d.live
        .ids_alerted
        .get(&r.sid)
        .is_some_and(|t| sec - t < IDS_COOLDOWN)
    {
        return;
    }
    d.live.ids_alerted.insert(r.sid, sec);
    let severity = match r.classtype.as_deref() {
        Some(
            "policy-violation"
            | "protocol-command-decode"
            | "misc-activity"
            | "not-suspicious"
            | "unknown",
        ) => Severity::Low,
        Some(
            "attempted-recon"
            | "network-scan"
            | "successful-recon-limited"
            | "bad-unknown"
            | "default-login-attempt",
        ) => Severity::Medium,
        Some("successful-admin" | "successful-user" | "command-and-control" | "domain-c2") => {
            Severity::Critical
        }
        Some(_) => Severity::High,
        None if r.priority <= 1 => Severity::High,
        None => Severity::Medium,
    };
    let remote = if p.src_home { p.dst } else { p.src };
    out.push(Draft {
        severity,
        rule: "ids-signature",
        title: r.msg.clone(),
        message: format!(
            "{}:{} → {}:{} matched signature {} rev {}{} from {}.",
            p.src,
            p.sport,
            p.dst,
            p.dport,
            r.sid,
            r.rev,
            r.classtype
                .as_ref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            r.source
        ),
        device: Some(d.mac),
        remote: Some(remote.to_string()),
        port: Some(if p.src_home { p.dport } else { p.sport }),
        value: Some(r.sid as f64),
        ts,
    });
}

/// Human summary of a frame for the live feed: (protocol, info).
pub fn describe(p: &PacketInfo, names: &HashMap<IpAddr, String>) -> (String, String) {
    if let Some(a) = &p.arp {
        return (
            "ARP".into(),
            if a.reply {
                format!("{} is at {}", a.sender_ip, a.sender_mac)
            } else {
                format!("Who has {}? Tell {}", a.target_ip, a.sender_ip)
            },
        );
    }
    if let Some(n) = &p.net {
        if let Some(q) = &n.dns_query {
            if n.dns_answers.is_empty() {
                return ("DNS".into(), format!("Query {q}"));
            }
            let ips: Vec<String> = n
                .dns_answers
                .iter()
                .take(3)
                .map(|(_, ip)| ip.to_string())
                .collect();
            return ("DNS".into(), format!("{q} → {}", ips.join(", ")));
        }
        if let Some(sni) = &n.sni {
            return (
                "TLS".into(),
                format!(
                    "ClientHello → {sni} ({}:{})",
                    n.dst_ip,
                    n.dst_port.unwrap_or(0)
                ),
            );
        }
        if let Some(h) = n.hints.first() {
            let (proto, txt) = match h {
                Hint::Hostname(v) if n.dst_port == Some(67) => {
                    ("DHCP", format!("Request from host \"{v}\""))
                }
                Hint::VendorClass(v) => ("DHCP", format!("Request, vendor class \"{v}\"")),
                Hint::Hostname(v) => ("mDNS", format!("Announces \"{v}\"")),
                Hint::Service(v) => ("mDNS", format!("Advertises service {v}")),
                Hint::Server(v) => ("SSDP", format!("UPnP device: {v}")),
                Hint::UserAgent(v) => ("HTTP", format!("User-Agent: {v}")),
                Hint::DhcpParams(v) => ("DHCP", format!("Request, parameter list {v}")),
            };
            return (proto.into(), txt);
        }
        if let Some((t, c)) = n.icmp {
            let who = |ip: &IpAddr| match names.get(ip) {
                Some(name) => format!("{ip} ({name})"),
                None => ip.to_string(),
            };
            let v6 = n.src_ip.is_ipv6();
            let txt = match (v6, t) {
                (true, 135) => n.nd_target.map(|x| {
                    format!(
                        "Neighbor solicitation: who has {}? (IPv6 address lookup, like ARP)",
                        who(&x)
                    )
                }),
                (true, 136) => n.nd_target.map(|x| {
                    format!(
                        "Neighbor advertisement: {} is here (answer to an address lookup)",
                        who(&x)
                    )
                }),
                (true, 133) => Some("Router solicitation: looking for an IPv6 router".into()),
                (true, 134) => {
                    Some("Router advertisement: announces IPv6 router and network prefix".into())
                }
                (true, 128) | (false, 8) => Some(format!(
                    "Ping request {} → {}",
                    who(&n.src_ip),
                    who(&n.dst_ip)
                )),
                (true, 129) | (false, 0) => Some(format!(
                    "Ping reply {} → {}",
                    who(&n.src_ip),
                    who(&n.dst_ip)
                )),
                (true, 1) | (false, 3) => Some(format!(
                    "Destination unreachable (code {c}) {} → {}",
                    who(&n.src_ip),
                    who(&n.dst_ip)
                )),
                (true, 3) | (false, 11) => Some(format!(
                    "Time exceeded {} → {}",
                    who(&n.src_ip),
                    who(&n.dst_ip)
                )),
                (true, 143) => {
                    Some("Multicast listener report (joins IPv6 multicast groups)".into())
                }
                _ => None,
            };
            if let Some(txt) = txt {
                return (if v6 { "ICMPv6" } else { "ICMP" }.into(), txt);
            }
        }
        let port_name = |p: Option<u16>| p.map(service_name).filter(|s| *s != "unknown service");
        let proto = match n.transport {
            Transport::Tcp => port_name(n.dst_port)
                .or(port_name(n.src_port))
                .unwrap_or("TCP"),
            Transport::Udp => port_name(n.dst_port)
                .or(port_name(n.src_port))
                .unwrap_or("UDP"),
            Transport::Icmp => "ICMP",
            Transport::Other => "IP",
        };
        let ep = |ip: &IpAddr, port: Option<u16>| {
            let base = match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.to_string(),
            };
            match names.get(ip) {
                Some(n) => format!("{base} ({n})"),
                None => base,
            }
        };
        return (
            proto.into(),
            format!(
                "{} → {}{}",
                ep(&n.src_ip, n.src_port),
                ep(&n.dst_ip, n.dst_port),
                if n.tcp_syn { " [SYN]" } else { "" }
            ),
        );
    }
    let ssid = |p: &PacketInfo| {
        p.ssid
            .as_deref()
            .map(|s| format!("“{s}”"))
            .unwrap_or_else(|| "(hidden/any)".into())
    };
    let info = match p.subtype {
        "beacon" => format!("Beacon {}", ssid(p)),
        "probe-req" => format!("Probe request for {}", ssid(p)),
        "probe-resp" => format!("Probe response {}", ssid(p)),
        "assoc-req" => format!("Association request to {}", ssid(p)),
        "reassoc-req" => format!("Reassociation request to {}", ssid(p)),
        "assoc-resp" | "reassoc-resp" => "Association response".into(),
        "auth" => "Authentication".into(),
        "deauth" => "Deauthentication".into(),
        "disassoc" => "Disassociation".into(),
        "action" => "Action frame".into(),
        "ack" => "ACK".into(),
        "rts" => "Request to send".into(),
        "cts" => "Clear to send".into(),
        "block-ack" | "block-ack-req" => "Block ACK".into(),
        "null" | "qos-null" => "Null function (power save)".into(),
        "eapol" => "EAPOL (WPA key handshake)".into(),
        _ if p.protected => "Encrypted data (WPA/WEP)".into(),
        s => s.to_string(),
    };
    let proto = match p.kind {
        FrameKind::Management => "802.11 mgmt",
        FrameKind::Control => "802.11 ctrl",
        FrameKind::Data => "802.11 data",
        FrameKind::Ethernet => "Ethernet",
    };
    (proto.into(), info)
}

/// UUIDs / long hex blobs announced as "names" by some mDNS stacks.
fn looks_like_id(s: &str) -> bool {
    let core: String = s.chars().filter(|c| *c != '-' && *c != ':').collect();
    core.len() >= 12 && core.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn fmt_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.1} kB", b / 1e3)
    } else {
        format!("{b} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NetInfo;

    #[test]
    fn describes_ipv6_neighbor_discovery() {
        let mut p = pkt(
            Utc::now(),
            Mac([2, 0, 0, 0, 0, 1]),
            Mac([2, 0, 0, 0, 0, 2]),
            "fe80::1",
            "fe80::2",
            0,
            false,
            86,
        );
        let n = p.net.as_mut().unwrap();
        n.transport = Transport::Icmp;
        n.dst_port = None;
        n.icmp = Some((135, 0));
        n.nd_target = Some("2600::5".parse().unwrap());
        let names = HashMap::from([("2600::5".parse().unwrap(), "iPhone".to_string())]);
        let (proto, info) = describe(&p, &names);
        assert_eq!(proto, "ICMPv6");
        assert!(info.contains("who has 2600::5 (iPhone)"), "{info}");
    }

    #[allow(clippy::too_many_arguments)]
    fn pkt(
        ts: DateTime<Utc>,
        src: Mac,
        dst: Mac,
        sip: &str,
        dip: &str,
        dport: u16,
        syn: bool,
        len: u32,
    ) -> PacketInfo {
        let mut p = PacketInfo::new(ts, FrameKind::Ethernet, "ipv4", len);
        p.src = Some(src);
        p.dst = Some(dst);
        p.net = Some(NetInfo {
            src_ip: sip.parse().unwrap(),
            dst_ip: dip.parse().unwrap(),
            transport: Transport::Tcp,
            src_port: Some(50000),
            dst_port: Some(dport),
            tcp_syn: syn,
            dns_query: None,
            dns_answers: vec![],
            sni: None,
            hints: vec![],
            routers: vec![],
            router_adv: None,
            tls: None,
            dns_response: false,
            dns_rcode: 0,
            icmp: None,
            nd_target: None,
            payload: vec![],
        });
        p
    }

    #[test]
    fn baseline_then_new_destination_and_risky_port() {
        let mut e = Engine::new(
            RuleSettings {
                learning_minutes: 1,
                ..Default::default()
            },
            OuiDb::load(None),
        );
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let cam: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        e.process(&pkt(
            t0,
            cam,
            gw,
            "192.168.1.10",
            "52.1.1.1",
            443,
            true,
            200,
        ));
        e.tick(None);
        assert!(e.devices[&cam].is_iot());
        assert!(e.alerts.is_empty());

        // after learning: known host stays quiet, new host alerts
        let t1 = t0 + Duration::minutes(2);
        e.process(&pkt(
            t1,
            cam,
            gw,
            "192.168.1.10",
            "52.1.1.1",
            443,
            true,
            200,
        ));
        assert!(e.alerts.is_empty());
        e.process(&pkt(
            t1,
            cam,
            gw,
            "192.168.1.10",
            "185.220.101.4",
            443,
            true,
            200,
        ));
        assert_eq!(e.alerts.len(), 1);
        assert_eq!(e.alerts[0].rule, "new-destination");
        assert_eq!(e.alerts[0].severity, Severity::High);

        e.process(&pkt(
            t1,
            cam,
            gw,
            "192.168.1.10",
            "203.0.113.5",
            23,
            true,
            60,
        ));
        assert!(e
            .alerts
            .iter()
            .any(|a| a.rule == "risky-port" && a.severity == Severity::Critical));

        // accepting folds it into the baseline
        let id = e.alerts[0].id;
        e.accept(id).unwrap();
        assert!(e.devices[&cam]
            .baseline
            .destinations
            .contains(&"185.220.101.4".parse().unwrap()));
    }

    #[test]
    fn connection_burst() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let plug: Mac = "24:0a:c4:00:00:02".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        for i in 0..60 {
            e.process(&pkt(
                t0,
                plug,
                gw,
                "192.168.1.11",
                &format!("198.51.100.{i}"),
                8080,
                true,
                60,
            ));
        }
        assert!(e.alerts.iter().any(|a| a.rule == "connection-burst"));
    }

    fn arp(ts: DateTime<Utc>, mac: Mac, ip: &str) -> PacketInfo {
        let mut p = PacketInfo::new(ts, FrameKind::Ethernet, "arp", 60);
        p.src = Some(mac);
        p.dst = Some(Mac::BROADCAST);
        p.arp = Some(crate::model::ArpInfo {
            sender_mac: mac,
            sender_ip: ip.parse().unwrap(),
            target_ip: "192.168.1.99".parse().unwrap(),
            reply: true,
        });
        p
    }

    fn ra(ts: DateTime<Utc>, mac: Mac, lifetime: u16) -> PacketInfo {
        let mut p = pkt(
            ts,
            mac,
            "33:33:00:00:00:01".parse().unwrap(),
            "fe80::1",
            "ff02::1",
            0,
            false,
            80,
        );
        let n = p.net.as_mut().unwrap();
        n.transport = Transport::Icmp;
        n.src_port = None;
        n.dst_port = None;
        n.router_adv = Some(crate::model::RouterAdv {
            lifetime,
            prefixes: vec![("2601:646:8f00:1::".parse().unwrap(), 64)],
        });
        p
    }

    /// Regression: hosts using global IPv6 addresses (neighbor discovery to
    /// link-local / multicast destinations) were all marked as gateways.
    #[test]
    fn ipv6_hosts_are_not_gateways() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let mac_mini: Mac = "46:48:79:df:94:29".parse().unwrap();
        let macbook: Mac = "4e:f8:ac:80:72:fa".parse().unwrap();
        let router: Mac = "a0:8a:06:2e:ff:9a".parse().unwrap();
        let mdns: Mac = "33:33:00:00:00:fb".parse().unwrap();
        for i in 0..10 {
            let a = format!("2601:646:8f00:1::{:x}", 0x100 + i);
            e.process(&pkt(t0, mac_mini, mdns, &a, "ff02::fb", 5353, false, 120));
            e.process(&pkt(t0, mac_mini, router, &a, "fe80::1", 0, false, 86));
            e.process(&pkt(
                t0,
                macbook,
                mac_mini,
                "2601:646:8f00:1::77",
                &a,
                7000,
                true,
                60,
            ));
        }
        e.tick(None);
        assert!(
            !e.devices[&mac_mini].is_gateway,
            "multicast / link-local peers are not relayed traffic"
        );
        assert!(!e.devices[&macbook].is_gateway);

        // Real router: relays traffic from many internet hosts.
        for i in 0..6 {
            e.process(&pkt(
                t0,
                router,
                mac_mini,
                &format!("17.253.{i}.10"),
                "192.168.1.59",
                443,
                false,
                1400,
            ));
        }
        assert!(e.devices[&router].is_gateway);
        assert!(!e.devices[&mac_mini].is_gateway);
    }

    #[test]
    fn global_ipv6_peers_on_the_lan_are_not_external() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        e.lan_nets = vec!["2601:646:8f00:1::/64".parse().unwrap()];
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let a: Mac = "02:00:00:00:00:0a".parse().unwrap();
        let b: Mac = "02:00:00:00:00:0b".parse().unwrap();
        for i in 0..8 {
            e.process(&pkt(
                t0,
                a,
                b,
                "2601:646:8f00:1::a",
                &format!("2601:646:8f00:1::{:x}", 0xb0 + i),
                7000,
                false,
                100,
            ));
        }
        assert!(!e.devices[&b].is_gateway);
        assert!(e.devices[&a].destinations.values().all(|d| !d.external));
    }

    #[test]
    fn router_identity_and_arp_spoofing() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        e.gateway_ip = Some("192.168.1.1".parse().unwrap());
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let router: Mac = "a0:8a:06:2e:ff:9a".parse().unwrap();
        let attacker: Mac = "02:13:37:00:00:01".parse().unwrap();
        e.process(&arp(t0, router, "192.168.1.1"));
        assert!(e.devices[&router].is_gateway);
        assert!(e.gateway_macs.contains(&router));

        e.process(&arp(t0, attacker, "192.168.1.1"));
        assert!(
            !e.devices[&attacker].is_gateway,
            "an impersonator must not be shown as the router"
        );
        let a = e
            .alerts
            .iter()
            .find(|a| a.rule == "arp-spoof")
            .expect("arp-spoof alert");
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.mitre_id.as_deref(), Some("T1557.002"));

        // Known router + another MAC relaying internet traffic: not promoted.
        for i in 0..8 {
            e.process(&pkt(
                t0,
                attacker,
                "02:00:00:00:00:05".parse().unwrap(),
                &format!("8.8.{i}.8"),
                "192.168.1.5",
                443,
                false,
                300,
            ));
        }
        assert!(!e.devices[&attacker].is_gateway);

        // Old false "unexpected port" alerts on link-local peers are closed on restore.
        let fp = Alert {
            id: 99,
            ts: t0,
            severity: Severity::Medium,
            rule: "unexpected-port".into(),
            title: "x".into(),
            message: "x".into(),
            device: Some(router),
            device_label: None,
            remote: Some("fe80::869:cffb:8384:d373".into()),
            port: Some(546),
            value: None,
            acknowledged: false,
            mitre_id: None,
            mitre_name: None,
            tactic: None,
            status: AlertStatus::New,
            owner: None,
            notes: vec![],
            urgency: None,
            evidence: None,
            context: None,
        };
        e.restore(vec![], vec![fp], 100);
        assert_eq!(e.alerts.back().unwrap().status, AlertStatus::FalsePositive);

        // Stale flags from older versions are dropped on restore.
        let mut stale = e.devices[&attacker].clone();
        stale.is_gateway = true;
        e.restore(vec![stale], vec![], 1);
        assert!(!e.devices[&attacker].is_gateway);
    }

    #[test]
    fn router_advertisements() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let router: Mac = "a0:8a:06:2e:ff:9a".parse().unwrap();
        let homepod: Mac = "7a:00:00:00:00:01".parse().unwrap();
        let rogue: Mac = "02:66:00:00:00:06".parse().unwrap();
        e.process(&ra(t0, homepod, 0)); // Thread border router: lifetime 0
        assert!(!e.devices[&homepod].is_gateway);
        e.process(&ra(t0, router, 1800));
        assert!(e.devices[&router].is_gateway);
        assert!(
            e.is_lan(&"2601:646:8f00:1::abcd".parse().unwrap()),
            "RA prefix is part of the LAN"
        );
        e.process(&ra(t0, rogue, 1800));
        assert!(e
            .alerts
            .iter()
            .any(|a| a.rule == "rogue-router" && a.device == Some(rogue)));
    }

    #[test]
    fn watchlist_dga_and_risk_correlation() {
        let rules = RuleSettings {
            watchlist: vec!["evil.example".into(), "203.0.113.0/24 # botnet C2".into()],
            ..Default::default()
        };
        let mut e = Engine::new(rules, OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let plug: Mac = "24:0a:c4:00:00:02".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        e.process(&pkt(
            t0,
            plug,
            gw,
            "192.168.1.11",
            "203.0.113.50",
            8443,
            true,
            80,
        ));
        e.process(&pkt(
            t0,
            plug,
            gw,
            "192.168.1.11",
            "203.0.113.51",
            8443,
            true,
            80,
        ));
        let hits: Vec<&Alert> = e
            .alerts
            .iter()
            .filter(|a| a.rule == "threat-intel")
            .collect();
        assert_eq!(hits.len(), 1, "one alert per indicator per device");

        let mut q = pkt(t0, plug, gw, "192.168.1.11", "192.168.1.1", 53, false, 70);
        q.net.as_mut().unwrap().transport = Transport::Udp;
        q.net.as_mut().unwrap().dns_query = Some("cdn.evil.example".into());
        e.process(&q);
        q.net.as_mut().unwrap().dns_query = Some("xj4kq9vbz2lmw8.net".into());
        e.process(&q);
        assert!(e.alerts.iter().filter(|a| a.rule == "threat-intel").count() == 2);
        assert!(e.alerts.iter().any(|a| a.rule == "suspicious-domain"));

        // Several distinct critical/high detections cross the risk threshold.
        assert!(e
            .alerts
            .iter()
            .any(|a| a.rule == "risk-threshold" && a.device == Some(plug)));
        assert!(e.summaries().iter().find(|d| d.mac == plug).unwrap().risk >= 100);
    }

    #[test]
    fn incident_review_priority_and_detections() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let cam: Mac = "44:19:b6:00:00:01".parse().unwrap();
        e.process(&arp(t0, cam, "192.168.1.21"));
        assert_eq!(
            e.raise_detection(
                "Camera talks Telnet",
                Severity::Medium,
                "matched",
                &[cam],
                60
            ),
            1
        );
        assert_eq!(
            e.raise_detection(
                "Camera talks Telnet",
                Severity::Medium,
                "matched",
                &[cam],
                60
            ),
            0,
            "throttled"
        );
        let id = e.alerts.back().unwrap().id;
        assert_eq!(
            e.view(e.alerts.back().unwrap()).urgency,
            Some(Severity::Medium)
        );

        e.update_device(&cam, None, None, None, Some(Priority::Critical));
        assert_eq!(
            e.view(e.alerts.back().unwrap()).urgency,
            Some(Severity::Critical)
        );
        let before = e.risk_map()[&cam].0;
        e.update_alerts(
            &[id],
            Some(AlertStatus::InProgress),
            Some("bryan".into()),
            Some("checking firmware".into()),
        );
        let a = e.alerts.back().unwrap();
        assert!(!a.acknowledged && a.owner.as_deref() == Some("bryan") && a.notes.len() == 2);
        assert!(before >= 30, "critical asset doubles risk");
        e.update_alerts(&[id], Some(AlertStatus::FalsePositive), None, None);
        assert!(e.alerts.back().unwrap().acknowledged);
        assert!(
            !e.risk_map().contains_key(&cam),
            "closed alerts carry no risk"
        );
    }

    #[test]
    fn connection_and_dns_logs() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let cam: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        for i in 0..3 {
            e.process(&pkt(
                t0 + Duration::seconds(i),
                cam,
                gw,
                "192.168.1.10",
                "52.1.1.1",
                443,
                i == 0,
                500,
            ));
        }
        let mut back = pkt(
            t0 + Duration::seconds(3),
            gw,
            cam,
            "52.1.1.1",
            "192.168.1.10",
            50000,
            false,
            1500,
        );
        back.net.as_mut().unwrap().src_port = Some(443);
        e.process(&back);
        assert_eq!(e.open_flows(Some(cam)).len(), 1);
        let f = &e.open_flows(None)[0];
        assert_eq!(
            (f.bytes_out, f.bytes_in, f.packets, f.outbound, f.service),
            (1500, 1500, 4, true, Some(443))
        );

        let mut r = pkt(
            t0,
            gw,
            cam,
            "192.168.1.1",
            "192.168.1.10",
            40000,
            false,
            120,
        );
        let n = r.net.as_mut().unwrap();
        n.transport = Transport::Udp;
        n.src_port = Some(53);
        n.dns_response = true;
        n.dns_rcode = 3;
        n.dns_query = Some("nope.example".into());
        e.process(&r);
        e.clock = t0 + Duration::minutes(5);
        e.close_idle_flows();
        let (flows, dns) = e.drain_records();
        assert!(flows
            .iter()
            .any(|f| f.remote_ip == "52.1.1.1".parse::<IpAddr>().unwrap()));
        assert_eq!(dns.len(), 1);
        assert_eq!((dns[0].mac, dns[0].rcode), (cam, 3));
    }

    #[test]
    fn signatures_fingerprints_peers_and_exposures() {
        let mut e = Engine::new(
            RuleSettings {
                learning_minutes: 1,
                ..Default::default()
            },
            OuiDb::load(None),
        );
        let mut set = RuleSet::default();
        set.add_text("built-in", ids::BUILTIN);
        set.build();
        e.ids = Arc::new(set);
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let cam: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();

        // Inbound exploit against the camera -> signature alert on the camera, ATT&CK from classtype.
        let mut x = pkt(t0, gw, cam, "203.0.113.9", "192.168.1.10", 80, false, 300);
        x.net.as_mut().unwrap().payload = b"PUT /SDK/webLanguage HTTP/1.1\r\n".to_vec();
        e.process(&x);
        let a = e
            .alerts
            .iter()
            .find(|a| a.rule == "ids-signature")
            .expect("signature alert");
        assert_eq!(
            (a.device, a.severity, a.mitre_id.as_deref()),
            (Some(cam), Severity::High, Some("T1190"))
        );
        let c = a.context.as_ref().expect("request context");
        assert_eq!(
            (
                c.direction.as_str(),
                c.src_ip.as_deref(),
                c.dst_port,
                c.service.as_deref()
            ),
            ("inbound", Some("203.0.113.9"), Some(80), Some("HTTP"))
        );
        assert!(c
            .payload
            .as_deref()
            .unwrap()
            .starts_with("PUT /SDK/webLanguage"));
        let parts = e.risk_breakdown(&cam);
        assert!(parts
            .iter()
            .any(|p| p.source == "ids-signature" && p.kind == "alert"));
        let total: f64 = parts.iter().map(|p| p.points).sum();
        assert_eq!(total.round().min(100.0) as u32, e.risk_map()[&cam].0);
        e.process(&x);
        assert_eq!(
            e.alerts
                .iter()
                .filter(|a| a.rule == "ids-signature")
                .count(),
            1,
            "throttled"
        );

        // TLS fingerprint learned, then a new one after learning -> fingerprint-change (IoT only).
        let hello = |sni: &str, v13: bool| {
            let mut p = pkt(t0, cam, gw, "192.168.1.10", "52.1.1.1", 443, false, 300);
            let n = p.net.as_mut().unwrap();
            n.tls = crate::fingerprint::client_hello(&crate::fingerprint::tests_support::hello(
                sni, v13,
            ));
            p
        };
        e.process(&hello("a.example", true));
        assert_eq!(e.devices[&cam].baseline.tls.len(), 1);
        let mut late = hello("b.example", false);
        late.ts = t0 + Duration::minutes(2);
        e.process(&late);
        assert!(e.alerts.iter().any(|a| a.rule == "fingerprint-change"));

        // Camera answers Telnet -> exposure finding + risk.
        let mut tel = pkt(t0, cam, gw, "192.168.1.10", "203.0.113.9", 51000, false, 80);
        tel.net.as_mut().unwrap().src_port = Some(23);
        e.process(&tel);
        let f = crate::exposure::assess(&e.devices[&cam], &e.kev);
        assert!(f.iter().any(|x| x.id == "telnet-server"));

        // Peer groups: three cameras with 2 hosts, one with 40.
        for i in 0..4u8 {
            let m: Mac = format!("44:19:b6:00:01:{i:02x}").parse().unwrap();
            let hosts = if i == 3 { 40 } else { 2 };
            for h in 0..hosts {
                e.process(&pkt(
                    t0,
                    m,
                    gw,
                    &format!("192.168.1.{}", 50 + i),
                    &format!("52.9.{i}.{h}"),
                    443,
                    false,
                    100,
                ));
            }
        }
        e.clock = t0 + Duration::minutes(3);
        e.peer_rules();
        let odd: Mac = "44:19:b6:00:01:03".parse().unwrap();
        assert!(e
            .alerts
            .iter()
            .any(|a| a.rule == "peer-anomaly" && a.device == Some(odd)));
        assert!(!e
            .alerts
            .iter()
            .any(|a| a.rule == "peer-anomaly" && a.device != Some(odd)));
    }

    /// Regression: DHCPv6 (546/547) and ephemeral-to-ephemeral UDP between
    /// link-local peers were reported as "unexpected service ports".
    #[test]
    fn no_port_alerts_from_guesswork() {
        let mut e = Engine::new(
            RuleSettings {
                learning_minutes: 1,
                ..Default::default()
            },
            OuiDb::load(None),
        );
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let mac: Mac = "46:48:79:df:94:29".parse().unwrap();
        let peer: Mac = "a0:8a:06:2e:ff:9a".parse().unwrap();
        e.process(&pkt(
            t0,
            mac,
            peer,
            "192.168.1.59",
            "192.168.1.1",
            53,
            false,
            80,
        ));
        let t1 = t0 + Duration::minutes(2);
        let udp = |sp: u16, dp: u16, s: &str, d: &str| {
            let mut p = pkt(t1, mac, peer, s, d, dp, false, 120);
            let n = p.net.as_mut().unwrap();
            n.transport = Transport::Udp;
            n.src_port = Some(sp);
            p
        };
        e.process(&udp(546, 547, "fe80::869:cffb:8384:d373", "fe80::1"));
        e.process(&udp(60000, 55435, "fe80::c01:c48f:693e:59b1", "fe80::2"));
        e.process(&udp(60001, 55435, "192.168.1.59", "192.168.1.77"));
        assert!(
            !e.alerts.iter().any(|a| a.rule == "unexpected-port"),
            "{:?}",
            e.alerts.iter().map(|a| &a.message).collect::<Vec<_>>()
        );
        // A real new service (TCP SYN to 8883) still alerts.
        e.process(&pkt(
            t1,
            mac,
            peer,
            "192.168.1.59",
            "52.1.1.1",
            8883,
            true,
            60,
        ));
        assert!(e
            .alerts
            .iter()
            .any(|a| a.rule == "unexpected-port" && a.port == Some(8883)));
    }

    #[test]
    fn dga_heuristic() {
        for legit in [
            "www.googleusercontent.com",
            "login.microsoftonline.com",
            "d3ag4hukkh62yn.cloudfront.net",
            "api.smartthings.com",
            "r3---sn-ab5l6n7s.googlevideo.com",
            "cloudflareinsights.com",
            "bytefcdn-oversea.com",
            "msftconnecttest.com",
            "Living-Room.local",
            "doubleclickbygoogle.com",
            "d2l.brightspace.com",
            "lightstreamer.com",
            "123formbuilder.com",
            "akamaitechnologies.com",
            "1.168.192.in-addr.arpa",
        ] {
            assert!(!looks_generated(legit), "{legit}");
        }
        for dga in [
            "xj4kq9vbz2lmw8.net",
            "qwhfkzpxlmtrbv.com",
            "a8f3k2l9x0q7.info",
            "kzmvbqxwtrplsd.biz",
        ] {
            assert!(looks_generated(dga), "{dga}");
        }
        assert!(!looks_generated(
            "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
        ));
        // Random 13-character names (typical DGA output) are caught reliably.
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let caught = (0..500)
            .filter(|_| {
                let n: String = (0..13)
                    .map(|_| {
                        char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[rng.gen_range(0..36)])
                    })
                    .collect();
                looks_generated(&format!("{n}.net"))
            })
            .count();
        // Per name; a DGA burst tries dozens, so a device is caught almost surely.
        assert!(caught >= 350, "caught {caught}/500");
    }

    #[test]
    fn base_domains() {
        assert_eq!(base_domain("api.ecobee.com"), "ecobee.com");
        assert_eq!(base_domain("a.b.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(base_domain("localhost"), "localhost");
    }
}
