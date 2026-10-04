//! Device profiling, behavioral baselines and the anomaly-detection rules.
//!
//! Every decoded packet goes through [`Engine::process`]. Per device we keep:
//! * identity: MAC, vendor (OUI), randomized-MAC flag, auto class, user tag
//! * radio: RSSI (last + smoothed), channel, AP role, SSIDs, connection history
//! * traffic: frame counts, tx/rx volume, per-second history, hour-of-day histogram
//! * network behavior: remote destinations (IP + DNS/SNI name), service ports
//! * a **baseline**: everything observed during the first `learning_minutes`
//!   after the device appears. After that, deviations raise alerts.

use crate::model::{is_local_ip, FrameKind, Hint, Mac, PacketInfo, Transport};
use crate::oui::{classify, is_iot_class, ClassHints, OuiDb};
use crate::settings::RuleSettings;
use chrono::{DateTime, Duration, Local, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

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
const INFRA_PORTS: &[u16] = &[53, 67, 68, 123, 137, 138, 1900, 5353, 5355];

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
    #[serde(skip)]
    live: Live,
}

impl Device {
    fn new(mac: Mac, ts: DateTime<Utc>, vendor: Option<String>, learning_minutes: u32) -> Self {
        Device {
            mac,
            vendor,
            randomized: mac.is_local(),
            name: None,
            tag: None,
            notes: String::new(),
            auto_class: "Unknown".into(),
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
            live: Live::default(),
        }
    }

    pub fn class(&self) -> &str {
        self.tag.as_deref().filter(|t| !t.is_empty()).unwrap_or(&self.auto_class)
    }

    pub fn is_iot(&self) -> bool {
        is_iot_class(self.class())
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
                self.connections.push(Connection { bssid, ssid, first_seen: ts, last_seen: ts, frames: 1 });
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
                if self.hostname.is_none() || (n.contains(' ') && !self.hostname.as_deref().unwrap_or("").contains(' ')) {
                    self.hostname = Some(n.clone());
                }
            }
            Hint::VendorClass(v) => self.vendor_class = Some(v.clone()),
            Hint::Service(v) => add(&mut self.services, v),
            Hint::Server(v) | Hint::UserAgent(v) => add(&mut self.banners, v),
        }
    }

    /// Current connected SSID (most recently active association).
    pub fn current_ssid(&self) -> Option<String> {
        self.connections.iter().max_by_key(|c| c.last_seen).and_then(|c| c.ssid.clone())
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
    pub gateway_ip: Option<IpAddr>,
    /// Suppress "new device" alerts while an active discovery scan runs.
    pub quiet_new_until: Option<DateTime<Utc>>,
    pub feed: VecDeque<FeedItem>,
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
            quiet_new_until: None,
            feed: VecDeque::new(),
            ticks: 0,
            self_hostname: None,
        }
    }

    /// Restore devices and alerts saved from a previous session.
    pub fn restore(&mut self, devices: Vec<Device>, alerts: Vec<Alert>, next_id: u64) {
        for d in devices {
            self.devices.insert(d.mac, d);
        }
        self.alerts = alerts.into();
        self.next_alert_id = next_id.max(self.alerts.iter().map(|a| a.id + 1).max().unwrap_or(1));
    }

    /// Reset per-session counters when a new capture starts.
    pub fn begin_session(&mut self, start: Option<DateTime<Utc>>) {
        let now = start.unwrap_or_else(Utc::now);
        self.started = now;
        self.clock = now;
        self.totals = Totals::default();
        self.traffic.clear();
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
        self.traffic.clear();
        self.totals = Totals::default();
        self.dirty = true;
    }

    pub fn drain_fresh(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.fresh)
    }

    fn raise(&mut self, d: Draft) {
        let label = d.device.and_then(|m| self.devices.get(&m)).map(|dev| dev.label());
        let a = Alert {
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
        };
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
            None => self.traffic.push_back(TrafficPoint { t: sec, ..Default::default() }),
            Some(last) if sec > last => {
                let gap = (sec - last).min(TRAFFIC_HISTORY as i64);
                for t in (sec - gap + 1)..=sec {
                    self.traffic.push_back(TrafficPoint { t, ..Default::default() });
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
        if self.ticks.is_multiple_of(30) {
            self.prune();
        }
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
            let mut by_age: Vec<(DateTime<Utc>, Mac)> =
                self.devices.values().filter(|d| d.tag.is_none() && d.name.is_none()).map(|d| (d.last_seen, d.mac)).collect();
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
            let domains: Vec<&str> = d.destinations.values().filter_map(|x| x.domain.as_deref()).collect();
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

        // Learn names for IPs before attributing traffic.
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
        }

        self.push_feed(p);
        let quiet_new = self.quiet_new_until.is_some_and(|q| ts <= q);

        // ARP: authoritative MAC <-> IP binding for LAN devices.
        if let Some(a) = &p.arp {
            if !self.devices.contains_key(&a.sender_mac) {
                let vendor = self.oui.lookup(&a.sender_mac);
                self.devices.insert(a.sender_mac, Device::new(a.sender_mac, ts, vendor, self.rules.learning_minutes));
                self.dirty = true;
            }
            let gw = self.gateway_ip;
            if let Some(d) = self.devices.get_mut(&a.sender_mac) {
                let ip = IpAddr::V4(a.sender_ip);
                d.ips.insert(ip);
                d.touch(ts);
                if gw == Some(ip) {
                    d.is_gateway = true;
                }
            }
        }

        let ap_ssid = p
            .bssid
            .and_then(|b| self.devices.get(&b))
            .and_then(|ap| ap.ssids.iter().next().cloned());
        let warmed_up = ts >= self.started + Duration::minutes(self.rules.learning_minutes as i64);
        let mut drafts: Vec<Draft> = Vec::new();
        let rules = &self.rules;
        let src = p.src.filter(Mac::is_unicast);
        let dst = p.dst.filter(|m| m.is_unicast() && Some(*m) != src);
        let on_net_frame = matches!(p.kind, FrameKind::Data | FrameKind::Ethernet);

        // ---- transmitter ----
        if let Some(mac) = src {
            if p.kind != FrameKind::Control && !self.devices.contains_key(&mac) {
                let vendor = self.oui.lookup(&mac);
                self.devices.insert(mac, Device::new(mac, ts, vendor, rules.learning_minutes));
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
                            severity: if d.randomized { Severity::Info } else { Severity::Low },
                            rule: "new-device",
                            title: "New device joined the network".into(),
                            message: format!(
                                "{}{} ({}) started sending traffic{}.",
                                mac,
                                d.hostname.as_ref().map(|h| format!(" \"{h}\"")).unwrap_or_default(),
                                d.vendor.as_deref().unwrap_or(if d.randomized { "randomized MAC" } else { "unknown vendor" }),
                                ap_ssid.as_ref().map(|s| format!(" on \"{s}\"")).unwrap_or_default()
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
                self.devices.insert(mac, Device::new(mac, ts, vendor, rules.learning_minutes));
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
        for mac in [src, dst].into_iter().flatten() {
            if let Some(d) = self.devices.get_mut(&mac) {
                let syn = p.net.as_ref().is_some_and(|n| n.tcp_syn) && Some(mac) == src;
                rate_rules(d, ts, len, syn, rules, &mut drafts);
            }
        }

        // ---- network layer: who is talking to whom ----
        if let Some(n) = &p.net {
            let (sl, dl) = (is_local_ip(&n.src_ip), is_local_ip(&n.dst_ip));
            let attribution = match (sl, dl) {
                (true, false) => Some((src, n.src_ip, n.dst_ip, true)),
                (false, true) => Some((dst, n.dst_ip, n.src_ip, false)),
                (true, true) => Some((src, n.src_ip, n.dst_ip, true)),
                (false, false) => None,
            };
            // The L2 peer of internet-bound traffic is the router.
            let gw_mac = match (sl, dl) {
                (true, false) => dst,
                (false, true) => src,
                _ => None,
            };
            if let Some(g) = gw_mac.and_then(|m| self.devices.get_mut(&m)) {
                if !g.is_gateway {
                    g.is_gateway = true;
                    self.dirty = true;
                }
            }
            if let Some((Some(mac), local_ip, remote, outbound)) = attribution {
                if let Some(d) = self.devices.get_mut(&mac) {
                    if !local_ip.is_unspecified() && !local_ip.is_multicast() && is_local_ip(&local_ip) {
                        d.ips.insert(local_ip);
                    }
                    let remote_is_group = match remote {
                        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.octets()[3] == 255,
                        IpAddr::V6(v6) => v6.is_multicast(),
                    };
                    if !remote_is_group && !remote.is_unspecified() {
                        let (lp, rp) = if outbound { (n.src_port, n.dst_port) } else { (n.dst_port, n.src_port) };
                        let syn_out = outbound && n.tcp_syn;
                        // The remote port is a "service" when this device is the client.
                        let service = match (n.transport, lp, rp) {
                            (Transport::Tcp, _, Some(r)) if syn_out => Some(r),
                            (Transport::Tcp | Transport::Udp, Some(l), Some(r)) if r < l || r < 1024 => Some(r),
                            _ => None,
                        };
                        let domain = self.dns.get(&remote).cloned();
                        net_rules(d, NetEvent { remote, domain, service, outbound, bytes: len, ts }, rules, &mut drafts);
                    }
                }
            }
        }

        for d in drafts {
            self.raise(d);
        }
    }

    // -- views & user actions ----------------------------------------------

    pub fn summaries(&self) -> Vec<DeviceSummary> {
        let open: HashMap<Mac, usize> = self.alerts.iter().filter(|a| !a.acknowledged).filter_map(|a| a.device).fold(
            HashMap::new(),
            |mut m, mac| {
                *m.entry(mac).or_default() += 1;
                m
            },
        );
        let now_sec = self.clock.timestamp();
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
                ssid: if d.is_ap { d.ssids.iter().next().cloned() } else { d.current_ssid() },
                ips: d.ips.iter().copied().collect(),
                destinations: d.destinations.len(),
                learning: d.baseline.learning(self.clock),
                open_alerts: open.get(&d.mac).copied().unwrap_or(0),
                recent_bytes: d.live.history.iter().filter(|(t, _)| *t > now_sec - WINDOW_SECS).map(|(_, b)| b).sum(),
                hostname: d.hostname.clone(),
                is_gateway: d.is_gateway,
                is_self: self.is_self(d),
                services: d.services.len(),
            })
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        v
    }

    pub fn detail(&self, mac: &Mac) -> Option<DeviceDetail> {
        let d = self.devices.get(mac)?;
        let b = &d.baseline;
        let total = (b.learning_until - b.learning_started).num_milliseconds().max(1) as f64;
        let done = (self.clock - b.learning_started).num_milliseconds() as f64;
        Some(DeviceDetail {
            label: d.label(),
            class: d.class().to_string(),
            is_iot: d.is_iot(),
            learning: b.learning(self.clock),
            learning_progress: (done / total).clamp(0.0, 1.0),
            history: d.live.history.iter().copied().collect(),
            alerts: self.alerts.iter().rev().filter(|a| a.device == Some(*mac)).take(100).cloned().collect(),
            is_self: self.is_self(d),
            device: d.clone(),
        })
    }

    pub fn update_device(&mut self, mac: &Mac, name: Option<String>, tag: Option<String>, notes: Option<String>) -> bool {
        let Some(d) = self.devices.get_mut(mac) else { return false };
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
        let Some(d) = self.devices.get_mut(mac) else { return false };
        d.baseline = Baseline::new(now, minutes);
        d.alerted_ports.clear();
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
        for a in self.alerts.iter_mut() {
            if id.is_none_or(|i| i == a.id) {
                a.acknowledged = true;
            }
        }
        self.dirty = true;
    }

    /// "Mark as normal": fold the alert's subject into the device baseline.
    pub fn accept(&mut self, id: u64) -> Result<(), String> {
        let a = self.alerts.iter_mut().find(|a| a.id == id).ok_or("alert not found")?;
        a.acknowledged = true;
        let (mac, remote, port, value, ts, rule) = (a.device, a.remote.clone(), a.port, a.value, a.ts, a.rule.clone());
        self.dirty = true;
        let Some(d) = mac.and_then(|m| self.devices.get_mut(&m)) else { return Ok(()) };
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
            _ => {}
        }
        Ok(())
    }

    fn push_feed(&mut self, p: &PacketInfo) {
        let (protocol, info) = describe(p, &self.dns);
        let seq = self.totals.packets;
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
    bytes: u64,
    ts: DateTime<Utc>,
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
    let take = if labels[n - 1].len() == 2 && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "ac" | "edu") { 3 } else { 2 };
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
    let external = !is_local_ip(&e.remote);
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
    let dest = d.destinations.entry(key.clone()).or_insert_with(|| Destination {
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
            || dest.domain.as_deref().is_some_and(|h| d.baseline.domains.contains(&base_domain(h)));
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
            let name = dest.domain.clone().map(|h| format!(" ({h})")).unwrap_or_else(|| " (no DNS name seen)".into());
            let port = dest.ports.iter().next().copied();
            out.push(Draft {
                severity: if iot { Severity::High } else { Severity::Medium },
                rule: "new-destination",
                title: format!("{label} communicating with unknown external host"),
                message: format!(
                    "Contacted {}{}{} — not part of the device's learned baseline of {} host(s).",
                    e.remote,
                    name,
                    port.map(|p| format!(" on port {p}/{}", service_name(p))).unwrap_or_default(),
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
        {
            d.alerted_ports.insert(port);
            out.push(Draft {
                severity: if iot { Severity::High } else { Severity::Medium },
                rule: "unexpected-port",
                title: format!("{label} using an unexpected service port"),
                message: format!(
                    "Connection to {}:{port} ({}). Baseline ports: {}.",
                    e.remote,
                    service_name(port),
                    if d.baseline.ports.is_empty() {
                        "none".to_string()
                    } else {
                        d.baseline.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
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

fn rate_rules(d: &mut Device, ts: DateTime<Utc>, bytes: u64, syn: bool, rules: &RuleSettings, out: &mut Vec<Draft>) {
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
        let threshold = ((d.baseline.peak_window_bytes as f64) * rules.spike_factor).max(rules.spike_min_bytes as f64);
        if d.live.win_bytes as f64 > threshold && sec - d.live.spike_alerted >= RATE_ALERT_COOLDOWN {
            d.live.spike_alerted = sec;
            let ratio = d.live.win_bytes as f64 / (d.baseline.peak_window_bytes.max(1)) as f64;
            out.push(Draft {
                severity: if iot { Severity::High } else { Severity::Medium },
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
        let outside_profile =
            b.hours_valid() && !b.hours[hour] && !b.hours[(hour + 23) % 24] && !b.hours[(hour + 1) % 24];
        let quiet = rules.quiet_hours_enabled && rules.in_quiet_hours(hour as u32);
        let heavy = d.live.hour_bytes >= rules.spike_min_bytes || d.live.hour_syns >= rules.syn_threshold;
        if (outside_profile || quiet) && heavy {
            d.live.unusual_alerted_hour = hour_key;
            out.push(Draft {
                severity: if iot { Severity::High } else { Severity::Medium },
                rule: "unusual-time",
                title: format!("{label}: heavy activity at an unusual time"),
                message: format!(
                    "{} and {} connection attempts this hour ({:02}:00) — {}.",
                    fmt_bytes(d.live.hour_bytes),
                    d.live.hour_syns,
                    hour,
                    if quiet { "inside configured quiet hours" } else { "outside the device's normal active hours" }
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
            let ips: Vec<String> = n.dns_answers.iter().take(3).map(|(_, ip)| ip.to_string()).collect();
            return ("DNS".into(), format!("{q} → {}", ips.join(", ")));
        }
        if let Some(sni) = &n.sni {
            return ("TLS".into(), format!("ClientHello → {sni} ({}:{})", n.dst_ip, n.dst_port.unwrap_or(0)));
        }
        if let Some(h) = n.hints.first() {
            let (proto, txt) = match h {
                Hint::Hostname(v) if n.dst_port == Some(67) => ("DHCP", format!("Request from host \"{v}\"")),
                Hint::VendorClass(v) => ("DHCP", format!("Request, vendor class \"{v}\"")),
                Hint::Hostname(v) => ("mDNS", format!("Announces \"{v}\"")),
                Hint::Service(v) => ("mDNS", format!("Advertises service {v}")),
                Hint::Server(v) => ("SSDP", format!("UPnP device: {v}")),
                Hint::UserAgent(v) => ("HTTP", format!("User-Agent: {v}")),
            };
            return (proto.into(), txt);
        }
        let port_name = |p: Option<u16>| p.map(service_name).filter(|s| *s != "unknown service");
        let proto = match n.transport {
            Transport::Tcp => port_name(n.dst_port).or(port_name(n.src_port)).unwrap_or("TCP"),
            Transport::Udp => port_name(n.dst_port).or(port_name(n.src_port)).unwrap_or("UDP"),
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
            format!("{} → {}{}", ep(&n.src_ip, n.src_port), ep(&n.dst_ip, n.dst_port), if n.tcp_syn { " [SYN]" } else { "" }),
        );
    }
    let ssid = |p: &PacketInfo| p.ssid.as_deref().map(|s| format!("“{s}”")).unwrap_or_else(|| "(hidden/any)".into());
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

    #[allow(clippy::too_many_arguments)]
    fn pkt(ts: DateTime<Utc>, src: Mac, dst: Mac, sip: &str, dip: &str, dport: u16, syn: bool, len: u32) -> PacketInfo {
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
        });
        p
    }

    #[test]
    fn baseline_then_new_destination_and_risky_port() {
        let mut e = Engine::new(RuleSettings { learning_minutes: 1, ..Default::default() }, OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let cam: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        e.process(&pkt(t0, cam, gw, "192.168.1.10", "52.1.1.1", 443, true, 200));
        e.tick(None);
        assert!(e.devices[&cam].is_iot());
        assert!(e.alerts.is_empty());

        // after learning: known host stays quiet, new host alerts
        let t1 = t0 + Duration::minutes(2);
        e.process(&pkt(t1, cam, gw, "192.168.1.10", "52.1.1.1", 443, true, 200));
        assert!(e.alerts.is_empty());
        e.process(&pkt(t1, cam, gw, "192.168.1.10", "185.220.101.4", 443, true, 200));
        assert_eq!(e.alerts.len(), 1);
        assert_eq!(e.alerts[0].rule, "new-destination");
        assert_eq!(e.alerts[0].severity, Severity::High);

        e.process(&pkt(t1, cam, gw, "192.168.1.10", "203.0.113.5", 23, true, 60));
        assert!(e.alerts.iter().any(|a| a.rule == "risky-port" && a.severity == Severity::Critical));

        // accepting folds it into the baseline
        let id = e.alerts[0].id;
        e.accept(id).unwrap();
        assert!(e.devices[&cam].baseline.destinations.contains(&"185.220.101.4".parse().unwrap()));
    }

    #[test]
    fn connection_burst() {
        let mut e = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let t0 = Utc::now();
        e.begin_session(Some(t0));
        let plug: Mac = "24:0a:c4:00:00:02".parse().unwrap();
        let gw: Mac = "50:c7:bf:00:00:01".parse().unwrap();
        for i in 0..60 {
            e.process(&pkt(t0, plug, gw, "192.168.1.11", &format!("198.51.100.{i}"), 8080, true, 60));
        }
        assert!(e.alerts.iter().any(|a| a.rule == "connection-burst"));
    }

    #[test]
    fn base_domains() {
        assert_eq!(base_domain("api.ecobee.com"), "ecobee.com");
        assert_eq!(base_domain("a.b.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(base_domain("localhost"), "localhost");
    }
}
