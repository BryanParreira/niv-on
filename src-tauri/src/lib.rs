//! Niv.ON — network & IoT behavior monitor.
//!
//! Tauri backend: owns the analysis engine, runs capture sessions and exposes
//! commands/events to the React dashboard.

mod adapters;
mod capture;
mod engine;
mod evidence;
mod exposure;
mod fingerprint;
mod ids;
mod intel;
mod model;
mod netif;
mod oui;
mod parser;
mod platform;
mod playbook;
mod report;
mod settings;
mod simulator;
mod store;
mod workspace;

use capture::{CaptureStats, Session, SessionInfo};
use chrono::{DateTime, Utc};
use engine::{
    Alert, Device, DeviceDetail, DeviceSummary, Engine, FeedItem, Severity, Totals, TrafficPoint,
};
use model::Mac;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use settings::{Settings, Source};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use workspace::{NetKind, NetMeta, NetworkStore, NetworkSummary, DEMO_ID};

const STATE_FILE: &str = "niv-state.json";

pub struct AppState {
    engine: Arc<Mutex<Engine>>,
    settings: Mutex<Settings>,
    session: Mutex<Option<Session>>,
    stats: Arc<Mutex<CaptureStats>>,
    data_dir: PathBuf,
    networks: Mutex<NetworkStore>,
    store: Option<Arc<store::Store>>,
}

/// What gets written to disk: settings, device profiles + baselines, alerts.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Persisted {
    settings: Settings,
    /// Per-network workspaces.
    networks: NetworkStore,
    // Pre-workspace format, read once for migration.
    #[serde(skip_serializing)]
    devices: Vec<Device>,
    #[serde(skip_serializing)]
    alerts: Vec<Alert>,
    #[serde(skip_serializing)]
    next_alert_id: u64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CurrentNetwork {
    id: String,
    name: String,
    kind: NetKind,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AlertCounts {
    open: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    session: Option<SessionInfo>,
    channel: Option<u16>,
    stats: CaptureStats,
    totals: Totals,
    clock: DateTime<Utc>,
    devices: usize,
    active_devices: usize,
    alerts: AlertCounts,
    /// Last complete second.
    packets_per_sec: u64,
    bytes_per_sec: u64,
    data_dir: String,
    oui_entries: usize,
    network: Option<CurrentNetwork>,
    /// Raw packets are buffered (live / file / remote), so evidence pcaps can be saved.
    evidence: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Tick {
    status: serde_json::Value,
    traffic: Vec<TrafficPoint>,
}

fn build_status(st: &AppState) -> Status {
    let network = st.networks.lock().current_record().map(|r| CurrentNetwork {
        id: r.id.clone(),
        name: r.name.clone(),
        kind: r.kind.clone(),
    });
    let session = st.session.lock();
    let eng = st.engine.lock();
    let mut alerts = AlertCounts::default();
    for a in eng.alerts.iter().filter(|a| !a.acknowledged) {
        alerts.open += 1;
        match a.severity {
            Severity::Critical => alerts.critical += 1,
            Severity::High => alerts.high += 1,
            Severity::Medium => alerts.medium += 1,
            Severity::Low => alerts.low += 1,
            Severity::Info => alerts.info += 1,
        }
    }
    let active_cutoff = eng.clock - chrono::Duration::seconds(60);
    let last = eng.traffic.iter().rev().nth(1).cloned().unwrap_or_default();
    Status {
        running: session.is_some(),
        channel: session
            .as_ref()
            .map(|s| s.channel.load(Ordering::Relaxed))
            .filter(|c| *c > 0),
        session: session.as_ref().map(|s| s.info.clone()),
        stats: st.stats.lock().clone(),
        totals: eng.totals.clone(),
        clock: eng.clock,
        devices: eng.devices.len(),
        active_devices: eng
            .devices
            .values()
            .filter(|d| d.last_seen >= active_cutoff)
            .count(),
        alerts,
        packets_per_sec: last.packets,
        bytes_per_sec: last.bytes,
        data_dir: st.data_dir.display().to_string(),
        oui_entries: eng.oui.external_entries,
        network,
        evidence: evidence::available(),
    }
}

fn save_state(st: &AppState) -> Result<(), String> {
    let p = {
        let mut eng = st.engine.lock();
        eng.dirty = false;
        let networks = st.networks.lock().persistable(&eng);
        Persisted {
            settings: st.settings.lock().clone(),
            networks,
            ..Default::default()
        }
    };
    std::fs::create_dir_all(&st.data_dir).map_err(|e| e.to_string())?;
    let tmp = st.data_dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(&p).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, st.data_dir.join(STATE_FILE)).map_err(|e| e.to_string())
}

fn parse_mac(s: &str) -> Result<Mac, String> {
    s.parse()
}

fn current_net(st: &AppState) -> String {
    st.networks
        .lock()
        .current
        .clone()
        .unwrap_or_else(|| "none".into())
}

/// Recompile threat intel (watchlist + enabled feeds) and the KEV catalog.
fn reload_intel(st: &AppState) {
    let s = st.settings.lock().clone();
    let i = intel::load(&st.data_dir, &s.data.feeds, &s.rules.watchlist);
    let kev = intel::Kev::load(&st.data_dir);
    let mut eng = st.engine.lock();
    eng.set_intel(i);
    eng.kev = Arc::new(kev);
}

fn rules_dir(data: &std::path::Path) -> PathBuf {
    data.join("rules")
}

/// Built-in signatures plus every imported `.rules` file.
fn load_rules(data: &std::path::Path) -> ids::RuleSet {
    let mut set = ids::RuleSet::default();
    set.add_text("built-in", ids::BUILTIN);
    let mut files: Vec<PathBuf> = std::fs::read_dir(rules_dir(data))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "rules"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    for f in files {
        if let Ok(text) = std::fs::read_to_string(&f) {
            set.add_text(
                &f.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                &text,
            );
        }
    }
    set.build();
    set
}

fn reload_rules(st: &AppState) -> usize {
    let set = load_rules(&st.data_dir);
    let n = set.rules.len();
    st.engine.lock().ids = Arc::new(set);
    n
}

/// Write closed connections / DNS answers to the event store.
fn persist_records(st: &AppState) {
    let (flows, dns) = st.engine.lock().drain_records();
    if let Some(store) = &st.store {
        if let Err(e) = store.insert(&current_net(st), &flows, &dns) {
            eprintln!("event store: {e}");
        }
    }
}

fn save_alert_evidence(st: &AppState, id: u64) -> Result<String, String> {
    let (device, rule) = {
        let eng = st.engine.lock();
        let a = eng
            .alerts
            .iter()
            .find(|a| a.id == id)
            .ok_or("alert not found")?;
        if let Some(p) = &a.evidence {
            return Ok(p.clone());
        }
        (a.device, a.rule.clone())
    };
    let path = evidence::save(&format!("alert-{id}-{rule}"), device)?
        .display()
        .to_string();
    st.engine.lock().set_evidence(id, path.clone());
    Ok(path)
}

/// Fresh alerts: automatic evidence, then response playbooks. Runs on its
/// own thread so a slow script never stalls packet analysis.
pub(crate) fn on_alerts(app: &AppHandle, fresh: Vec<Alert>) {
    let app = app.clone();
    std::thread::spawn(move || {
        use tauri_plugin_notification::NotificationExt;
        let st = app.state::<AppState>();
        let cfg = st.settings.lock().clone();
        for a in &fresh {
            if cfg.data.auto_evidence
                && a.severity >= Severity::High
                && a.device.is_some()
                && evidence::available()
            {
                let _ = save_alert_evidence(&st, a.id);
            }
        }
        for pb in &cfg.playbooks {
            for a in &fresh {
                let (iot, ip, label) = {
                    let eng = st.engine.lock();
                    let d = a.device.and_then(|m| eng.devices.get(&m));
                    (
                        d.is_some_and(|d| d.is_iot()),
                        d.and_then(|d| d.ips.iter().find(|i| i.is_ipv4()).map(|i| i.to_string()))
                            .unwrap_or_default(),
                        a.device_label.clone().unwrap_or_default(),
                    )
                };
                if !pb.matches(a, iot) {
                    continue;
                }
                let mut results = vec![];
                let mut ok = true;
                for action in &pb.actions {
                    let r: Result<String, String> = match action {
                        playbook::Action::Notify => app
                            .notification()
                            .builder()
                            .title(format!("Niv.ON · {:?}", a.severity))
                            .body(format!("{}\n{}", a.title, label))
                            .show()
                            .map(|_| "notified".to_string())
                            .map_err(|e| e.to_string()),
                        playbook::Action::Evidence => {
                            save_alert_evidence(&st, a.id).map(|p| format!("evidence {p}"))
                        }
                        playbook::Action::Investigate { owner } => {
                            let o = if owner.trim().is_empty() {
                                "automation".to_string()
                            } else {
                                owner.clone()
                            };
                            st.engine.lock().update_alerts(
                                &[a.id],
                                Some(engine::AlertStatus::InProgress),
                                Some(o.clone()),
                                Some(format!("Opened by playbook “{}”.", pb.name)),
                            );
                            Ok(format!("investigation assigned to {o}"))
                        }
                        playbook::Action::Tag { tag } => match a.device {
                            Some(m) => {
                                st.engine.lock().update_device(
                                    &m,
                                    None,
                                    Some(tag.clone()),
                                    None,
                                    None,
                                );
                                Ok(format!("tagged “{tag}”"))
                            }
                            None => Err("alert has no device".into()),
                        },
                        playbook::Action::Priority { priority } => match a.device {
                            Some(m) => {
                                st.engine.lock().update_device(
                                    &m,
                                    None,
                                    None,
                                    None,
                                    Some(*priority),
                                );
                                Ok(format!("priority → {priority:?}"))
                            }
                            None => Err("alert has no device".into()),
                        },
                        playbook::Action::Script { path } => playbook::run_script(
                            path,
                            &[
                                ("NIV_ALERT_ID", a.id.to_string()),
                                ("NIV_RULE", a.rule.clone()),
                                ("NIV_SEVERITY", format!("{:?}", a.severity).to_lowercase()),
                                ("NIV_TITLE", a.title.clone()),
                                ("NIV_MESSAGE", a.message.clone()),
                                (
                                    "NIV_DEVICE_MAC",
                                    a.device.map(|m| m.to_string()).unwrap_or_default(),
                                ),
                                ("NIV_DEVICE_IP", ip.clone()),
                                ("NIV_DEVICE_LABEL", label.clone()),
                                ("NIV_REMOTE", a.remote.clone().unwrap_or_default()),
                            ],
                        ),
                    };
                    match r {
                        Ok(m) => results.push(m),
                        Err(e) => {
                            ok = false;
                            results.push(format!("failed: {e}"));
                        }
                    }
                }
                playbook::record(playbook::RunLog {
                    ts: Utc::now(),
                    playbook: pb.name.clone(),
                    alert_id: a.id,
                    alert_title: a.title.clone(),
                    results,
                    ok,
                });
            }
        }
    });
}

fn open_with_os(path: &str, reveal: bool) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return Err(format!("{path} no longer exists"));
    }
    let status = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        if reveal {
            c.arg("-R");
        }
        c.arg(p).status()
    } else if cfg!(windows) {
        if reveal {
            std::process::Command::new("explorer")
                .arg(format!("/select,{}", p.display()))
                .status()
        } else {
            std::process::Command::new("cmd")
                .args(["/C", "start", ""])
                .arg(p)
                .status()
        }
    } else {
        let target = if reveal { p.parent().unwrap_or(p) } else { p };
        std::process::Command::new("xdg-open").arg(target).status()
    };
    status.map(|_| ()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn list_interfaces() -> Result<Vec<netif::Interface>, String> {
    tauri::async_runtime::spawn_blocking(netif::list)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn check_access() -> Result<netif::Access, String> {
    tauri::async_runtime::spawn_blocking(netif::check_access)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn fix_access() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(netif::fix_access)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_interface(
    name: String,
    monitor: bool,
    promiscuous: bool,
) -> Result<netif::TestResult, String> {
    tauri::async_runtime::spawn_blocking(move || netif::test_interface(&name, monitor, promiscuous))
        .await
        .map_err(|e| e.to_string())
}

/// Active discovery: ARP-sweep the subnet of the live interface.
#[tauri::command]
async fn scan_network(st: State<'_, AppState>) -> Result<String, String> {
    let (iface, running_live) = {
        let s = st.session.lock();
        let info = s.as_ref().map(|s| s.info.clone());
        (
            info.as_ref().and_then(|i| i.interface.clone()),
            info.is_some_and(|i| i.source == Source::Live && !i.monitor_mode_active()),
        )
    };
    let iface = iface.filter(|_| running_live).ok_or("Start a live capture (managed mode, not monitor) first — replies are collected by the running capture.")?;
    let ifs = netif::list()?;
    let info = ifs.iter().find(|i| i.name == iface);
    let own = info
        .and_then(|i| i.mac.as_deref())
        .and_then(netif::parse_mac_str)
        .or_else(|| {
            // Fall back to the MAC we have seen using this interface's IP.
            let eng = st.engine.lock();
            let ips: Vec<std::net::IpAddr> = info.map(|i| i.ipv4.iter().filter_map(|a| a.parse().ok()).collect()).unwrap_or_default();
            eng.devices.values().find(|d| d.ips.iter().any(|ip| ips.contains(ip))).map(|d| d.mac.0)
        })
        .ok_or("Could not determine this interface's MAC address yet — let the capture run a few seconds and retry.")?;
    {
        let mut eng = st.engine.lock();
        eng.quiet_new_until = Some(Utc::now() + chrono::Duration::seconds(30));
    }
    let n = tauri::async_runtime::spawn_blocking(move || netif::arp_sweep(&iface, own))
        .await
        .map_err(|e| e.to_string())??;
    Ok(format!(
        "Sent {n} ARP requests. Devices that answer appear in the device list within seconds."
    ))
}

/// The interface's IPv4 subnet plus the /64 of each global IPv6 address:
/// hosts in them are LAN peers even when their addresses are public.
fn lan_nets(i: &netif::Interface) -> Vec<model::IpNet> {
    let mut v: Vec<model::IpNet> = i.network.iter().filter_map(|n| n.parse().ok()).collect();
    for a in i
        .ipv6
        .iter()
        .filter_map(|a| a.split('%').next()?.parse::<std::net::IpAddr>().ok())
    {
        if let std::net::IpAddr::V6(v6) = a {
            let s0 = v6.segments()[0];
            let global = (s0 & 0xe000) == 0x2000 || (s0 & 0xfe00) == 0xfc00;
            // Anchor at the network address so addresses in one /64 dedupe.
            let net = model::IpNet::new(
                std::net::IpAddr::V6((u128::from(v6) & (u128::MAX << 64)).into()),
                64,
            );
            if global && !v.contains(&net) {
                v.push(net);
            }
        }
    }
    v
}

fn local_hostname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    // "Mac-mini.lan" / "host.local" -> "Mac-mini"
    let h = String::from_utf8_lossy(&out.stdout)
        .trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string();
    (!h.is_empty()).then_some(h)
}

/// Download the IEEE MAC vendor registry (~38k vendors) into the data folder.
#[tauri::command]
async fn update_vendor_db(st: State<'_, AppState>) -> Result<String, String> {
    let dir = st.data_dir.clone();
    let path = dir.join("oui.csv");
    let tmp = dir.join("oui.csv.download");
    let tmp2 = tmp.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let curl = std::process::Command::new(if cfg!(windows) { "curl.exe" } else { "curl" })
            .args(["-fsSL", "--max-time", "120", "-A", "Mozilla/5.0 (Niv.ON vendor update)", "-o"])
            .arg(&tmp2)
            .arg(oui::IEEE_URL)
            .status();
        match curl {
            Ok(s) if s.success() => Ok(()),
            _ if cfg!(windows) => {
                let ps = format!(
                    "Invoke-WebRequest -UseBasicParsing -UserAgent 'Mozilla/5.0' -Uri '{}' -OutFile '{}'",
                    oui::IEEE_URL,
                    tmp2.display()
                );
                let s = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &ps]).status().map_err(|e| e.to_string())?;
                if s.success() { Ok(()) } else { Err("download failed".into()) }
            }
            Ok(_) => Err("Download failed — check the internet connection.".into()),
            Err(e) => Err(format!("curl not available: {e}")),
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    let size = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
    if size < 100_000 {
        let _ = std::fs::remove_file(&tmp);
        return Err("Downloaded file looks wrong (too small) — the IEEE site may be blocking requests; try again later.".into());
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    let db = oui::OuiDb::load(Some(&dir));
    let n = db.external_entries;
    {
        let mut eng = st.engine.lock();
        eng.oui = db;
        eng.refresh_vendors();
    }
    Ok(format!(
        "Vendor database updated: {n} manufacturers. Device vendors refreshed."
    ))
}

#[tauri::command]
fn get_feed(st: State<AppState>, after: Option<u64>) -> Vec<FeedItem> {
    let eng = st.engine.lock();
    let after = after.unwrap_or(0);
    eng.feed.iter().filter(|f| f.seq > after).cloned().collect()
}

/// Quick switch from the top bar: change source/interface and (re)start.
#[tauri::command]
fn switch_source(
    app: AppHandle,
    st: State<AppState>,
    source: Source,
    interface: Option<String>,
    monitor_mode: Option<bool>,
) -> Result<SessionInfo, String> {
    {
        let mut s = st.settings.lock();
        s.capture.source = source;
        if interface.is_some() {
            s.capture.interface = interface;
        }
        if let Some(m) = monitor_mode {
            s.capture.monitor_mode = m;
        }
    }
    let _ = save_state(&st);
    start_capture(app, st)
}

#[tauri::command]
fn get_settings(st: State<AppState>) -> Settings {
    st.settings.lock().clone()
}

#[tauri::command]
fn save_settings(st: State<AppState>, settings: Settings) -> Result<(), String> {
    st.engine.lock().set_rules(settings.rules.clone());
    *st.settings.lock() = settings;
    reload_intel(&st);
    save_state(&st)
}

#[tauri::command]
fn start_capture(app: AppHandle, st: State<AppState>) -> Result<SessionInfo, String> {
    if let Some(s) = st.session.lock().take() {
        s.stop();
    }
    st.engine.lock().flush_flows();
    persist_records(&st);
    let cfg = st.settings.lock().clone();
    if cfg.capture.source == Source::Simulator {
        if let Some(store) = &st.store {
            store.delete_network(DEMO_ID); // every demo run starts clean
        }
    }
    {
        // Know who "we" are, so the UI can mark this computer and the router.
        let mut eng = st.engine.lock();
        eng.reset_network_identity();
        eng.self_hostname = local_hostname();
        let mut meta = None;
        let mut fresh = false;
        match cfg.capture.source {
            Source::Live => {
                if let Some(i) = netif::list().ok().and_then(|l| {
                    l.into_iter()
                        .find(|i| Some(&i.name) == cfg.capture.interface.as_ref())
                }) {
                    eng.self_macs
                        .extend(i.mac.as_deref().and_then(|m| m.parse::<Mac>().ok()));
                    eng.self_ips.extend(
                        i.ipv4
                            .iter()
                            .chain(i.ipv6.iter())
                            .filter_map(|a| a.parse::<std::net::IpAddr>().ok()),
                    );
                    eng.gateway_ip = i.gateway.as_deref().and_then(|g| g.parse().ok());
                    eng.lan_nets = lan_nets(&i);
                    // Which network is this? Its router decides the workspace.
                    let id = netif::identify(&i);
                    meta = Some(NetMeta {
                        id: id.id,
                        name: id.name,
                        kind: NetKind::Live,
                        interface: Some(i.name.clone()),
                        subnet: id.subnet,
                        gateway_mac: id.gateway_mac,
                        ssid: id.ssid,
                    });
                }
            }
            Source::Simulator => {
                fresh = true; // every demo starts clean so the learning phase and attacks replay
                eng.lan_nets = vec!["192.168.1.0/24".parse().expect("valid CIDR")];
                eng.gateway_ip = Some(std::net::IpAddr::V4(simulator::GATEWAY_IP.into()));
                meta = Some(NetMeta {
                    id: DEMO_ID.into(),
                    name: "Demo · simulated smart home".into(),
                    kind: NetKind::Demo,
                    interface: None,
                    subnet: Some("192.168.1.0/24".into()),
                    gateway_mac: Some("50:c7:bf:4e:21:01".into()),
                    ssid: Some("HomeNet".into()),
                });
            }
            Source::Remote => {
                let r = &cfg.capture.remote;
                let host = r.host.trim();
                if !host.is_empty() {
                    meta = Some(NetMeta {
                        id: format!("remote:{host}:{}", r.iface.trim()),
                        name: format!("Sensor · {host} ({})", r.iface.trim()),
                        kind: NetKind::Live,
                        interface: Some(format!("{host}:{}", r.iface.trim())),
                        subnet: None,
                        gateway_mac: None,
                        ssid: None,
                    });
                }
            }
            Source::File => {
                if let Some(path) = cfg.capture.file_path.as_deref() {
                    fresh = true; // a replay is a self-contained analysis
                    let name = std::path::Path::new(path)
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.into());
                    meta = Some(NetMeta {
                        id: format!("file:{path}"),
                        name: format!("File · {name}"),
                        kind: NetKind::File,
                        interface: None,
                        subnet: None,
                        gateway_mac: None,
                        ssid: None,
                    });
                }
            }
        }
        if let Some(m) = meta {
            st.networks.lock().activate(&mut eng, m, fresh);
        }
    }
    let _ = save_state(&st);
    let session = capture::start(
        &cfg.capture,
        cfg.rules.learning_minutes,
        st.engine.clone(),
        st.stats.clone(),
        app,
    )?;
    let info = session.info.clone();
    *st.session.lock() = Some(session);
    Ok(info)
}

#[tauri::command]
fn stop_capture(st: State<AppState>) -> Result<(), String> {
    if let Some(s) = st.session.lock().take() {
        s.stop();
    }
    st.engine.lock().flush_flows();
    persist_records(&st);
    save_state(&st)
}

#[tauri::command]
fn get_status(st: State<AppState>) -> Status {
    build_status(&st)
}

#[tauri::command]
fn get_traffic(st: State<AppState>) -> Vec<TrafficPoint> {
    st.engine.lock().traffic.iter().cloned().collect()
}

#[tauri::command]
fn get_devices(st: State<AppState>) -> Vec<DeviceSummary> {
    st.engine.lock().summaries()
}

#[tauri::command]
fn get_device(st: State<AppState>, mac: String) -> Result<Option<DeviceDetail>, String> {
    Ok(st.engine.lock().detail(&parse_mac(&mac)?))
}

#[tauri::command]
fn update_device(
    st: State<AppState>,
    mac: String,
    name: Option<String>,
    tag: Option<String>,
    notes: Option<String>,
    priority: Option<engine::Priority>,
) -> Result<bool, String> {
    Ok(st
        .engine
        .lock()
        .update_device(&parse_mac(&mac)?, name, tag, notes, priority))
}

#[tauri::command]
fn relearn_device(st: State<AppState>, mac: String) -> Result<bool, String> {
    Ok(st.engine.lock().relearn(&parse_mac(&mac)?))
}

#[tauri::command]
fn forget_device(st: State<AppState>, mac: String) -> Result<bool, String> {
    Ok(st.engine.lock().forget(&parse_mac(&mac)?))
}

#[tauri::command]
fn get_alerts(st: State<AppState>, limit: Option<usize>) -> Vec<Alert> {
    let eng = st.engine.lock();
    eng.alerts
        .iter()
        .rev()
        .take(limit.unwrap_or(500))
        .map(|a| eng.view(a))
        .collect()
}

#[tauri::command]
fn update_alerts(
    st: State<AppState>,
    ids: Vec<u64>,
    status: Option<engine::AlertStatus>,
    owner: Option<String>,
    note: Option<String>,
) -> usize {
    st.engine.lock().update_alerts(&ids, status, owner, note)
}

/// A user detection (saved search) matched: raise alerts for the devices it found.
#[tauri::command]
fn raise_detection(
    app: AppHandle,
    st: State<AppState>,
    name: String,
    severity: Severity,
    message: String,
    devices: Vec<String>,
    throttle_minutes: u32,
) -> usize {
    let macs: Vec<Mac> = devices.iter().filter_map(|m| m.parse().ok()).collect();
    let (n, fresh) = {
        let mut eng = st.engine.lock();
        let n = eng.raise_detection(&name, severity, &message, &macs, throttle_minutes);
        (n, eng.drain_fresh())
    };
    if !fresh.is_empty() {
        let _ = app.emit("niv://alerts", &fresh);
    }
    n
}

#[tauri::command]
fn ack_alert(st: State<AppState>, id: Option<u64>) {
    st.engine.lock().acknowledge(id);
}

#[tauri::command]
fn accept_alert(st: State<AppState>, id: u64) -> Result<(), String> {
    st.engine.lock().accept(id)
}

#[tauri::command]
fn clear_alerts(st: State<AppState>) {
    st.engine.lock().clear_alerts();
}

#[tauri::command]
fn reset_data(st: State<AppState>) -> Result<(), String> {
    // Clears devices, baselines and alerts of the current network only.
    st.engine.lock().clear_all();
    if let Some(store) = &st.store {
        store.delete_network(&current_net(&st));
    }
    save_state(&st)
}

#[tauri::command]
fn list_networks(st: State<AppState>) -> Vec<NetworkSummary> {
    let eng = st.engine.lock();
    st.networks.lock().summaries(&eng)
}

/// Browse a saved network's devices while not capturing.
#[tauri::command]
fn open_network(st: State<AppState>, id: String) -> Result<(), String> {
    if st.session.lock().is_some() {
        return Err("Stop the capture before switching to another network.".into());
    }
    {
        let mut eng = st.engine.lock();
        let mut nets = st.networks.lock();
        let rec = nets.records.get(&id).cloned().ok_or("network not found")?;
        let meta = NetMeta {
            id: rec.id,
            name: rec.name,
            kind: rec.kind,
            interface: rec.interface,
            subnet: rec.subnet,
            gateway_mac: rec.gateway_mac,
            ssid: rec.ssid,
        };
        eng.reset_network_identity(); // browsing: nothing from the previous network carries over
        nets.activate(&mut eng, meta, false);
    }
    save_state(&st)
}

#[tauri::command]
fn rename_network(st: State<AppState>, id: String, name: String) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name can't be empty.".into());
    }
    {
        let mut nets = st.networks.lock();
        let r = nets.records.get_mut(&id).ok_or("network not found")?;
        r.name = name;
        r.custom_name = true;
    }
    save_state(&st)
}

/// Forget a network: its devices, baselines and alerts.
#[tauri::command]
fn delete_network(st: State<AppState>, id: String) -> Result<(), String> {
    let is_current = st.networks.lock().current.as_deref() == Some(id.as_str());
    if is_current && st.session.lock().is_some() {
        return Err("Stop the capture before forgetting the network it is running on.".into());
    }
    {
        let mut eng = st.engine.lock();
        let mut nets = st.networks.lock();
        nets.records.remove(&id);
        if let Some(store) = &st.store {
            store.delete_network(&id);
        }
        if is_current {
            nets.current = None;
            nets.activate_latest(&mut eng);
        }
    }
    save_state(&st)
}

/// Drop all simulated devices/alerts. Stops the simulator if it is running.
#[tauri::command]
fn clear_demo(st: State<AppState>) -> Result<(), String> {
    let sim_running = st
        .session
        .lock()
        .as_ref()
        .is_some_and(|s| s.info.source == Source::Simulator);
    if sim_running {
        if let Some(s) = st.session.lock().take() {
            s.stop();
        }
    }
    {
        let mut eng = st.engine.lock();
        let mut nets = st.networks.lock();
        let was_current = nets.current.as_deref() == Some(DEMO_ID);
        nets.records.remove(DEMO_ID);
        if was_current {
            nets.current = None;
            nets.activate_latest(&mut eng);
        }
    }
    save_state(&st)
}

/// Write a JSON report (status, every device profile + baseline, alerts).
#[tauri::command]
fn export_report(app: AppHandle, st: State<AppState>) -> Result<String, String> {
    let status = build_status(&st);
    let (devices, alerts) = {
        let eng = st.engine.lock();
        let macs: Vec<Mac> = eng.devices.keys().copied().collect();
        let devices: Vec<DeviceDetail> = macs.iter().filter_map(|m| eng.detail(m)).collect();
        (devices, eng.alerts.iter().cloned().collect::<Vec<_>>())
    };
    let report = serde_json::json!({
        "generatedAt": Utc::now(),
        "tool": "Niv.ON",
        "status": status,
        "rules": st.settings.lock().rules,
        "devices": devices,
        "alerts": alerts,
    });
    let dir = app
        .path()
        .download_dir()
        .unwrap_or_else(|_| st.data_dir.clone());
    let path = dir.join(format!(
        "niv-on-report-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

// ---------------------------------------------------------------------------
// Investigation, intel, signatures, evidence, reports
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnRow {
    #[serde(flatten)]
    flow: engine::Flow,
    label: Option<String>,
    open: bool,
}

fn labels(st: &AppState) -> std::collections::HashMap<Mac, String> {
    st.engine
        .lock()
        .devices
        .values()
        .map(|d| (d.mac, d.label()))
        .collect()
}

/// Connection log: open flows plus stored history.
#[tauri::command]
fn get_connections(
    st: State<AppState>,
    mac: Option<String>,
    hours: Option<u32>,
    limit: Option<usize>,
) -> Result<Vec<ConnRow>, String> {
    let mac = mac.as_deref().map(parse_mac).transpose()?;
    let limit = limit.unwrap_or(5000).min(50_000);
    let since = Utc::now() - chrono::Duration::hours(hours.unwrap_or(24 * 7) as i64);
    persist_records(&st);
    let names = labels(&st);
    let mut rows: Vec<ConnRow> = st
        .engine
        .lock()
        .open_flows(mac)
        .into_iter()
        .map(|f| ConnRow {
            label: names.get(&f.mac).cloned(),
            flow: f,
            open: true,
        })
        .collect();
    if let Some(store) = &st.store {
        rows.extend(
            store
                .connections(&current_net(&st), mac, since, limit)
                .into_iter()
                .map(|f| ConnRow {
                    label: names.get(&f.mac).cloned(),
                    flow: f,
                    open: false,
                }),
        );
    }
    rows.truncate(limit);
    Ok(rows)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DnsRow {
    #[serde(flatten)]
    rec: engine::DnsRecord,
    label: Option<String>,
}

#[tauri::command]
fn get_dns(
    st: State<AppState>,
    mac: Option<String>,
    hours: Option<u32>,
    limit: Option<usize>,
) -> Result<Vec<DnsRow>, String> {
    let mac = mac.as_deref().map(parse_mac).transpose()?;
    let since = Utc::now() - chrono::Duration::hours(hours.unwrap_or(24 * 7) as i64);
    persist_records(&st);
    let names = labels(&st);
    Ok(st
        .store
        .as_ref()
        .map(|s| {
            s.dns(
                &current_net(&st),
                mac,
                since,
                limit.unwrap_or(5000).min(50_000),
            )
        })
        .unwrap_or_default()
        .into_iter()
        .map(|r| DnsRow {
            label: names.get(&r.mac).cloned(),
            rec: r,
        })
        .collect())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineEvent {
    ts: DateTime<Utc>,
    kind: &'static str,
    title: String,
    detail: String,
    severity: Option<Severity>,
}

/// One device's story: alerts, first contacts, lookups, big transfers,
/// fingerprints and baseline milestones on one time axis.
#[tauri::command]
fn get_timeline(st: State<AppState>, mac: String) -> Result<Vec<TimelineEvent>, String> {
    let mac = parse_mac(&mac)?;
    persist_records(&st);
    let mut ev: Vec<TimelineEvent> = vec![];
    {
        let eng = st.engine.lock();
        let d = eng.devices.get(&mac).ok_or("device not found")?;
        ev.push(TimelineEvent {
            ts: d.first_seen,
            kind: "device",
            title: "First seen".into(),
            detail: d.vendor.clone().unwrap_or_else(|| "unknown vendor".into()),
            severity: None,
        });
        if !d.baseline.learning(eng.clock) {
            ev.push(TimelineEvent {
                ts: d.baseline.learning_until,
                kind: "baseline",
                title: "Baseline locked".into(),
                detail: format!(
                    "{} hosts, {} ports learned",
                    d.baseline.destinations.len(),
                    d.baseline.ports.len()
                ),
                severity: None,
            });
        }
        for a in eng.alerts.iter().filter(|a| a.device == Some(mac)) {
            ev.push(TimelineEvent {
                ts: a.ts,
                kind: "alert",
                title: a.title.clone(),
                detail: a.message.clone(),
                severity: Some(a.severity),
            });
        }
        let mut dests: Vec<&engine::Destination> =
            d.destinations.values().filter(|x| x.external).collect();
        dests.sort_by_key(|x| std::cmp::Reverse(x.first_seen));
        for x in dests.into_iter().take(300) {
            ev.push(TimelineEvent {
                ts: x.first_seen,
                kind: if x.in_baseline {
                    "contact"
                } else {
                    "new-contact"
                },
                title: format!(
                    "First contact with {}",
                    x.domain.clone().unwrap_or_else(|| x.ip.to_string())
                ),
                detail: format!(
                    "{}{}",
                    x.ip,
                    if x.ports.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " · ports {}",
                            x.ports
                                .iter()
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ),
                severity: None,
            });
        }
        for (ja4, t) in &d.tls {
            ev.push(TimelineEvent {
                ts: t.first_seen,
                kind: "fingerprint",
                title: "New TLS client fingerprint".into(),
                detail: format!("JA4 {ja4} · JA3 {}", t.ja3),
                severity: None,
            });
        }
    }
    if let Some(store) = &st.store {
        let since = Utc::now() - chrono::Duration::days(14);
        let net = current_net(&st);
        let mut last = String::new();
        for r in store.dns(&net, Some(mac), since, 400) {
            if r.query == last {
                continue;
            }
            last = r.query.clone();
            ev.push(TimelineEvent {
                ts: r.ts,
                kind: "dns",
                title: format!("Looked up {}", r.query),
                detail: if r.rcode == 3 {
                    "NXDOMAIN (does not exist)".into()
                } else {
                    r.answers.join(", ")
                },
                severity: None,
            });
        }
        for f in store
            .connections(&net, Some(mac), since, 5000)
            .into_iter()
            .filter(|f| f.bytes_out + f.bytes_in >= 1_000_000)
            .take(100)
        {
            ev.push(TimelineEvent {
                ts: f.start,
                kind: "transfer",
                title: format!(
                    "Large transfer with {}",
                    f.domain.clone().unwrap_or_else(|| f.remote_ip.to_string())
                ),
                detail: format!(
                    "↑{} ↓{} over {} s",
                    engine::fmt_bytes(f.bytes_out),
                    engine::fmt_bytes(f.bytes_in),
                    (f.end - f.start).num_seconds()
                ),
                severity: None,
            });
        }
    }
    ev.sort_by_key(|e| std::cmp::Reverse(e.ts));
    ev.truncate(1000);
    Ok(ev)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TopoNode {
    id: String,
    label: String,
    kind: &'static str,
    class: String,
    risk: u32,
    alerts: usize,
    iot: bool,
    flagged: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TopoEdge {
    from: String,
    to: String,
    kind: &'static str,
    bytes: u64,
    /// Bytes sent by `from` / received by `from`.
    tx: u64,
    rx: u64,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    ports: Vec<u16>,
    suspicious: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatDevice {
    mac: String,
    label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatReason {
    alert_id: u64,
    rule: String,
    title: String,
    severity: engine::Severity,
}

/// An address involved in open alerts, with who talked to it and how much.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Threat {
    address: String,
    ip: Option<std::net::IpAddr>,
    domain: Option<String>,
    internal: bool,
    severity: engine::Severity,
    /// Threat-intel feed that lists the address, if any.
    intel: Option<String>,
    reasons: Vec<ThreatReason>,
    devices: Vec<ThreatDevice>,
    tx: u64,
    rx: u64,
    ports: Vec<u16>,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Open alerts that name a remote address, grouped by that address.
fn topology_threats(eng: &engine::Engine) -> Vec<Threat> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by: BTreeMap<String, Threat> = BTreeMap::new();
    for a in eng.alerts.iter().filter(|a| !a.acknowledged) {
        let Some(remote) = a.remote.as_deref().map(str::trim).filter(|r| !r.is_empty()) else {
            continue;
        };
        // Impersonation alerts name the address being claimed (often the
        // router); the threat is the device doing the claiming.
        let impersonation = matches!(
            a.rule.as_str(),
            "arp-spoof" | "ip-conflict" | "rogue-router"
        );
        let attacker = a
            .device
            .filter(|_| impersonation)
            .and_then(|m| eng.devices.get(&m));
        if impersonation && attacker.is_none() {
            continue;
        }
        let ip = match attacker {
            Some(d) => {
                let own = || d.ips.iter().filter(|i| i.to_string() != remote);
                own().find(|i| i.is_ipv4()).or(own().next()).copied()
            }
            None => remote
                .parse::<std::net::IpAddr>()
                .ok()
                .or_else(|| remote.parse::<std::net::SocketAddr>().ok().map(|s| s.ip())),
        };
        let remote = match attacker {
            Some(d) if ip.is_none() => d.mac.to_string(),
            _ => remote.to_string(),
        };
        let remote = remote.as_str();
        let key = ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| remote.to_ascii_lowercase());
        let t = by.entry(key.clone()).or_insert_with(|| Threat {
            address: key.clone(),
            ip,
            domain: match (attacker, ip) {
                (Some(_), _) => None,
                (None, Some(i)) => eng.name_of(&i),
                (None, None) => Some(key.clone()),
            },
            internal: attacker.is_some() || ip.is_some_and(|i| eng.is_lan(&i)),
            severity: a.severity,
            intel: None,
            reasons: vec![],
            devices: vec![],
            tx: 0,
            rx: 0,
            ports: vec![],
            first_seen: None,
            last_seen: None,
        });
        t.severity = t.severity.max(a.severity);
        t.reasons.push(ThreatReason {
            alert_id: a.id,
            rule: a.rule.clone(),
            title: a.title.clone(),
            severity: a.severity,
        });
        if let Some(p) = a.port {
            if !t.ports.contains(&p) {
                t.ports.push(p);
            }
        }
        if let Some(mac) = a.device {
            if !t.devices.iter().any(|d| d.mac == mac.to_string()) {
                t.devices.push(ThreatDevice {
                    mac: mac.to_string(),
                    label: a.device_label.clone().unwrap_or_else(|| mac.to_string()),
                });
            }
        }
    }
    for t in by.values_mut() {
        t.intel = eng.intel_source(t.ip.as_ref(), t.domain.as_deref());
        // Traffic each involved device exchanged with the address.
        let mut ports: BTreeSet<u16> = t.ports.iter().copied().collect();
        let (want_ip, suffix) = (t.ip, format!(".{}", t.address));
        let matches = t
            .devices
            .iter()
            .filter_map(|dev| dev.mac.parse().ok().and_then(|m| eng.devices.get(&m)))
            .flat_map(|d| d.destinations.values())
            .filter(|x| {
                Some(x.ip) == want_ip
                    || want_ip.is_none()
                        && x.domain
                            .as_deref()
                            .is_some_and(|dom| dom == t.address || dom.ends_with(&suffix))
            })
            .collect::<Vec<_>>();
        for x in matches {
            t.tx += x.tx_bytes;
            t.rx += x.rx_bytes;
            ports.extend(x.ports.iter().copied());
            t.first_seen = Some(t.first_seen.map_or(x.first_seen, |f| f.min(x.first_seen)));
            t.last_seen = Some(t.last_seen.map_or(x.last_seen, |l| l.max(x.last_seen)));
            t.ip.get_or_insert(x.ip);
        }
        t.ports = ports.into_iter().take(8).collect();
        t.reasons.sort_by_key(|r| std::cmp::Reverse(r.severity));
    }
    let mut out: Vec<Threat> = by.into_values().collect();
    out.sort_by_key(|t| {
        (
            std::cmp::Reverse(t.severity),
            t.intel.is_none(),
            std::cmp::Reverse(t.last_seen),
        )
    });
    out.truncate(40);
    out
}

/// Network map: devices, the router, LAN peers and each device's main internet hosts.
#[tauri::command]
fn get_topology(st: State<AppState>) -> serde_json::Value {
    let eng = st.engine.lock();
    let summaries = eng.summaries();
    let mut nodes: Vec<TopoNode> = vec![];
    let mut edges: Vec<TopoEdge> = vec![];
    let router = summaries
        .iter()
        .find(|d| d.is_gateway)
        .map(|d| d.mac.to_string());
    let by_ip: std::collections::HashMap<std::net::IpAddr, String> = eng
        .devices
        .values()
        .flat_map(|d| d.ips.iter().map(move |ip| (*ip, d.mac.to_string())))
        .collect();
    let shown: Vec<&DeviceSummary> = summaries
        .iter()
        .filter(|d| !d.ips.is_empty() || d.is_ap || d.is_gateway)
        .take(250)
        .collect();
    let mut internet: std::collections::HashMap<String, TopoNode> =
        std::collections::HashMap::new();
    for s in &shown {
        let id = s.mac.to_string();
        nodes.push(TopoNode {
            id: id.clone(),
            label: s.label.clone(),
            kind: if s.is_gateway {
                "router"
            } else if s.is_self {
                "self"
            } else if s.is_ap {
                "ap"
            } else {
                "device"
            },
            class: s.class.clone(),
            risk: s.risk,
            alerts: s.open_alerts,
            iot: s.is_iot,
            flagged: s.open_alerts > 0,
        });
        if let Some(r) = router.as_ref().filter(|r| **r != id) {
            edges.push(TopoEdge {
                from: id.clone(),
                to: r.clone(),
                kind: "lan",
                bytes: s.tx_bytes + s.rx_bytes,
                tx: s.tx_bytes,
                rx: s.rx_bytes,
                last_seen: Some(s.last_seen),
                ports: vec![],
                suspicious: false,
            });
        }
        let Some(d) = eng.devices.get(&s.mac) else {
            continue;
        };
        let mut ext: Vec<&engine::Destination> =
            d.destinations.values().filter(|x| x.external).collect();
        ext.sort_by_key(|x| std::cmp::Reverse(x.tx_bytes + x.rx_bytes));
        for x in ext.into_iter().take(6) {
            let key = x.ip.to_string();
            let bad = x.alerted || !x.in_baseline && !d.baseline.learning(eng.clock);
            let n = internet.entry(key.clone()).or_insert_with(|| TopoNode {
                id: key.clone(),
                label: x.domain.clone().unwrap_or_else(|| key.clone()),
                kind: "internet",
                class: "Internet".into(),
                risk: 0,
                alerts: 0,
                iot: false,
                flagged: false,
            });
            n.flagged |= x.alerted;
            edges.push(TopoEdge {
                from: id.clone(),
                to: key,
                kind: "internet",
                bytes: x.tx_bytes + x.rx_bytes,
                tx: x.tx_bytes,
                rx: x.rx_bytes,
                last_seen: Some(x.last_seen),
                ports: x.ports.iter().copied().take(5).collect(),
                suspicious: bad,
            });
        }
        for x in d.destinations.values().filter(|x| !x.external) {
            if let Some(peer) = by_ip
                .get(&x.ip)
                .filter(|p| **p != id && Some(*p) != router.as_ref())
            {
                edges.push(TopoEdge {
                    from: id.clone(),
                    to: peer.clone(),
                    kind: "peer",
                    bytes: x.tx_bytes + x.rx_bytes,
                    tx: x.tx_bytes,
                    rx: x.rx_bytes,
                    last_seen: Some(x.last_seen),
                    ports: x.ports.iter().copied().take(5).collect(),
                    suspicious: x.alerted,
                });
            }
        }
    }
    let mut inet: Vec<TopoNode> = internet.into_values().collect();
    inet.sort_by_key(|n| !n.flagged);
    inet.truncate(150);
    let keep: std::collections::HashSet<String> = nodes
        .iter()
        .map(|n| n.id.clone())
        .chain(inet.iter().map(|n| n.id.clone()))
        .collect();
    nodes.extend(inet);
    edges.retain(|e| keep.contains(&e.from) && keep.contains(&e.to));
    let threats = topology_threats(&eng);
    serde_json::json!({ "nodes": nodes, "edges": edges, "threats": threats, "clock": eng.clock })
}

#[tauri::command]
fn get_compliance(st: State<AppState>) -> Vec<exposure::CheckResult> {
    let eng = st.engine.lock();
    exposure::compliance(eng.devices.values(), &eng.kev)
}

fn intel_json(st: &AppState) -> serde_json::Value {
    let meta = intel::read_meta(&st.data_dir);
    let s = st.settings.lock().clone();
    let feeds: Vec<serde_json::Value> = intel::FEEDS
        .iter()
        .map(|f| {
            let m = meta.feeds.get(f.id).cloned().unwrap_or_default();
            serde_json::json!({
                "id": f.id, "name": f.name, "description": f.description, "url": f.url, "severity": f.severity,
                "enabled": s.data.feeds.iter().any(|e| e == f.id), "updated": m.updated, "count": m.count, "error": m.error,
            })
        })
        .collect();
    let eng = st.engine.lock();
    serde_json::json!({
        "feeds": feeds,
        "kev": { "updated": meta.kev.updated, "count": eng.kev.entries, "error": meta.kev.error },
        "indicators": eng.intel_size(),
        "watchlist": s.rules.watchlist.iter().filter(|l| !l.split('#').next().unwrap_or("").trim().is_empty()).count(),
        "autoUpdate": s.data.auto_update_intel,
    })
}

#[tauri::command]
fn intel_status(st: State<AppState>) -> serde_json::Value {
    intel_json(&st)
}

/// Download enabled feeds and the KEV catalog now.
#[tauri::command]
async fn update_intel(app: AppHandle) -> Result<serde_json::Value, String> {
    let h = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let st = h.state::<AppState>();
        let feeds = st.settings.lock().data.feeds.clone();
        intel::update(&st.data_dir, &feeds, true);
        reload_intel(&st);
        intel_json(&st)
    })
    .await
    .map_err(|e| e.to_string())
}

const ET_BASE: &str = "https://rules.emergingthreats.net/open/suricata-7.0/rules/";
const ET_CATEGORIES: &[(&str, &str)] = &[
    ("emerging-exploit", "Exploits against servers and devices"),
    ("emerging-scan", "Port and vulnerability scanners"),
    ("emerging-attack_response", "Signs a host was compromised"),
    ("emerging-coinminer", "Cryptocurrency miners"),
    ("emerging-dos", "Denial of service"),
    ("emerging-worm", "Worm propagation"),
    ("emerging-mobile_malware", "Mobile malware"),
    ("emerging-malware", "Malware command and control (large)"),
];

#[tauri::command]
fn rules_status(st: State<AppState>) -> serde_json::Value {
    let eng = st.engine.lock();
    let sources: Vec<serde_json::Value> =
        eng.ids.stats.iter().map(|(n, ok, skip)| serde_json::json!({ "name": n, "loaded": ok, "skipped": skip, "builtin": n == "built-in" })).collect();
    let cats: Vec<serde_json::Value> = ET_CATEGORIES
        .iter()
        .map(|(id, d)| serde_json::json!({ "id": id, "description": d, "installed": rules_dir(&st.data_dir).join(format!("et-{id}.rules")).exists() }))
        .collect();
    serde_json::json!({ "total": eng.ids.rules.len(), "sources": sources, "etCategories": cats, "enabled": eng.rules.ids })
}

/// Copy a Suricata / Snort `.rules` file into the rules folder and load it.
#[tauri::command]
fn import_rules(st: State<AppState>, path: String) -> Result<String, String> {
    let src = std::path::Path::new(&path);
    let text = std::fs::read_to_string(src).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut probe = ids::RuleSet::default();
    probe.add_text("probe", &text);
    let (_, ok, skipped) = probe.stats[0].clone();
    if ok == 0 {
        return Err(format!(
            "No usable rules found ({skipped} skipped as unsupported or invalid)."
        ));
    }
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "imported.rules".into());
    let name = if name.ends_with(".rules") {
        name
    } else {
        format!("{name}.rules")
    };
    std::fs::create_dir_all(rules_dir(&st.data_dir)).map_err(|e| e.to_string())?;
    std::fs::write(rules_dir(&st.data_dir).join(&name), text).map_err(|e| e.to_string())?;
    let total = reload_rules(&st);
    Ok(format!("Imported {ok} rules from {name} ({skipped} skipped as unsupported). {total} signatures active."))
}

#[tauri::command]
fn remove_rules(st: State<AppState>, name: String) -> Result<String, String> {
    if name.contains(['/', '\\']) || !name.ends_with(".rules") {
        return Err("invalid rule file name".into());
    }
    let _ = std::fs::remove_file(rules_dir(&st.data_dir).join(&name));
    Ok(format!(
        "Removed {name}. {} signatures active.",
        reload_rules(&st)
    ))
}

/// Download Emerging Threats Open categories (free, community-maintained).
#[tauri::command]
async fn download_et(app: AppHandle, categories: Vec<String>) -> Result<String, String> {
    let h = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let st = h.state::<AppState>();
        let dir = rules_dir(&st.data_dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut done = vec![];
        let mut failed = vec![];
        for c in categories
            .iter()
            .filter(|c| ET_CATEGORIES.iter().any(|(id, _)| id == c))
        {
            match intel::download(
                &format!("{ET_BASE}{c}.rules"),
                &dir.join(format!("et-{c}.rules")),
                1000,
            ) {
                Ok(()) => done.push(c.clone()),
                Err(e) => failed.push(format!("{c}: {e}")),
            }
        }
        let total = reload_rules(&st);
        if done.is_empty() && !failed.is_empty() {
            return Err(failed.join("; "));
        }
        Ok(format!(
            "Installed {} ET Open categor{}. {total} signatures active.{}",
            done.len(),
            if done.len() == 1 { "y" } else { "ies" },
            if failed.is_empty() {
                String::new()
            } else {
                format!(" Failed: {}", failed.join("; "))
            }
        ))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn save_evidence(st: State<AppState>, id: u64) -> Result<String, String> {
    save_alert_evidence(&st, id)
}

#[tauri::command]
fn reveal_path(path: String) -> Result<(), String> {
    open_with_os(&path, true)
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    open_with_os(&path, false)
}

fn write_report(st: &AppState, days: u32, dir: PathBuf) -> Result<String, String> {
    persist_records(st);
    let network = st
        .networks
        .lock()
        .current_record()
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "Current network".into());
    let data = {
        let eng = st.engine.lock();
        report::ReportData {
            network,
            days: days.max(1),
            devices: eng.summaries(),
            alerts: eng.alerts.iter().map(|a| eng.view(a)).collect(),
            compliance: exposure::compliance(eng.devices.values(), &eng.kev),
            store: st
                .store
                .as_ref()
                .map(|s| s.stats(&current_net(st)))
                .unwrap_or_default(),
            indicators: eng.intel_size(),
            signatures: eng.ids.rules.len(),
        }
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!(
        "niv-on-security-report-{}.html",
        Utc::now().format("%Y%m%d-%H%M")
    ));
    std::fs::write(&path, report::render(&data)).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
fn generate_report(app: AppHandle, st: State<AppState>, days: u32) -> Result<String, String> {
    let dir = app
        .path()
        .download_dir()
        .unwrap_or_else(|_| st.data_dir.join("reports"));
    write_report(&st, days, dir)
}

#[tauri::command]
async fn list_adapters() -> Result<Vec<adapters::Adapter>, String> {
    tauri::async_runtime::spawn_blocking(adapters::list)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_monitor_mode(
    iface: String,
    enable: bool,
    channel: Option<u16>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || adapters::set_monitor(&iface, enable, channel))
        .await
        .map_err(|e| e.to_string())?
}

/// Check a remote sensor: SSH login, passwordless sudo, tools, the interface.
#[tauri::command]
async fn test_remote_sensor(sensor: settings::RemoteSensor) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let host = sensor.host.trim().to_string();
        if host.is_empty() || host.starts_with('-') || host.contains(char::is_whitespace) {
            return Err("Enter the sensor as user@host.".to_string());
        }
        if !adapters::valid_iface(sensor.iface.trim()) || sensor.iface.contains(' ') {
            return Err("Invalid interface name.".into());
        }
        let probe = format!(
            "echo ssh-ok; sudo -n true 2>/dev/null && echo sudo-ok; command -v tcpdump >/dev/null && echo tcpdump-ok; command -v iw >/dev/null && echo iw-ok; ip link show {i} >/dev/null 2>&1 && echo iface-ok; iw phy $(cat /sys/class/net/{i}/phy80211/name 2>/dev/null) info 2>/dev/null | grep -q '[*] monitor' && echo monitor-ok",
            i = sensor.iface.trim()
        );
        let out = std::process::Command::new("ssh")
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", "-p"])
            .arg(sensor.port.max(1).to_string())
            .arg(&host)
            .arg(probe)
            .output()
            .map_err(|e| format!("cannot run ssh: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let has = |k: &str| text.lines().any(|l| l.trim() == k);
        if !has("ssh-ok") {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("SSH login failed: {}. Set up key-based login with `ssh-copy-id {host}`.", err.trim().lines().last().unwrap_or("no response")));
        }
        let mut problems = vec![];
        if !has("sudo-ok") {
            problems.push("passwordless sudo is not enabled (sudo visudo → `<user> ALL=(root) NOPASSWD: ALL`)");
        }
        if !has("tcpdump-ok") {
            problems.push("tcpdump is missing (sudo apt install tcpdump)");
        }
        if !has("iw-ok") && sensor.monitor {
            problems.push("iw is missing (sudo apt install iw)");
        }
        if !has("iface-ok") {
            problems.push("the interface does not exist (check `ip link` on the sensor)");
        } else if sensor.monitor && !has("monitor-ok") {
            problems.push("the adapter does not advertise monitor mode (driver missing? ALFA RTL8812AU needs the aircrack-ng/rtl8812au driver)");
        }
        if problems.is_empty() {
            Ok(format!("Sensor ready: SSH, sudo, tcpdump{} and {} OK.", if sensor.monitor { ", iw, monitor mode" } else { "" }, sensor.iface.trim()))
        } else {
            Err(format!("Connected, but: {}.", problems.join("; ")))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn playbook_log() -> Vec<playbook::RunLog> {
    playbook::history()
}

#[tauri::command]
fn store_stats(st: State<AppState>) -> store::StoreStats {
    st.store
        .as_ref()
        .map(|s| s.stats(&current_net(&st)))
        .unwrap_or_default()
}

/// Retention, daily intel refresh and scheduled reports.
fn hourly(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let st = app.state::<AppState>();
        let cfg = st.settings.lock().clone();
        if let Some(store) = &st.store {
            store.purge(cfg.data.retention_days);
        }
        if cfg.data.auto_update_intel {
            let meta = intel::read_meta(&st.data_dir);
            let stale = |u: Option<DateTime<Utc>>| {
                u.is_none_or(|t| Utc::now() - t > chrono::Duration::hours(23))
            };
            let due = cfg
                .data
                .feeds
                .iter()
                .any(|f| stale(meta.feeds.get(f).and_then(|m| m.updated)))
                || stale(meta.kev.updated);
            if due {
                intel::update(&st.data_dir, &cfg.data.feeds, true);
                reload_intel(&st);
            }
        }
        let period = match cfg.data.report_schedule.as_str() {
            "daily" => Some(1),
            "weekly" => Some(7),
            _ => None,
        };
        if let Some(days) = period {
            let due = cfg.data.last_report.is_none_or(|t| {
                Utc::now() - t >= chrono::Duration::days(days as i64) - chrono::Duration::hours(1)
            });
            if due {
                let dir = app
                    .path()
                    .download_dir()
                    .unwrap_or_else(|_| st.data_dir.join("reports"));
                if write_report(&st, days, dir).is_ok() {
                    st.settings.lock().data.last_report = Some(Utc::now());
                    let _ = save_state(&st);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    platform::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            let _ = std::fs::create_dir_all(&data_dir);
            let persisted: Persisted = std::fs::read(data_dir.join(STATE_FILE))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();

            let oui = oui::OuiDb::load(Some(&data_dir));
            let mut engine = Engine::new(persisted.settings.rules.clone(), oui);
            let mut networks = persisted.networks;
            // Migrate pre-workspace data into its own "Earlier data" network.
            if !persisted.devices.is_empty() && networks.records.is_empty() {
                networks.activate(
                    &mut engine,
                    NetMeta {
                        id: "legacy".into(),
                        name: "Earlier data".into(),
                        kind: NetKind::Legacy,
                        interface: None,
                        subnet: None,
                        gateway_mac: None,
                        ssid: None,
                    },
                    false,
                );
                engine.restore(persisted.devices, persisted.alerts, persisted.next_alert_id);
                networks.snapshot(&engine);
                engine.clear_all();
            }
            // Re-open the last network the user worked on.
            let last = networks.current.clone();
            networks.current = None;
            if let Some(id) = last.filter(|id| networks.records.contains_key(id)) {
                let r = &networks.records[&id];
                // Router and address ranges first: restore() recomputes which
                // destinations are external and which device is the gateway.
                engine.gateway_macs.clear();
                engine.gateway_macs.extend(workspace::saved_gateway(r));
                engine.lan_nets = r.lan_nets.clone();
                engine.restore(r.devices.clone(), r.alerts.clone(), r.next_alert_id);
                networks.current = Some(id);
            }

            evidence::init(&data_dir);
            let store = match store::Store::open(&data_dir.join("niv-events.db")) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    eprintln!("event store unavailable: {e}");
                    None
                }
            };
            engine.ids = Arc::new(load_rules(&data_dir));
            app.manage(AppState {
                engine: Arc::new(Mutex::new(engine)),
                settings: Mutex::new(persisted.settings),
                session: Mutex::new(None),
                stats: Arc::new(Mutex::new(CaptureStats::default())),
                data_dir,
                networks: Mutex::new(networks),
                store,
            });
            reload_intel(&app.state::<AppState>());

            // 1 Hz ticker: advance the clock, push status + traffic graph,
            // and persist every 30 s when something changed.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut n: u64 = 0;
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    n += 1;
                    let st = handle.state::<AppState>();
                    let live = st.session.lock().as_ref().map(|s| s.is_live());
                    if live == Some(true) && n.is_multiple_of(5) {
                        let mut eng = st.engine.lock();
                        if st.networks.lock().adopt_gateway_mac(&mut eng) {
                            eng.dirty = true;
                        }
                    }
                    let traffic = {
                        let mut eng = st.engine.lock();
                        eng.tick(if live == Some(true) {
                            Some(Utc::now())
                        } else {
                            None
                        });
                        eng.traffic
                            .iter()
                            .rev()
                            .take(300)
                            .rev()
                            .cloned()
                            .collect::<Vec<_>>()
                    };
                    let status = serde_json::to_value(build_status(&st)).unwrap_or_default();
                    let _ = handle.emit("niv://tick", Tick { status, traffic });
                    persist_records(&st);
                    if n.is_multiple_of(30) && st.engine.lock().dirty {
                        let _ = save_state(&st);
                    }
                    // Hourly housekeeping (first run a minute after launch).
                    if n % 3600 == 60 {
                        hourly(&handle);
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let st = window.state::<AppState>();
                if let Some(s) = st.session.lock().take() {
                    s.stop();
                }
                st.engine.lock().flush_flows();
                persist_records(&st);
                let _ = save_state(&st);
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            check_access,
            fix_access,
            test_interface,
            scan_network,
            get_feed,
            switch_source,
            list_networks,
            open_network,
            rename_network,
            delete_network,
            clear_demo,
            update_vendor_db,
            get_settings,
            save_settings,
            start_capture,
            stop_capture,
            get_status,
            get_traffic,
            get_devices,
            get_device,
            update_device,
            relearn_device,
            forget_device,
            get_alerts,
            ack_alert,
            accept_alert,
            clear_alerts,
            reset_data,
            export_report,
            update_alerts,
            raise_detection,
            get_connections,
            get_dns,
            get_timeline,
            get_topology,
            get_compliance,
            intel_status,
            update_intel,
            rules_status,
            import_rules,
            remove_rules,
            download_et,
            save_evidence,
            reveal_path,
            open_path,
            generate_report,
            playbook_log,
            store_stats,
            list_adapters,
            set_monitor_mode,
            test_remote_sensor,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Niv.ON");
}
