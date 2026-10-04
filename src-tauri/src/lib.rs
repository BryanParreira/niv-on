//! Niv.ON — network & IoT behavior monitor.
//!
//! Tauri backend: owns the analysis engine, runs capture sessions and exposes
//! commands/events to the React dashboard.

mod capture;
mod engine;
mod model;
mod netif;
mod oui;
mod parser;
mod platform;
mod settings;
mod simulator;
mod workspace;

use capture::{CaptureStats, Session, SessionInfo};
use chrono::{DateTime, Utc};
use engine::{Alert, Device, DeviceDetail, DeviceSummary, Engine, FeedItem, Severity, Totals, TrafficPoint};
use model::Mac;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use settings::{Settings, Source};
use workspace::{NetKind, NetMeta, NetworkStore, NetworkSummary, DEMO_ID};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

const STATE_FILE: &str = "niv-state.json";

pub struct AppState {
    engine: Arc<Mutex<Engine>>,
    settings: Mutex<Settings>,
    session: Mutex<Option<Session>>,
    stats: Arc<Mutex<CaptureStats>>,
    data_dir: PathBuf,
    networks: Mutex<NetworkStore>,
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
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Tick {
    status: serde_json::Value,
    traffic: Vec<TrafficPoint>,
}

fn build_status(st: &AppState) -> Status {
    let network = st.networks.lock().current_record().map(|r| CurrentNetwork { id: r.id.clone(), name: r.name.clone(), kind: r.kind.clone() });
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
        channel: session.as_ref().map(|s| s.channel.load(Ordering::Relaxed)).filter(|c| *c > 0),
        session: session.as_ref().map(|s| s.info.clone()),
        stats: st.stats.lock().clone(),
        totals: eng.totals.clone(),
        clock: eng.clock,
        devices: eng.devices.len(),
        active_devices: eng.devices.values().filter(|d| d.last_seen >= active_cutoff).count(),
        alerts,
        packets_per_sec: last.packets,
        bytes_per_sec: last.bytes,
        data_dir: st.data_dir.display().to_string(),
        oui_entries: eng.oui.external_entries,
        network,
    }
}

fn save_state(st: &AppState) -> Result<(), String> {
    let p = {
        let mut eng = st.engine.lock();
        eng.dirty = false;
        let networks = st.networks.lock().persistable(&eng);
        Persisted { settings: st.settings.lock().clone(), networks, ..Default::default() }
    };
    std::fs::create_dir_all(&st.data_dir).map_err(|e| e.to_string())?;
    let tmp = st.data_dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(&p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, st.data_dir.join(STATE_FILE)).map_err(|e| e.to_string())
}

fn parse_mac(s: &str) -> Result<Mac, String> {
    s.parse()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn list_interfaces() -> Result<Vec<netif::Interface>, String> {
    tauri::async_runtime::spawn_blocking(netif::list).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn check_access() -> Result<netif::Access, String> {
    tauri::async_runtime::spawn_blocking(netif::check_access).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn fix_access() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(netif::fix_access).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_interface(name: String, monitor: bool, promiscuous: bool) -> Result<netif::TestResult, String> {
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
        (info.as_ref().and_then(|i| i.interface.clone()), info.is_some_and(|i| i.source == Source::Live && !i.monitor_mode_active()))
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
    let n = tauri::async_runtime::spawn_blocking(move || netif::arp_sweep(&iface, own)).await.map_err(|e| e.to_string())??;
    Ok(format!("Sent {n} ARP requests. Devices that answer appear in the device list within seconds."))
}

fn local_hostname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    // "Mac-mini.lan" / "host.local" -> "Mac-mini"
    let h = String::from_utf8_lossy(&out.stdout).trim().split('.').next().unwrap_or_default().to_string();
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
    Ok(format!("Vendor database updated: {n} manufacturers. Device vendors refreshed."))
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
    st.engine.lock().rules = settings.rules.clone();
    *st.settings.lock() = settings;
    save_state(&st)
}

#[tauri::command]
fn start_capture(app: AppHandle, st: State<AppState>) -> Result<SessionInfo, String> {
    if let Some(s) = st.session.lock().take() {
        s.stop();
    }
    let cfg = st.settings.lock().clone();
    {
        // Know who "we" are, so the UI can mark this computer and the router.
        let mut eng = st.engine.lock();
        eng.self_macs.clear();
        eng.self_ips.clear();
        eng.gateway_ip = None;
        eng.self_hostname = local_hostname();
        let mut meta = None;
        let mut fresh = false;
        match cfg.capture.source {
            Source::Live => {
                if let Some(i) = netif::list().ok().and_then(|l| l.into_iter().find(|i| Some(&i.name) == cfg.capture.interface.as_ref())) {
                    eng.self_macs.extend(i.mac.as_deref().and_then(|m| m.parse::<Mac>().ok()));
                    eng.self_ips.extend(i.ipv4.iter().chain(i.ipv6.iter()).filter_map(|a| a.parse::<std::net::IpAddr>().ok()));
                    eng.gateway_ip = i.gateway.as_deref().and_then(|g| g.parse().ok());
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
            Source::File => {
                if let Some(path) = cfg.capture.file_path.as_deref() {
                    fresh = true; // a replay is a self-contained analysis
                    let name = std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| path.into());
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
    let session = capture::start(&cfg.capture, cfg.rules.learning_minutes, st.engine.clone(), st.stats.clone(), app)?;
    let info = session.info.clone();
    *st.session.lock() = Some(session);
    Ok(info)
}

#[tauri::command]
fn stop_capture(st: State<AppState>) -> Result<(), String> {
    if let Some(s) = st.session.lock().take() {
        s.stop();
    }
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
) -> Result<bool, String> {
    Ok(st.engine.lock().update_device(&parse_mac(&mac)?, name, tag, notes))
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
    st.engine.lock().alerts.iter().rev().take(limit.unwrap_or(500)).cloned().collect()
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
    let sim_running = st.session.lock().as_ref().is_some_and(|s| s.info.source == Source::Simulator);
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
    let dir = app.path().download_dir().unwrap_or_else(|_| st.data_dir.clone());
    let path = dir.join(format!("niv-on-report-{}.json", Utc::now().format("%Y%m%d-%H%M%S")));
    std::fs::write(&path, serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
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
        .setup(|app| {
            let data_dir = app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from("."));
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
                    NetMeta { id: "legacy".into(), name: "Earlier data".into(), kind: NetKind::Legacy, interface: None, subnet: None, gateway_mac: None, ssid: None },
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
                engine.restore(r.devices.clone(), r.alerts.clone(), r.next_alert_id);
                networks.current = Some(id);
            }

            app.manage(AppState {
                engine: Arc::new(Mutex::new(engine)),
                settings: Mutex::new(persisted.settings),
                session: Mutex::new(None),
                stats: Arc::new(Mutex::new(CaptureStats::default())),
                data_dir,
                networks: Mutex::new(networks),
            });

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
                        eng.tick(if live == Some(true) { Some(Utc::now()) } else { None });
                        eng.traffic.iter().rev().take(300).rev().cloned().collect::<Vec<_>>()
                    };
                    let status = serde_json::to_value(build_status(&st)).unwrap_or_default();
                    let _ = handle.emit("niv://tick", Tick { status, traffic });
                    if n.is_multiple_of(30) && st.engine.lock().dirty {
                        let _ = save_state(&st);
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Niv.ON");
}
