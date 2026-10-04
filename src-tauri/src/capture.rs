//! Capture sources and the processing pipeline.
//!
//! ```text
//!  [libpcap live | pcap file | simulator] --(bounded queue)--> [processor] --> Engine
//!                    \__ channel hopper (monitor mode)            \__ "niv://alerts" events
//! ```

// timeval field widths differ per platform, so the casts are intentional.
#![allow(clippy::unnecessary_cast)]

use crate::engine::Engine;
use crate::model::PacketInfo;
use crate::parser;
use crate::settings::{CaptureSettings, Source};
use crate::simulator::Simulator;
use chrono::{DateTime, Utc};
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender, TrySendError};
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

const QUEUE: usize = 100_000;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStats {
    /// Packets reported by libpcap.
    pub received: u64,
    /// Dropped by the kernel buffer.
    pub dropped: u64,
    pub if_dropped: u64,
    /// Dropped because the analysis queue was full.
    pub queue_dropped: u64,
    /// Frames libpcap delivered that we could not decode.
    pub undecoded: u64,
    pub error: Option<String>,
    /// File replay reached end of file.
    pub finished: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub source: Source,
    pub interface: Option<String>,
    pub file: Option<String>,
    pub linktype: Option<String>,
    pub monitor_mode: bool,
    pub hopping: bool,
    pub started_at: DateTime<Utc>,
    /// Non-fatal setup messages (e.g. channel could not be set).
    pub notes: Vec<String>,
}

pub struct Session {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub info: SessionInfo,
    pub channel: Arc<AtomicU16>,
}

impl SessionInfo {
    /// Raw 802.11 frames are arriving (monitor mode really active).
    pub fn monitor_mode_active(&self) -> bool {
        self.linktype.as_deref().is_some_and(|l| l.contains("802.11") && !l.starts_with("Simulated"))
    }
}

impl Session {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    pub fn is_live(&self) -> bool {
        self.info.source != Source::File
    }
}

/// Turn libpcap error strings into something actionable.
pub fn friendly_error(e: &str) -> String {
    let lower = e.to_lowercase();
    let hint = if lower.contains("permission") || lower.contains("operation not permitted") || lower.contains("not permitted") {
        if cfg!(target_os = "macos") {
            " — macOS: run the app with sudo, or install Wireshark's \"ChmodBPF\" helper so your user can open /dev/bpf*."
        } else if cfg!(target_os = "linux") {
            " — Linux: run with sudo or grant capabilities: sudo setcap cap_net_raw,cap_net_admin=eip <path-to-niv-binary>"
        } else {
            " — Windows: install Npcap (with \"Support raw 802.11 traffic\" for monitor mode) and run as Administrator."
        }
    } else if lower.contains("rfmon") || lower.contains("monitor mode") || lower.contains("not supported") {
        " — this adapter/driver does not support RF monitor mode. Turn off monitor mode, pick another adapter, or use the simulator / a pcap file."
    } else if lower.contains("no such device") || lower.contains("doesn't exist") {
        " — interface not found. Refresh the interface list in Settings."
    } else {
        ""
    };
    format!("{e}{hint}")
}

#[cfg(test)]
pub fn ts_now_from(tv_sec: i64, tv_usec: i64) -> DateTime<Utc> {
    ts_from(tv_sec, tv_usec)
}

fn ts_from(tv_sec: i64, tv_usec: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(tv_sec, (tv_usec.clamp(0, 999_999) as u32) * 1000).unwrap_or_else(Utc::now)
}

/// Best-effort channel switch using the platform's wireless tool.
pub fn set_channel(iface: &str, ch: u16) -> Result<(), String> {
    use std::process::Command;
    let ch_s = ch.to_string();
    let out = if cfg!(target_os = "linux") {
        Command::new("iw").args(["dev", iface, "set", "channel", &ch_s]).output()
    } else if cfg!(target_os = "macos") {
        let airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
        if !std::path::Path::new(airport).exists() {
            return Err("macOS no longer ships the `airport` tool, so the channel can't be changed programmatically. \
                        Use Wireless Diagnostics → Window → Sniffer to capture on a chosen channel and replay the file here, \
                        or use a USB adapter on Linux."
                .into());
        }
        Command::new(airport).arg(format!("--channel={ch}")).output()
    } else {
        let helper = r"C:\Windows\System32\Npcap\WlanHelper.exe";
        Command::new(helper).args([iface, "channel", &ch_s]).output()
    };
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "failed to set channel {ch}: {}",
            String::from_utf8_lossy(if o.stderr.is_empty() { &o.stdout } else { &o.stderr }).trim()
        )),
        Err(e) => Err(format!("failed to run channel tool: {e}")),
    }
}

pub fn start(
    cfg: &CaptureSettings,
    learning_minutes: u32,
    engine: Arc<Mutex<Engine>>,
    stats: Arc<Mutex<CaptureStats>>,
    app: AppHandle,
) -> Result<Session, String> {
    *stats.lock() = CaptureStats::default();
    let stop = Arc::new(AtomicBool::new(false));
    let channel = Arc::new(AtomicU16::new(cfg.channel.unwrap_or(0)));
    let (tx, rx) = bounded::<PacketInfo>(QUEUE);
    let mut threads = Vec::new();
    let mut info = SessionInfo {
        source: cfg.source,
        interface: None,
        file: None,
        linktype: None,
        monitor_mode: false,
        hopping: false,
        started_at: Utc::now(),
        notes: vec![],
    };

    match cfg.source {
        Source::Simulator => {
            info.linktype = Some("Simulated 802.11 + radiotap".into());
            info.monitor_mode = true;
            channel.store(6, Ordering::Relaxed);
            info.notes.push(format!(
                "Simulated smart-home network on channel 6. Attack scenarios begin after the {learning_minutes}-minute baseline learning period."
            ));
            engine.lock().begin_session(None);
            let stop = stop.clone();
            threads.push(thread::spawn(move || run_simulator(learning_minutes, tx, stop)));
        }
        Source::File => {
            crate::platform::pcap_available()?;
            let path = cfg.file_path.clone().filter(|p| !p.is_empty()).ok_or("Choose a .pcap/.pcapng file in Settings first")?;
            let mut cap = pcap::Capture::from_file(&path).map_err(|e| format!("cannot open {path}: {e}"))?;
            if !cfg.bpf_filter.trim().is_empty() {
                cap.filter(cfg.bpf_filter.trim(), true).map_err(|e| format!("invalid BPF filter: {e}"))?;
            }
            let lt = cap.get_datalink().0;
            if !parser::supported_linktype(lt) {
                return Err(format!("unsupported link type {lt} in {path} (need 802.11/radiotap or Ethernet)"));
            }
            info.linktype = Some(parser::linktype_name(lt).into());
            info.file = Some(path);
            engine.lock().begin_session(None);
            let (stop, stats, eng) = (stop.clone(), stats.clone(), engine.clone());
            threads.push(thread::spawn(move || {
                let mut first = true;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match cap.next_packet() {
                        Ok(pkt) => {
                            let ts = ts_from(pkt.header.ts.tv_sec as i64, pkt.header.ts.tv_usec as i64);
                            stats.lock().received += 1;
                            if first {
                                first = false;
                                // Align the engine clock with the capture's start.
                                eng.lock().begin_session(Some(ts));
                            }
                            match parser::parse(lt, pkt.data, ts, pkt.header.len) {
                                Some(p) => {
                                    if tx.send(p).is_err() {
                                        break;
                                    }
                                }
                                None => stats.lock().undecoded += 1,
                            }
                        }
                        Err(pcap::Error::NoMorePackets) => {
                            stats.lock().finished = true;
                            break;
                        }
                        Err(e) => {
                            stats.lock().error = Some(e.to_string());
                            break;
                        }
                    }
                }
            }));
        }
        Source::Live => {
            crate::platform::pcap_available()?;
            let iface = cfg.interface.clone().filter(|s| !s.is_empty()).ok_or("Choose a network interface in Settings first")?;
            info.interface = Some(iface.clone());
            info.monitor_mode = cfg.monitor_mode;

            // Open in the worker thread; report the outcome back synchronously.
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<i32, String>>();
            let (stop2, stats2, cfg2, iface2) = (stop.clone(), stats.clone(), cfg.clone(), iface.clone());
            threads.push(thread::spawn(move || run_live(iface2, cfg2, tx, stop2, stats2, ready_tx)));
            let lt = match ready_rx.recv_timeout(Duration::from_secs(15)) {
                Ok(Ok(lt)) => lt,
                Ok(Err(e)) => {
                    stop.store(true, Ordering::SeqCst);
                    return Err(e);
                }
                Err(_) => {
                    stop.store(true, Ordering::SeqCst);
                    return Err("timed out opening the capture interface".into());
                }
            };
            info.linktype = Some(parser::linktype_name(lt).into());
            let is_80211 = matches!(lt, parser::DLT_IEEE802_11 | parser::DLT_IEEE802_11_RADIO);
            if cfg.monitor_mode && !is_80211 {
                info.notes.push(
                    "Interface delivered Ethernet frames, not raw 802.11 — monitor mode is not active. Device/IP analysis still works for traffic visible to this host."
                        .into(),
                );
            }
            if !is_80211 {
                info.notes.push("RSSI and frame-type (management/control) data are only available in monitor mode.".into());
            } else {
                info.notes.push(
                    "In monitor mode, data frames on WPA2/WPA3 networks are encrypted: IP/DNS/SNI behavior is only visible on open networks or for traffic this host can see in clear."
                        .into(),
                );
            }
            engine.lock().begin_session(None);

            if cfg.monitor_mode && is_80211 {
                if cfg.hop && !cfg.hop_channels.is_empty() {
                    info.hopping = true;
                    let (stop, chan, chans, dwell, iface) =
                        (stop.clone(), channel.clone(), cfg.hop_channels.clone(), cfg.hop_dwell_ms.max(100), iface.clone());
                    // Probe once so the user learns immediately if switching is unsupported.
                    if let Err(e) = set_channel(&iface, chans[0]) {
                        info.notes.push(e);
                        info.hopping = false;
                    } else {
                        threads.push(thread::spawn(move || {
                            let mut i = 0;
                            while !stop.load(Ordering::Relaxed) {
                                let ch = chans[i % chans.len()];
                                if set_channel(&iface, ch).is_ok() {
                                    chan.store(ch, Ordering::Relaxed);
                                }
                                i += 1;
                                let until = Instant::now() + Duration::from_millis(dwell);
                                while Instant::now() < until && !stop.load(Ordering::Relaxed) {
                                    thread::sleep(Duration::from_millis(50));
                                }
                            }
                        }));
                    }
                } else if let Some(ch) = cfg.channel {
                    if let Err(e) = set_channel(&iface, ch) {
                        info.notes.push(e);
                        channel.store(0, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    // Processor: drain the queue in batches, feed the engine, push alerts to the UI.
    {
        let (stop, engine) = (stop.clone(), engine.clone());
        threads.push(thread::spawn(move || run_processor(rx, engine, app, stop)));
    }

    Ok(Session { stop, threads, info, channel })
}

fn run_live(
    iface: String,
    cfg: CaptureSettings,
    tx: Sender<PacketInfo>,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<CaptureStats>>,
    ready: std::sync::mpsc::Sender<Result<i32, String>>,
) {
    let opened = (|| -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
        #[allow(unused_mut)]
        let mut c = pcap::Capture::from_device(iface.as_str())?
            .promisc(cfg.promiscuous)
            .snaplen(4096)
            .timeout(200)
            .immediate_mode(true);
        #[cfg(not(windows))]
        if cfg.monitor_mode {
            c = c.rfmon(true);
        }
        let mut cap = c.open()?;
        if cfg.monitor_mode {
            // Prefer radiotap (gives RSSI + channel) when the driver offers it.
            let _ = cap.set_datalink(pcap::Linktype(parser::DLT_IEEE802_11_RADIO));
        }
        if !cfg.bpf_filter.trim().is_empty() {
            cap.filter(cfg.bpf_filter.trim(), true)?;
        }
        Ok(cap)
    })();
    let mut cap = match opened {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(friendly_error(&e.to_string())));
            return;
        }
    };
    let lt = cap.get_datalink().0;
    if !parser::supported_linktype(lt) {
        let _ = ready.send(Err(format!("unsupported link type {lt} on {iface}")));
        return;
    }
    let _ = ready.send(Ok(lt));

    let mut last_stats = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                let ts = ts_from(pkt.header.ts.tv_sec as i64, pkt.header.ts.tv_usec as i64);
                match parser::parse(lt, pkt.data, ts, pkt.header.len) {
                    Some(p) => match tx.try_send(p) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => stats.lock().queue_dropped += 1,
                        Err(TrySendError::Disconnected(_)) => break,
                    },
                    None => stats.lock().undecoded += 1,
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                stats.lock().error = Some(friendly_error(&e.to_string()));
                break;
            }
        }
        if last_stats.elapsed() >= Duration::from_secs(1) {
            last_stats = Instant::now();
            if let Ok(s) = cap.stats() {
                let mut st = stats.lock();
                st.received = s.received as u64;
                st.dropped = s.dropped as u64;
                st.if_dropped = s.if_dropped as u64;
            }
        }
    }
}

fn run_simulator(learning_minutes: u32, tx: Sender<PacketInfo>, stop: Arc<AtomicBool>) {
    let mut sim = Simulator::new(learning_minutes);
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        for p in sim.step(Utc::now()) {
            if tx.try_send(p).is_err() {
                break;
            }
        }
        next += Duration::from_millis(100);
        let now = Instant::now();
        if next > now {
            thread::sleep(next - now);
        } else {
            next = now;
        }
    }
}

fn run_processor(rx: Receiver<PacketInfo>, engine: Arc<Mutex<Engine>>, app: AppHandle, stop: Arc<AtomicBool>) {
    let mut batch: Vec<PacketInfo> = Vec::with_capacity(4096);
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => batch.push(p),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
        batch.extend(rx.try_iter().take(4095));
        let fresh = {
            let mut eng = engine.lock();
            for p in &batch {
                eng.process(p);
            }
            eng.drain_fresh()
        };
        batch.clear();
        if !fresh.is_empty() {
            let _ = app.emit("niv://alerts", &fresh);
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }
}

