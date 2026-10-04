//! Cross-platform network interface discovery, capture permission checks,
//! interface self-test and active ARP discovery.
//!
//! libpcap only gives raw names (`en0`, `\Device\NPF_{GUID}`, `wlp2s0`), so
//! we enrich them with OS tooling: `networksetup` + `route` on macOS,
//! `/sys/class/net` + `/proc/net/route` on Linux, `getmac` + `route print`
//! on Windows.

use crate::parser;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IfKind {
    Wifi,
    Ethernet,
    Loopback,
    Vpn,
    Virtual,
    Other,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    /// libpcap device name (what we open).
    pub name: String,
    /// Human name, e.g. "Wi-Fi", "Ethernet", "Intel(R) Wi-Fi 6 AX201".
    pub friendly: String,
    pub description: Option<String>,
    pub kind: IfKind,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// CIDR of the first IPv4 network, e.g. 192.168.1.0/24.
    pub network: Option<String>,
    pub up: bool,
    pub running: bool,
    /// Carries the default route - the one to pick for "my network".
    pub is_default: bool,
    pub gateway: Option<String>,
    /// Noise (tunnels, virtual, AWDL, down) - hidden unless "show all".
    pub hidden: bool,
}

struct OsInfo {
    friendly: Option<String>,
    mac: Option<String>,
    kind: Option<IfKind>,
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let mut c = Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = c.output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn kind_from_text(t: &str) -> Option<IfKind> {
    let l = t.to_lowercase();
    if l.contains("wi-fi") || l.contains("wifi") || l.contains("wireless") || l.contains("wlan") || l.contains("802.11") || l.contains("airport") {
        Some(IfKind::Wifi)
    } else if l.contains("loopback") {
        Some(IfKind::Loopback)
    } else if ["vpn", "tap-", "tap ", "wireguard", "tunnel", "tailscale", "zerotier", "openvpn"].iter().any(|k| l.contains(k)) {
        Some(IfKind::Vpn)
    } else if ["virtual", "hyper-v", "vmware", "virtualbox", "docker", "wsl", "bridge"].iter().any(|k| l.contains(k)) {
        Some(IfKind::Virtual)
    } else if l.contains("bluetooth") {
        Some(IfKind::Other)
    } else if l.contains("ethernet") || l.contains("lan") || l.contains("gbe") || l.contains("usb") || l.contains("thunderbolt") {
        Some(IfKind::Ethernet)
    } else {
        None
    }
}

fn kind_from_name(n: &str) -> IfKind {
    let n = n.to_lowercase();
    let starts = |p: &[&str]| p.iter().any(|x| n.starts_with(x));
    if starts(&["lo"]) {
        IfKind::Loopback
    } else if starts(&["utun", "tun", "ipsec", "ppp", "wg", "tailscale", "zt", "gif", "stf"]) {
        IfKind::Vpn
    } else if starts(&["wl", "wlan", "ath", "ra", "mon"]) {
        IfKind::Wifi
    } else if starts(&["awdl", "llw", "anpi", "ap", "nan", "bridge", "br", "docker", "veth", "virbr", "vmnet", "vboxnet", "xhc", "pktap", "any", "nflog", "nfqueue", "dbus", "bluetooth", "usbmon", "ciscodump", "randpkt", "sshdump", "udpdump", "etwdump"]) {
        IfKind::Virtual
    } else if starts(&["en", "eth", "em", "eno", "ens", "enp", "enx"]) {
        IfKind::Ethernet
    } else {
        IfKind::Other
    }
}

/// Platform-specific enrichment keyed by pcap device name.
fn os_info() -> HashMap<String, OsInfo> {
    let mut m = HashMap::new();
    if cfg!(target_os = "macos") {
        // Hardware Port: Wi-Fi / Device: en0 / Ethernet Address: aa:bb:..
        if let Some(out) = run("networksetup", &["-listallhardwareports"]) {
            let (mut port, mut dev) = (None::<String>, None::<String>);
            for line in out.lines() {
                if let Some(v) = line.strip_prefix("Hardware Port: ") {
                    port = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("Device: ") {
                    dev = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("Ethernet Address: ") {
                    if let (Some(p), Some(d)) = (port.take(), dev.take()) {
                        let kind = kind_from_text(&p);
                        let mac = Some(v.trim().to_lowercase()).filter(|s| s.contains(':'));
                        m.insert(d, OsInfo { friendly: Some(p), mac, kind });
                    }
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let p = e.path();
                let wireless = p.join("wireless").exists() || p.join("phy80211").exists();
                let physical = p.join("device").exists();
                let mac = std::fs::read_to_string(p.join("address")).ok().map(|s| s.trim().to_string()).filter(|s| s != "00:00:00:00:00:00");
                let kind = if wireless {
                    Some(IfKind::Wifi)
                } else if physical {
                    Some(IfKind::Ethernet)
                } else {
                    None
                };
                let friendly = match kind {
                    Some(IfKind::Wifi) => Some("Wi-Fi".to_string()),
                    Some(IfKind::Ethernet) => Some("Ethernet".to_string()),
                    _ => None,
                };
                m.insert(name, OsInfo { friendly, mac, kind });
            }
        }
    } else if cfg!(windows) {
        // "Connection Name","Network Adapter","Physical Address","Transport Name"
        if let Some(out) = run("getmac", &["/fo", "csv", "/nh", "/v"]) {
            for line in out.lines() {
                let cols: Vec<String> = line.split("\",\"").map(|c| c.trim_matches('"').trim().to_string()).collect();
                if cols.len() < 4 {
                    continue;
                }
                if let (Some(a), Some(b)) = (cols[3].find('{'), cols[3].find('}')) {
                    let guid = &cols[3][a..=b];
                    let mac = Some(cols[2].replace('-', ":").to_lowercase()).filter(|s| s.len() == 17);
                    let kind = kind_from_text(&cols[0]).or_else(|| kind_from_text(&cols[1]));
                    m.insert(
                        format!("\\Device\\NPF_{guid}"),
                        OsInfo { friendly: Some(format!("{} — {}", cols[0], cols[1])), mac, kind },
                    );
                }
            }
        }
    }
    m
}

/// (default interface name or IP, gateway IP)
fn default_route() -> (Option<String>, Option<String>) {
    if cfg!(target_os = "macos") {
        if let Some(out) = run("route", &["-n", "get", "default"]) {
            let get = |k: &str| out.lines().find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_string()));
            return (get("interface:"), get("gateway:"));
        }
    } else if cfg!(target_os = "linux") {
        if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
            for l in t.lines().skip(1) {
                let c: Vec<&str> = l.split_whitespace().collect();
                if c.len() > 2 && c[1] == "00000000" {
                    let gw = u32::from_str_radix(c[2], 16).ok().map(|g| Ipv4Addr::from(g.swap_bytes()).to_string());
                    return (Some(c[0].to_string()), gw);
                }
            }
        }
    } else if cfg!(windows) {
        // Network Destination  Netmask  Gateway  Interface  Metric
        if let Some(out) = run("route", &["print", "-4", "0.0.0.0"]) {
            let mut best: Option<(u32, String, String)> = None;
            for l in out.lines() {
                let c: Vec<&str> = l.split_whitespace().collect();
                if c.len() >= 5 && c[0] == "0.0.0.0" && c[1] == "0.0.0.0" {
                    let metric = c[4].parse().unwrap_or(u32::MAX);
                    if best.as_ref().is_none_or(|b| metric < b.0) {
                        best = Some((metric, c[3].to_string(), c[2].to_string()));
                    }
                }
            }
            if let Some((_, ip, gw)) = best {
                return (Some(ip), Some(gw));
            }
        }
    }
    (None, None)
}

fn prefix_len(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

pub fn list() -> Result<Vec<Interface>, String> {
    crate::platform::pcap_available()?;
    let devs = pcap::Device::list().map_err(|e| crate::capture::friendly_error(&e.to_string()))?;
    let os = os_info();
    let (def_if, gateway) = default_route();
    let mut v: Vec<Interface> = devs
        .into_iter()
        .map(|d| {
            let info = os.get(&d.name);
            let ipv4: Vec<(Ipv4Addr, Option<Ipv4Addr>)> = d
                .addresses
                .iter()
                .filter_map(|a| match (a.addr, a.netmask) {
                    (std::net::IpAddr::V4(ip), Some(std::net::IpAddr::V4(m))) => Some((ip, Some(m))),
                    (std::net::IpAddr::V4(ip), _) => Some((ip, None)),
                    _ => None,
                })
                .collect();
            let ipv6 = d.addresses.iter().filter(|a| a.addr.is_ipv6()).map(|a| a.addr.to_string()).collect();
            let network = ipv4.iter().find_map(|(ip, m)| {
                let m = (*m)?;
                let net = Ipv4Addr::from(u32::from(*ip) & u32::from(m));
                Some(format!("{net}/{}", prefix_len(m)))
            });
            let mut kind = info
                .and_then(|i| i.kind.clone())
                .or_else(|| d.desc.as_deref().and_then(kind_from_text))
                .unwrap_or_else(|| kind_from_name(&d.name));
            if d.flags.is_loopback() {
                kind = IfKind::Loopback;
            } else if d.flags.is_wireless() && kind != IfKind::Virtual {
                kind = IfKind::Wifi;
            }
            let is_default = def_if.as_deref().is_some_and(|di| di == d.name || ipv4.iter().any(|(ip, _)| ip.to_string() == di));
            let friendly = info.and_then(|i| i.friendly.clone()).or_else(|| d.desc.clone()).unwrap_or_else(|| {
                match kind {
                    IfKind::Wifi => "Wi-Fi",
                    IfKind::Ethernet => "Ethernet",
                    IfKind::Loopback => "Loopback",
                    IfKind::Vpn => "VPN / tunnel",
                    IfKind::Virtual => "Virtual",
                    IfKind::Other => "Other",
                }
                .to_string()
            });
            let up = d.flags.is_up();
            let hidden = !is_default && (matches!(kind, IfKind::Loopback | IfKind::Vpn | IfKind::Virtual | IfKind::Other) || !up);
            Interface {
                friendly,
                description: d.desc.clone(),
                kind,
                mac: info.and_then(|i| i.mac.clone()),
                ipv4: ipv4.iter().map(|(ip, _)| ip.to_string()).collect(),
                ipv6,
                network,
                up,
                running: d.flags.is_running(),
                gateway: if is_default { gateway.clone() } else { None },
                is_default,
                hidden,
                name: d.name,
            }
        })
        .collect();
    v.sort_by_key(|i| {
        (
            !i.is_default,
            i.hidden,
            match i.kind {
                IfKind::Wifi => 0,
                IfKind::Ethernet => 1,
                _ => 2,
            },
            i.ipv4.is_empty(),
            i.name.clone(),
        )
    });
    Ok(v)
}

// ---------------------------------------------------------------------------
// Network identity (which network is this?)
// ---------------------------------------------------------------------------

/// Normalise "0:1a:2b:3:4:5" / "00-1A-2B-03-04-05" to "00:1a:2b:03:04:05".
fn norm_mac(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let bytes: Option<Vec<u8>> = parts.iter().map(|p| u8::from_str_radix(p, 16).ok()).collect();
    let b = bytes?;
    if b.iter().all(|x| *x == 0) || b.iter().all(|x| *x == 0xff) {
        return None;
    }
    Some(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
}

/// Router MAC from the OS ARP cache — a stable fingerprint for "this network".
/// The cache entry expires after a few minutes, so on a miss we ping the
/// gateway once to refresh it and look again.
pub fn gateway_mac(gateway: &str) -> Option<String> {
    let lookup = || -> Option<String> {
        if cfg!(target_os = "linux") {
            if let Ok(t) = std::fs::read_to_string("/proc/net/arp") {
                if let Some(m) = t.lines().filter(|l| l.split_whitespace().next() == Some(gateway)).find_map(|l| l.split_whitespace().nth(3).and_then(norm_mac)) {
                    return Some(m);
                }
            }
        }
        let out = if cfg!(windows) { run("arp", &["-a", gateway]) } else { run("arp", &["-n", gateway]) }?;
        out.lines().filter(|l| l.contains(gateway)).flat_map(|l| l.split_whitespace()).find_map(norm_mac)
    };
    lookup().or_else(|| {
        let _ = if cfg!(windows) {
            run("ping", &["-n", "1", "-w", "1000", gateway])
        } else if cfg!(target_os = "macos") {
            run("ping", &["-c", "1", "-t", "1", gateway])
        } else {
            run("ping", &["-c", "1", "-W", "1", gateway])
        };
        lookup()
    })
}

/// Wi-Fi network name for an interface, when the OS will tell us.
pub fn current_ssid(iface: &str) -> Option<String> {
    let found = if cfg!(target_os = "macos") {
        run("ipconfig", &["getsummary", iface])?
            .lines()
            .find_map(|l| l.trim().strip_prefix("SSID : ").map(str::to_string))
    } else if cfg!(target_os = "linux") {
        run("iwgetid", &[iface, "-r"]).map(|s| s.trim().to_string())
    } else {
        run("netsh", &["wlan", "show", "interfaces"])?
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim() == "SSID").then(|| v.trim().to_string())
            })
    };
    found.filter(|s| !s.is_empty() && !s.contains("redacted"))
}

#[derive(Clone, Debug)]
pub struct NetIdentity {
    pub id: String,
    pub name: String,
    pub subnet: Option<String>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
}

/// Work out which network an interface is attached to.
pub fn identify(i: &Interface) -> NetIdentity {
    let gw_mac = i.gateway.as_deref().and_then(gateway_mac);
    let ssid = if i.kind == IfKind::Wifi { current_ssid(&i.name) } else { None };
    let id = match (&gw_mac, &i.network, &i.gateway) {
        (Some(m), _, _) => format!("net:{m}"),
        (None, Some(net), Some(gw)) => format!("net:{net}@{gw}"),
        (None, Some(net), None) => format!("net:{net}"),
        _ => format!("iface:{}", i.name),
    };
    let name = ssid.clone().unwrap_or_else(|| match &i.network {
        Some(net) => format!("{} · {net}", i.friendly),
        None => format!("{} ({})", i.friendly, i.name),
    });
    NetIdentity { id, name, subnet: i.network.clone(), gateway_mac: gw_mac, ssid }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub ok: bool,
    pub message: String,
    /// The app can attempt an automatic fix (admin prompt).
    pub can_fix: bool,
    pub platform: &'static str,
}

pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

/// Try to open the default interface (no monitor/promisc) to see whether
/// the current user may capture at all.
pub fn check_access() -> Access {
    if let Err(e) = crate::platform::pcap_available() {
        return Access { ok: false, message: e, can_fix: false, platform: platform() };
    }
    let ifs = list().unwrap_or_default();
    let Some(target) = ifs.iter().find(|i| !i.hidden).or(ifs.first()) else {
        return Access {
            ok: false,
            message: if cfg!(windows) {
                "No capture interfaces found. Install Npcap from https://npcap.com (tick \"Support raw 802.11 traffic\") and restart Niv.ON.".into()
            } else {
                "No capture interfaces found — libpcap could not list devices (missing permissions?).".into()
            },
            can_fix: !cfg!(windows),
            platform: platform(),
        };
    };
    let res = pcap::Capture::from_device(target.name.as_str()).and_then(|c| c.timeout(50).snaplen(64).open());
    match res {
        Ok(_) => Access { ok: true, message: format!("Capture access OK (tested on {}).", target.name), can_fix: false, platform: platform() },
        Err(e) => Access {
            ok: false,
            message: crate::capture::friendly_error(&e.to_string()),
            can_fix: !cfg!(windows),
            platform: platform(),
        },
    }
}

/// Grant capture rights through the OS's own elevation prompt.
pub fn fix_access() -> Result<String, String> {
    if cfg!(target_os = "macos") {
        // Same approach as Wireshark's ChmodBPF: let the admin group read BPF.
        let script = r#"do shell script "chgrp admin /dev/bpf* && chmod g+rw /dev/bpf*" with prompt "Niv.ON needs permission to capture network packets (grants the admin group access to /dev/bpf until reboot)." with administrator privileges"#;
        let out = Command::new("osascript").args(["-e", script]).output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok("Capture access granted until the next reboot. For a permanent fix install Wireshark's ChmodBPF package.".into())
        } else {
            Err(format!("Not granted: {}", String::from_utf8_lossy(&out.stderr).trim()))
        }
    } else if cfg!(target_os = "linux") {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let out = Command::new("pkexec")
            .args(["setcap", "cap_net_raw,cap_net_admin=eip"])
            .arg(&exe)
            .output()
            .map_err(|e| format!("pkexec not available ({e}). Run: sudo setcap cap_net_raw,cap_net_admin=eip {}", exe.display()))?;
        if out.status.success() {
            Ok("Capabilities granted. Restart Niv.ON to apply them.".into())
        } else {
            Err(format!("Not granted: {}", String::from_utf8_lossy(&out.stderr).trim()))
        }
    } else {
        Err("On Windows, install Npcap (https://npcap.com) and restart Niv.ON. For monitor mode, run Niv.ON as Administrator.".into())
    }
}

// ---------------------------------------------------------------------------
// Interface self-test
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    pub ok: bool,
    pub linktype: Option<String>,
    pub packets: u64,
    pub decoded: u64,
    pub with_rssi: u64,
    pub seconds: f64,
    pub message: String,
}

/// Open the interface the way a capture would and listen for ~3 seconds.
pub fn test_interface(name: &str, monitor: bool, promisc: bool) -> TestResult {
    let started = Instant::now();
    if let Err(e) = crate::platform::pcap_available() {
        return TestResult { ok: false, linktype: None, packets: 0, decoded: 0, with_rssi: 0, seconds: 0.0, message: e };
    }
    let opened = (|| {
        #[allow(unused_mut)]
        let mut c = pcap::Capture::from_device(name)?.promisc(promisc).snaplen(4096).timeout(200).immediate_mode(true);
        #[cfg(not(windows))]
        if monitor {
            c = c.rfmon(true);
        }
        let mut cap = c.open()?;
        if monitor {
            let _ = cap.set_datalink(pcap::Linktype(parser::DLT_IEEE802_11_RADIO));
        }
        Ok::<_, pcap::Error>(cap)
    })();
    let mut cap = match opened {
        Ok(c) => c,
        Err(e) => {
            return TestResult {
                ok: false,
                linktype: None,
                packets: 0,
                decoded: 0,
                with_rssi: 0,
                seconds: started.elapsed().as_secs_f64(),
                message: crate::capture::friendly_error(&e.to_string()),
            }
        }
    };
    let lt = cap.get_datalink().0;
    let (mut packets, mut decoded, mut with_rssi) = (0u64, 0u64, 0u64);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(p) => {
                packets += 1;
                if let Some(info) = parser::parse(lt, p.data, chrono::Utc::now(), p.header.len) {
                    decoded += 1;
                    if info.rssi.is_some() {
                        with_rssi += 1;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(_) => break,
        }
    }
    let is_80211 = matches!(lt, parser::DLT_IEEE802_11 | parser::DLT_IEEE802_11_RADIO);
    let mut message = if !parser::supported_linktype(lt) {
        format!("Opened, but link type {lt} is not supported.")
    } else if packets == 0 {
        "Opened successfully but no packets arrived in 3 s. Check the interface is connected (or the channel has traffic).".into()
    } else {
        format!("Working — {packets} packets in 3 s.")
    };
    if monitor && !is_80211 && parser::supported_linktype(lt) {
        message.push_str(" Monitor mode is NOT active (got Ethernet frames) — this adapter/driver doesn't support it here.");
    } else if monitor && is_80211 {
        message.push_str(" Monitor mode active ✓ (raw 802.11).");
    }
    TestResult {
        ok: parser::supported_linktype(lt) && packets > 0,
        linktype: Some(parser::linktype_name(lt).into()),
        packets,
        decoded,
        with_rssi,
        seconds: started.elapsed().as_secs_f64(),
        message,
    }
}

// ---------------------------------------------------------------------------
// Active discovery (ARP sweep)
// ---------------------------------------------------------------------------

/// Send one ARP request to every address of the interface's IPv4 subnet
/// (capped at /22). Replies are picked up by the running capture.
pub fn arp_sweep(iface: &str, own_mac: [u8; 6]) -> Result<usize, String> {
    crate::platform::pcap_available()?;
    let dev = pcap::Device::list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or("interface not found")?;
    let (ip, mask) = dev
        .addresses
        .iter()
        .find_map(|a| match (a.addr, a.netmask) {
            (std::net::IpAddr::V4(ip), Some(std::net::IpAddr::V4(m))) => Some((ip, m)),
            _ => None,
        })
        .ok_or("this interface has no IPv4 address — connect it to a network first")?;
    let prefix = prefix_len(mask).max(22);
    let host_bits = 32 - prefix;
    let net = u32::from(ip) & (!0u32 << host_bits);
    let count = (1u32 << host_bits).saturating_sub(2);

    let mut cap = pcap::Capture::from_device(iface)
        .and_then(|c| c.timeout(50).snaplen(64).open())
        .map_err(|e| crate::capture::friendly_error(&e.to_string()))?;
    if cap.get_datalink().0 != parser::DLT_EN10MB {
        return Err("Active discovery needs a normal (managed-mode) Ethernet/Wi-Fi capture, not monitor mode.".into());
    }
    let mut frame = Vec::with_capacity(42);
    let mut sent = 0;
    for h in 1..=count {
        let target = Ipv4Addr::from(net + h);
        if target == ip {
            continue;
        }
        frame.clear();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&own_mac);
        frame.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
        frame.extend_from_slice(&own_mac);
        frame.extend_from_slice(&ip.octets());
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&target.octets());
        if cap.sendpacket(&frame[..]).is_ok() {
            sent += 1;
        }
        // ~500 requests/s - gentle on the network
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(sent)
}

pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    s.parse::<crate::model::Mac>().ok().map(|m| m.0)
}

#[cfg(test)]
mod tests {
    /// Manual check against the real machine: `cargo test real_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_interfaces_and_access() {
        for i in super::list().unwrap().iter().filter(|i| !i.hidden) {
            println!("{} | {} | {:?} | mac={:?} ip={:?} net={:?} default={} gw={:?}", i.name, i.friendly, i.kind, i.mac, i.ipv4, i.network, i.is_default, i.gateway);
        }
        println!("{:?}", super::check_access());
        if let Some(d) = super::list().unwrap().iter().find(|i| i.is_default) {
            println!("identity: {:?}", super::identify(d));
        }
    }

    /// End-to-end on the real network: capture 20 s on the default interface,
    /// ARP-sweep the subnet, run everything through parser + engine and print
    /// what was learned. `cargo test real_capture -- --ignored --nocapture`
    #[test]
    #[ignore]
    #[allow(clippy::unnecessary_cast)]
    fn real_capture() {
        use crate::engine::Engine;
        use crate::oui::OuiDb;
        use crate::settings::RuleSettings;
        use std::time::{Duration, Instant};

        let ifs = super::list().unwrap();
        let i = ifs.iter().find(|i| i.is_default).expect("no default interface");
        println!("capturing on {} ({}) {:?} gw {:?}", i.name, i.friendly, i.ipv4, i.gateway);
        let r = super::test_interface(&i.name, false, true);
        println!("self-test: {r:?}");
        assert!(r.linktype.is_some(), "cannot open interface: {}", r.message);

        // NIV_DATA_DIR may point at a folder holding oui.csv / manuf for vendor names.
        let data = std::env::var("NIV_DATA_DIR").ok().map(std::path::PathBuf::from);
        let mut eng = Engine::new(RuleSettings::default(), OuiDb::load(data.as_deref()));
        eng.self_hostname = std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().trim_end_matches(".local").to_string());
        eng.self_macs.extend(i.mac.as_deref().and_then(|m| m.parse::<crate::model::Mac>().ok()));
        eng.self_ips.extend(i.ipv4.iter().filter_map(|a| a.parse::<std::net::IpAddr>().ok()));
        eng.gateway_ip = i.gateway.as_deref().and_then(|g| g.parse().ok());

        let mut cap = pcap::Capture::from_device(i.name.as_str()).unwrap().promisc(true).snaplen(4096).timeout(200).immediate_mode(true).open().unwrap();
        let lt = cap.get_datalink().0;
        let (name, mac) = (i.name.clone(), i.mac.as_deref().and_then(super::parse_mac_str).unwrap());
        let sweeper = std::thread::spawn(move || super::arp_sweep(&name, mac));
        let (mut pk, mut dec) = (0, 0);
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if let Ok(p) = cap.next_packet() {
                pk += 1;
                let ts = crate::capture::ts_now_from(p.header.ts.tv_sec as i64, p.header.ts.tv_usec as i64);
                if let Some(info) = crate::parser::parse(lt, p.data, ts, p.header.len) {
                    dec += 1;
                    eng.process(&info);
                }
            }
        }
        println!("ARP sweep: {:?}", sweeper.join().unwrap());
        eng.tick(None);
        println!("packets {pk}, decoded {dec}, devices {}", eng.devices.len());
        for d in eng.summaries() {
            println!(
                "  {:<28} {:<22} {} {:<16} {:<22} self={} gw={} hosts={}",
                d.label, d.class, d.mac, d.ips.iter().find(|x| x.is_ipv4()).map(|x| x.to_string()).unwrap_or_default(),
                d.vendor.unwrap_or_default(), d.is_self, d.is_gateway, d.destinations
            );
        }
        for f in eng.feed.iter().rev().take(15) {
            println!("  feed: {:<12} {}", f.protocol, f.info);
        }
        assert!(dec > 0);
    }
}
