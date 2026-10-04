//! Wi-Fi adapters and monitor mode: which adapters exist, which chipset
//! they use (ALFA cards are Realtek / MediaTek / Ralink / Atheros inside),
//! whether this OS can put them in monitor mode, and switching it.
//!
//! macOS: the built-in Wi-Fi supports monitor mode through libpcap (rfmon);
//! USB adapters have no monitor-mode driver, so they are used as a remote
//! sensor on Linux instead. Linux: `iw` via an admin prompt. Windows: Npcap's
//! WlanHelper.

use serde::Serialize;
use std::process::Command;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Adapter {
    /// Interface name (`en1`, `wlan1`, `Wi-Fi 2`), if the OS exposes one.
    pub iface: Option<String>,
    pub name: String,
    pub chipset: Option<String>,
    pub driver: Option<String>,
    /// USB `vid:pid`.
    pub usb_id: Option<String>,
    pub usb: bool,
    /// Chipset used in ALFA Network adapters.
    pub alfa_chipset: bool,
    /// `managed`, `monitor` or `unknown`.
    pub mode: String,
    /// Can this OS capture raw 802.11 from it?
    pub monitor_supported: bool,
    /// Niv.ON can switch it into / out of monitor mode here.
    pub can_toggle: bool,
    pub note: String,
}

/// Monitor-capable chipsets found in ALFA and similar USB adapters.
const CHIPSETS: &[(&str, &str, &str)] = &[
    (
        "0bda:8812",
        "Realtek RTL8812AU",
        "ALFA AWUS036ACH / AWUS036AC",
    ),
    ("0bda:881a", "Realtek RTL8812AU", "ALFA AWUS036ACH"),
    ("0bda:8813", "Realtek RTL8814AU", "ALFA AWUS1900"),
    ("0bda:a811", "Realtek RTL8811AU", "ALFA AWUS036ACS"),
    ("0bda:8187", "Realtek RTL8187L", "ALFA AWUS036H"),
    ("0bda:b812", "Realtek RTL88x2BU", "ALFA AWUS036ACU"),
    ("0e8d:7612", "MediaTek MT7612U", "ALFA AWUS036ACM"),
    ("0e8d:7610", "MediaTek MT7610U", "ALFA AWUS036ACHM"),
    ("0e8d:7961", "MediaTek MT7921AU", "ALFA AWUS036AXML"),
    ("148f:3070", "Ralink RT3070", "ALFA AWUS036NH"),
    ("148f:5370", "Ralink RT5370", "ALFA AWUS036NEH"),
    ("148f:5572", "Ralink RT5572", "ALFA AWUS052NH"),
    ("0cf3:9271", "Atheros AR9271", "ALFA AWUS036NHA"),
];

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let mut c = Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let out = c.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn chip(usb_id: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    CHIPSETS.iter().find(|c| c.0.eq_ignore_ascii_case(usb_id))
}

/// Safe interface name for shell commands.
pub fn valid_iface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
}

pub fn list() -> Vec<Adapter> {
    if cfg!(target_os = "macos") {
        macos()
    } else if cfg!(target_os = "linux") {
        linux()
    } else {
        windows()
    }
}

fn macos() -> Vec<Adapter> {
    let mut out = vec![];
    if let Some(ports) = run("networksetup", &["-listallhardwareports"]) {
        let mut port = None::<String>;
        for l in ports.lines() {
            if let Some(v) = l.strip_prefix("Hardware Port: ") {
                port = Some(v.trim().into());
            } else if let Some(d) = l.strip_prefix("Device: ") {
                if port.as_deref() == Some("Wi-Fi") {
                    out.push(Adapter {
                        iface: Some(d.trim().into()),
                        name: "Built-in Wi-Fi".into(),
                        chipset: None,
                        driver: None,
                        usb_id: None,
                        usb: false,
                        alfa_chipset: false,
                        mode: "managed".into(),
                        monitor_supported: true,
                        can_toggle: false,
                        note: "Monitor mode works: choose “Monitor mode” as the capture source. macOS leaves the Wi-Fi network while capturing.".into(),
                    });
                }
            }
        }
    }
    // USB Wi-Fi adapters show up in the USB tree even without a driver.
    // Older macOS reports SPUSBDataType (vendor_id/product_id); newer releases
    // report SPUSBHostDataType (USBDeviceKeyVendorID/USBDeviceKeyProductID).
    let mut seen = std::collections::HashSet::new();
    for kind in ["SPUSBHostDataType", "SPUSBDataType"] {
        let Some(json) = run("system_profiler", &["-json", kind]) else {
            continue;
        };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            let mut stack = vec![v];
            while let Some(n) = stack.pop() {
                match n {
                    serde_json::Value::Array(a) => stack.extend(a),
                    serde_json::Value::Object(o) => {
                        let key = |a: &str, b: &str| {
                            o.get(a)
                                .or_else(|| o.get(b))
                                .and_then(|x| x.as_str())
                                .and_then(|s| s.split_whitespace().next())
                                .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
                        };
                        let vid = key("vendor_id", "USBDeviceKeyVendorID");
                        let pid = key("product_id", "USBDeviceKeyProductID");
                        let name = o
                            .get("_name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("USB device")
                            .to_string();
                        if let (Some(vid), Some(pid)) = (vid, pid) {
                            let id = format!("{vid:0>4}:{pid:0>4}");
                            let serial = o
                                .get("serial_num")
                                .or_else(|| o.get("USBDeviceKeySerialNumber"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("");
                            if !seen.insert(format!("{id}/{serial}/{name}")) {
                                stack.extend(o.into_iter().map(|(_, v)| v));
                                continue;
                            }
                            let lname = name.to_ascii_lowercase();
                            if let Some(c) = chip(&id) {
                                out.push(usb_adapter(None, name.clone(), &id, Some(c)));
                            } else if lname.contains("802.11")
                                || lname.contains("wlan")
                                || lname.contains("wireless")
                                || lname.contains("wi-fi")
                            {
                                out.push(usb_adapter(None, name.clone(), &id, None));
                            }
                        }
                        stack.extend(o.into_iter().map(|(_, v)| v));
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

fn usb_adapter(
    iface: Option<String>,
    name: String,
    id: &str,
    c: Option<&(&str, &str, &str)>,
) -> Adapter {
    Adapter {
        iface,
        name: c.map(|c| format!("{name} ({})", c.2)).unwrap_or(name),
        chipset: c.map(|c| c.1.to_string()),
        driver: None,
        usb_id: Some(id.into()),
        usb: true,
        alfa_chipset: c.is_some(),
        mode: "unknown".into(),
        monitor_supported: false,
        can_toggle: false,
        note: "macOS has no monitor-mode driver for USB Wi-Fi chipsets. Plug this adapter into a Linux machine (Raspberry Pi, Kali) and add it under Remote sensor — Niv.ON streams its capture over SSH.".into(),
    }
}

fn read(p: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn linux() -> Vec<Adapter> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for e in rd.flatten() {
        let iface = e.file_name().to_string_lossy().into_owned();
        let p = e.path();
        let Some(phy) = read(&p.join("phy80211/name")) else {
            continue;
        };
        let driver = std::fs::read_link(p.join("device/driver"))
            .ok()
            .and_then(|l| l.file_name().map(|f| f.to_string_lossy().into_owned()));
        // USB interface dir -> parent device holds idVendor / idProduct.
        let dev = std::fs::canonicalize(p.join("device")).ok();
        let usb_id = dev.as_ref().and_then(|d| d.parent()).and_then(|d| {
            Some(format!(
                "{}:{}",
                read(&d.join("idVendor"))?,
                read(&d.join("idProduct"))?
            ))
        });
        let c = usb_id.as_deref().and_then(chip);
        let ty = read(&p.join("type")).unwrap_or_default();
        let mode = match ty.as_str() {
            "803" | "801" | "802" => "monitor",
            "1" => "managed",
            _ => "unknown",
        };
        let info = run("iw", &["phy", &phy, "info"]).unwrap_or_default();
        let supported = info.lines().any(|l| l.trim() == "* monitor");
        out.push(Adapter {
            iface: Some(iface.clone()),
            name: c
                .map(|c| format!("{iface} — {}", c.2))
                .unwrap_or_else(|| format!("{iface} ({phy})")),
            chipset: c.map(|c| c.1.to_string()),
            driver,
            usb: usb_id.is_some(),
            usb_id,
            alfa_chipset: c.is_some(),
            mode: mode.into(),
            monitor_supported: supported,
            can_toggle: supported,
            note: if supported {
                "Switch to monitor mode below, then capture on this interface with “Monitor mode”."
                    .into()
            } else if info.is_empty() {
                "Install the `iw` tool to check monitor-mode support.".into()
            } else {
                "This driver does not advertise monitor mode.".into()
            },
        });
    }
    out
}

fn wlanhelper() -> Option<std::path::PathBuf> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let p = std::path::Path::new(&root)
        .join("System32")
        .join("Npcap")
        .join("WlanHelper.exe");
    p.exists().then_some(p)
}

fn windows() -> Vec<Adapter> {
    let helper = wlanhelper();
    let text = run("netsh", &["wlan", "show", "interfaces"]).unwrap_or_default();
    let mut out = vec![];
    let mut name = None::<String>;
    let mut desc = None::<String>;
    let flush = |out: &mut Vec<Adapter>, name: &mut Option<String>, desc: &mut Option<String>| {
        if let Some(n) = name.take() {
            let mode = helper
                .as_ref()
                .and_then(|h| run(&h.display().to_string(), &[&n, "mode"]))
                .map(|m| m.trim().to_string())
                .unwrap_or_else(|| "unknown".into());
            out.push(Adapter {
                iface: Some(n.clone()),
                name: desc.take().unwrap_or_else(|| n.clone()),
                chipset: None,
                driver: None,
                usb_id: None,
                usb: false,
                alfa_chipset: false,
                mode: if mode.contains("monitor") { "monitor".into() } else if mode.contains("managed") { "managed".into() } else { "unknown".into() },
                monitor_supported: helper.is_some(),
                can_toggle: helper.is_some(),
                note: if helper.is_some() {
                    "Npcap WlanHelper can switch modes (needs “Support raw 802.11 traffic” and Administrator).".into()
                } else {
                    "Install Npcap with “Support raw 802.11 traffic” for monitor mode.".into()
                },
            });
        }
    };
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        match k.trim() {
            "Name" => {
                flush(&mut out, &mut name, &mut desc);
                name = Some(v.trim().to_string());
            }
            "Description" => desc = Some(v.trim().to_string()),
            _ => {}
        }
    }
    flush(&mut out, &mut name, &mut desc);
    out
}

/// Put an adapter in (or out of) monitor mode, optionally on a channel.
pub fn set_monitor(iface: &str, enable: bool, channel: Option<u16>) -> Result<String, String> {
    if !valid_iface(iface) {
        return Err("invalid interface name".into());
    }
    if cfg!(target_os = "linux") {
        let mode = if enable { "monitor" } else { "managed" };
        let mut script = format!(
            "command -v nmcli >/dev/null 2>&1 && nmcli device set '{iface}' managed {nm} >/dev/null 2>&1; ip link set dev '{iface}' down && iw dev '{iface}' set type {mode} && ip link set dev '{iface}' up",
            nm = if enable { "no" } else { "yes" }
        );
        if let (true, Some(ch)) = (enable, channel) {
            script.push_str(&format!(" && iw dev '{iface}' set channel {ch}"));
        }
        let out = Command::new("pkexec")
            .args(["sh", "-c", &script])
            .output()
            .map_err(|e| format!("pkexec not available ({e}). Run as root: {script}"))?;
        return if out.status.success() {
            Ok(format!("{iface} is now in {mode} mode."))
        } else {
            Err(format!(
                "Could not switch {iface}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        };
    }
    if cfg!(windows) {
        let h = wlanhelper().ok_or(
            "Npcap WlanHelper not found — install Npcap with “Support raw 802.11 traffic”.",
        )?;
        let h = h.display().to_string();
        let mode = if enable { "monitor" } else { "managed" };
        let out = Command::new(&h)
            .args([iface, "mode", mode])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "WlanHelper failed (run Niv.ON as Administrator): {}",
                String::from_utf8_lossy(&out.stdout).trim()
            ));
        }
        if let (true, Some(ch)) = (enable, channel) {
            let _ = Command::new(&h)
                .args([iface, "channel", &ch.to_string()])
                .output();
        }
        return Ok(format!("{iface} is now in {mode} mode."));
    }
    Err("On macOS the built-in Wi-Fi enters monitor mode automatically when you capture with “Monitor mode”. USB adapters (ALFA) have no macOS monitor-mode driver — use them as a Remote sensor on Linux.".into())
}

/// Shell command run on a Linux sensor: monitor mode on, optional channel
/// hopping, then tcpdump writing pcap to stdout (SSH traffic excluded).
pub fn remote_command(
    iface: &str,
    channel: u16,
    hop: bool,
    monitor: bool,
) -> Result<String, String> {
    if !valid_iface(iface) || iface.contains(' ') {
        return Err("invalid remote interface name".into());
    }
    let mut s = String::new();
    if monitor {
        s.push_str(&format!("ip link set {iface} down; iw dev {iface} set type monitor; ip link set {iface} up; iw dev {iface} set channel {channel}; "));
        if hop {
            s.push_str(&format!(
                "(while :; do for c in 1 6 11 2 7 3 8 4 9 5 10 36 40 44 48 149 153 157 161; do iw dev {iface} set channel $c 2>/dev/null; sleep 0.4; done; done) & "
            ));
        }
    }
    s.push_str(&format!(
        "exec tcpdump -i {iface} -U -s 4096 -w - not port 22"
    ));
    Ok(format!("sudo -n sh -c '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chipsets_and_commands() {
        assert_eq!(chip("0BDA:8812").unwrap().1, "Realtek RTL8812AU");
        assert!(valid_iface("wlan1") && valid_iface("Wi-Fi 2") && !valid_iface("wlan1;rm -rf /"));
        let c = remote_command("wlan1", 6, true, true).unwrap();
        assert!(
            c.starts_with("sudo -n sh -c '")
                && c.contains("iw dev wlan1 set type monitor")
                && c.ends_with("not port 22'")
        );
        assert!(remote_command("wlan1 x", 6, false, false).is_err());
        assert_eq!(
            remote_command("eth0", 1, false, false).unwrap(),
            "sudo -n sh -c 'exec tcpdump -i eth0 -U -s 4096 -w - not port 22'"
        );
    }

    /// `cargo test real_adapters -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_adapters() {
        for a in list() {
            println!("{a:?}");
        }
    }
}
