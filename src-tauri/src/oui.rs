//! MAC vendor lookup and heuristic device classification.
//!
//! The built-in OUI table is a small starter set of vendors common on home /
//! lab networks. For full coverage drop Wireshark's `manuf` file
//! (https://www.wireshark.org/download/automated/data/manuf) into the app data
//! directory - it is loaded on start-up and takes precedence.

use crate::model::Mac;
use std::collections::HashMap;
use std::path::Path;

const BUILTIN: &[(&str, &str)] = &[
    // Single-board computers / IoT chipsets
    ("b8:27:eb", "Raspberry Pi"),
    ("dc:a6:32", "Raspberry Pi"),
    ("e4:5f:01", "Raspberry Pi"),
    ("d8:3a:dd", "Raspberry Pi"),
    ("2c:cf:67", "Raspberry Pi"),
    ("24:0a:c4", "Espressif"),
    ("30:ae:a4", "Espressif"),
    ("84:cc:a8", "Espressif"),
    ("a4:cf:12", "Espressif"),
    ("24:6f:28", "Espressif"),
    ("7c:9e:bd", "Espressif"),
    ("ec:fa:bc", "Espressif"),
    ("5c:cf:7f", "Espressif"),
    ("60:01:94", "Espressif"),
    ("18:fe:34", "Espressif"),
    ("68:c6:3a", "Espressif"),
    ("bc:dd:c2", "Espressif"),
    ("c8:2b:96", "Espressif"),
    ("3c:71:bf", "Espressif"),
    ("8c:aa:b5", "Espressif"),
    // Cameras
    ("44:19:b6", "Hikvision"),
    ("c0:56:e3", "Hikvision"),
    ("bc:ad:28", "Hikvision"),
    ("4c:bd:8f", "Hikvision"),
    ("28:57:be", "Hikvision"),
    ("54:c4:15", "Hikvision"),
    ("3c:ef:8c", "Dahua"),
    ("90:02:a9", "Dahua"),
    ("e0:50:8b", "Dahua"),
    ("4c:11:bf", "Dahua"),
    ("14:a7:8b", "Dahua"),
    ("2c:aa:8e", "Wyze Labs"),
    ("d0:3f:27", "Wyze Labs"),
    // Smart home
    ("18:b4:30", "Nest Labs"),
    ("64:16:66", "Nest Labs"),
    ("44:61:32", "ecobee"),
    ("00:17:88", "Philips Lighting (Signify)"),
    ("ec:b5:fa", "Philips Lighting (Signify)"),
    ("00:0e:58", "Sonos"),
    ("94:9f:3e", "Sonos"),
    ("5c:aa:fd", "Sonos"),
    ("48:a6:b8", "Sonos"),
    ("b8:e9:37", "Sonos"),
    ("78:28:ca", "Sonos"),
    ("b0:a7:37", "Roku"),
    ("dc:3a:5e", "Roku"),
    ("d8:31:34", "Roku"),
    ("08:05:81", "Roku"),
    ("ac:3a:7a", "Roku"),
    // Amazon / Google
    ("44:65:0d", "Amazon"),
    ("f0:d2:f1", "Amazon"),
    ("74:c2:46", "Amazon"),
    ("68:54:fd", "Amazon"),
    ("fc:65:de", "Amazon"),
    ("0c:47:c9", "Amazon"),
    ("84:d6:d0", "Amazon"),
    ("38:f7:3d", "Amazon"),
    ("40:b4:cd", "Amazon"),
    ("a0:02:dc", "Amazon"),
    ("f4:f5:d8", "Google"),
    ("f4:f5:e8", "Google"),
    ("54:60:09", "Google"),
    ("3c:5a:b4", "Google"),
    ("f8:8f:ca", "Google"),
    ("d8:6c:63", "Google"),
    ("1c:f2:9a", "Google"),
    // Phones / computers
    ("f0:18:98", "Apple"),
    ("ac:bc:32", "Apple"),
    ("3c:22:fb", "Apple"),
    ("a4:83:e7", "Apple"),
    ("88:66:5a", "Apple"),
    ("f4:0f:24", "Apple"),
    ("bc:d0:74", "Apple"),
    ("8c:85:90", "Apple"),
    ("00:1c:b3", "Apple"),
    ("28:cf:e9", "Apple"),
    ("d0:81:7a", "Apple"),
    ("14:7d:da", "Apple"),
    ("70:56:81", "Apple"),
    ("8c:77:12", "Samsung"),
    ("5c:0a:5b", "Samsung"),
    ("84:25:db", "Samsung"),
    ("f4:7b:5e", "Samsung"),
    ("34:14:5f", "Samsung"),
    ("bc:44:86", "Samsung"),
    ("00:1b:21", "Intel"),
    ("3c:a9:f4", "Intel"),
    ("a4:34:d9", "Intel"),
    ("7c:5c:f8", "Intel"),
    ("8c:8d:28", "Intel"),
    ("f8:94:c2", "Intel"),
    ("28:18:78", "Microsoft"),
    ("7c:1e:52", "Microsoft"),
    ("f8:bc:12", "Dell"),
    ("b8:ca:3a", "Dell"),
    ("18:db:f2", "Dell"),
    // Network gear
    ("50:c7:bf", "TP-Link"),
    ("98:da:c4", "TP-Link"),
    ("60:32:b1", "TP-Link"),
    ("b0:be:76", "TP-Link"),
    ("1c:3b:f3", "TP-Link"),
    ("ec:08:6b", "TP-Link"),
    ("f4:f2:6d", "TP-Link"),
    ("c0:06:c3", "TP-Link"),
    ("24:a4:3c", "Ubiquiti"),
    ("44:d9:e7", "Ubiquiti"),
    ("78:8a:20", "Ubiquiti"),
    ("f0:9f:c2", "Ubiquiti"),
    ("80:2a:a8", "Ubiquiti"),
    ("fc:ec:da", "Ubiquiti"),
    ("a0:40:a0", "Netgear"),
    ("20:e5:2a", "Netgear"),
    ("9c:3d:cf", "Netgear"),
    ("c0:3f:0e", "Netgear"),
];

pub struct OuiDb {
    map: HashMap<[u8; 3], String>,
    pub external_entries: usize,
}

fn parse_prefix(s: &str) -> Option<[u8; 3]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    let b = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some([b(0)?, b(2)?, b(4)?])
}

/// Split one CSV line honoring double quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// "Hangzhou Hikvision Digital Technology Co.,Ltd." -> "Hangzhou Hikvision Digital Technology"
pub fn clean_vendor(name: &str) -> String {
    let mut n = name.trim().trim_end_matches('.').trim().to_string();
    const SUFFIXES: &[&str] = &[
        " co.,ltd",
        " co., ltd",
        " co.,ltd.",
        " co. ltd",
        " co ltd",
        ", inc",
        " inc",
        " corporation",
        " corp",
        " limited",
        " ltd",
        " llc",
        " gmbh",
        " s.a",
        " ag",
        " b.v",
        " oy",
        " ab",
        " pty",
        ",",
    ];
    loop {
        let lower = n.to_lowercase();
        match SUFFIXES.iter().find(|s| lower.ends_with(*s)) {
            Some(s) => {
                n = n[..n.len() - s.len()]
                    .trim()
                    .trim_end_matches('.')
                    .trim()
                    .to_string()
            }
            None => break,
        }
    }
    if n.is_empty() {
        name.trim().to_string()
    } else {
        n
    }
}

pub const IEEE_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

impl OuiDb {
    pub fn load(data_dir: Option<&Path>) -> Self {
        let mut map: HashMap<[u8; 3], String> = BUILTIN
            .iter()
            .filter_map(|(p, v)| Some((parse_prefix(p)?, v.to_string())))
            .collect();
        let mut external_entries = 0;
        // IEEE registry (downloaded from the app): Registry,Assignment,Organization Name,...
        if let Some(text) = data_dir.and_then(|d| std::fs::read_to_string(d.join("oui.csv")).ok()) {
            for line in text.lines().skip(1) {
                let f = csv_fields(line);
                if f.len() >= 3 && f[0] == "MA-L" {
                    if let Some(p) = parse_prefix(&f[1]) {
                        map.insert(p, clean_vendor(&f[2]));
                        external_entries += 1;
                    }
                }
            }
        }
        if let Some(text) = data_dir.and_then(|d| std::fs::read_to_string(d.join("manuf")).ok()) {
            for line in text.lines() {
                if line.starts_with('#') {
                    continue;
                }
                let cols: Vec<&str> = line.split('\t').collect();
                // Only plain /24 prefixes ("00:11:22"); skip /28, /36 blocks.
                if cols.len() < 2 || cols[0].contains('/') {
                    continue;
                }
                if let Some(p) = parse_prefix(cols[0]) {
                    let name = cols.get(2).filter(|s| !s.is_empty()).unwrap_or(&cols[1]);
                    map.insert(p, name.trim().to_string());
                    external_entries += 1;
                }
            }
        }
        OuiDb {
            map,
            external_entries,
        }
    }

    pub fn lookup(&self, mac: &Mac) -> Option<String> {
        if mac.is_local() {
            return None;
        }
        self.map.get(&mac.oui()).cloned()
    }
}

/// Signals gathered about a device that the classifier looks at.
pub struct ClassHints<'a> {
    pub vendor: Option<&'a str>,
    pub is_ap: bool,
    pub is_gateway: bool,
    /// DHCP / mDNS hostnames.
    pub hostnames: &'a [&'a str],
    /// mDNS service types (`_googlecast._tcp`).
    pub services: &'a [&'a str],
    pub vendor_class: Option<&'a str>,
    /// SSDP SERVER headers and HTTP User-Agents.
    pub banners: &'a [&'a str],
    pub randomized: bool,
    pub domains: &'a [&'a str],
    pub ports: &'a [u16],
    pub probes_many_ssids: bool,
    /// OS family from the DHCP fingerprint.
    pub os: Option<&'a str>,
}

/// Best-effort automatic category. Users can override it with a tag.
pub fn classify(h: &ClassHints) -> &'static str {
    if h.is_gateway {
        return "Router / Gateway";
    }
    if h.is_ap {
        return "Access Point";
    }

    // 2. Hostnames people/vendors give devices.
    let host = |needles: &[&str]| {
        h.hostnames
            .iter()
            .any(|n| needles.iter().any(|k| n.to_lowercase().contains(k)))
    };
    if host(&[
        "iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi", "huawei-p",
    ]) {
        return "Phone / Tablet";
    }
    if host(&[
        "macbook",
        "imac",
        "mac-mini",
        "mac mini",
        "mac pro",
        "mac studio",
        "laptop",
        "desktop",
        "thinkpad",
        "surface",
        "-pc",
        "pc-",
        "workstation",
        "windows",
    ]) {
        return "Laptop / PC";
    }
    if host(&[
        "cam", "doorbell", "ring-", "wyze", "arlo", "blink", "eufy", "reolink",
    ]) {
        return "Smart Camera";
    }
    if host(&[
        "printer",
        "epson",
        "brother",
        "canon",
        "officejet",
        "laserjet",
        "envy",
    ]) {
        return "Printer";
    }
    if host(&[
        "echo",
        "alexa",
        "google-home",
        "nest-mini",
        "homepod",
        "sonos",
    ]) {
        return "Smart Speaker";
    }
    if host(&[
        "roku",
        "chromecast",
        "firetv",
        "fire-tv",
        "appletv",
        "apple-tv",
        "shield",
        "bravia",
        "-tv",
        "tv-",
    ]) {
        return "Media / TV";
    }
    if host(&["thermostat", "ecobee"]) {
        return "Thermostat";
    }
    if host(&[
        "tasmota",
        "shelly",
        "esp-",
        "esp_",
        "tuya",
        "wled",
        "smartplug",
        "plug",
    ]) {
        return "Smart Home Hub/Plug";
    }
    if host(&["hue", "bulb", "lifx", "light"]) {
        return "Smart Lighting";
    }
    if host(&["xbox", "playstation", "ps4", "ps5", "nintendo"]) {
        return "Game Console";
    }

    // 1. DNS-SD services are the strongest passive signal.
    let svc = |needles: &[&str]| {
        h.services
            .iter()
            .any(|s| needles.iter().any(|n| s.contains(n)))
    };
    if svc(&["_ipp", "_printer", "_pdl-datastream", "_scanner", "_uscan"]) {
        return "Printer";
    }
    if svc(&["_hap.", "_matter", "_homekit"]) {
        return "Smart Home Hub/Plug";
    }
    if svc(&["_hue"]) {
        return "Smart Lighting";
    }
    if svc(&["_sonos", "_amzn-", "_spotify-connect"]) {
        return "Smart Speaker";
    }
    // Computers also advertise AirPlay receivers, so check them first.
    if svc(&[
        "_smb",
        "_afpovertcp",
        "_ssh",
        "_sftp-ssh",
        "_rfb",
        "_workstation",
    ]) {
        return "Laptop / PC";
    }
    if svc(&["_companion-link", "_apple-mobdev", "_rdlink"]) {
        return "Phone / Laptop";
    }
    if svc(&[
        "_googlecast",
        "_roku",
        "_airplay",
        "_raop",
        "_androidtvremote",
    ]) {
        return "Media / TV";
    }

    // 3. UPnP SERVER / HTTP User-Agent banners.
    let banner = |needles: &[&str]| {
        h.banners
            .iter()
            .any(|b| needles.iter().any(|k| b.to_lowercase().contains(k)))
    };
    if banner(&["hikvision", "dahua", "ipcam", "ip camera", "onvif"]) {
        return "Smart Camera";
    }
    if banner(&["sonos", "alexa", "amazon"]) {
        return "Smart Speaker";
    }
    if banner(&[
        "roku",
        "webos",
        "tizen",
        "smarttv",
        "smart tv",
        "bravia",
        "chromecast",
    ]) {
        return "Media / TV";
    }
    if banner(&["printer", "epson", "brother", "cups", "hp http server"]) {
        return "Printer";
    }
    if banner(&["ipbridge", "philips hue"]) {
        return "Smart Lighting";
    }
    if banner(&["xbox", "playstation"]) {
        return "Game Console";
    }
    let has_domain = |needles: &[&str]| {
        h.domains
            .iter()
            .any(|d| needles.iter().any(|n| d.contains(n)))
    };
    let has_port = |ps: &[u16]| h.ports.iter().any(|p| ps.contains(p));

    if has_port(&[554, 8554])
        || has_domain(&[
            "ring.com",
            "wyze",
            "hik-connect",
            "ezviz",
            "dahua",
            "arlo",
            "blinkforhome",
            "nest.com/camera",
        ])
    {
        return "Smart Camera";
    }
    if has_domain(&["ecobee", "honeywell", "tccna", "nest.com", "home.nest"]) {
        return "Thermostat";
    }
    if has_domain(&[
        "meethue",
        "tuya",
        "lifx",
        "tplinkcloud",
        "smartthings",
        "ewelink",
    ]) {
        return "Smart Home Hub/Plug";
    }
    if has_domain(&["sonos", "spotify", "alexa", "avs-alexa", "googlecast"]) {
        return "Smart Speaker";
    }
    if has_domain(&["roku", "netflix", "nflxvideo", "youtube", "hulu"]) {
        return "Media / TV";
    }

    if let Some(v) = h.vendor {
        let v = v.to_ascii_lowercase();
        let vendor_class: &[(&str, &'static str)] = &[
            ("hikvision", "Smart Camera"),
            ("dahua", "Smart Camera"),
            ("wyze", "Smart Camera"),
            ("nest", "Thermostat"),
            ("ecobee", "Thermostat"),
            ("philips", "Smart Lighting"),
            ("signify", "Smart Lighting"),
            ("sonos", "Smart Speaker"),
            ("roku", "Media / TV"),
            ("amazon", "Smart Speaker"),
            ("espressif", "IoT Module"),
            ("raspberry", "Single-board Computer"),
            ("tp-link", "Network Device"),
            ("ubiquiti", "Network Device"),
            ("netgear", "Network Device"),
            ("intel", "Laptop / PC"),
            ("dell", "Laptop / PC"),
            ("microsoft", "Laptop / PC"),
            ("apple", "Phone / Laptop"),
            ("samsung", "Phone / Tablet"),
            ("google", "Phone / Smart Speaker"),
        ];
        for (needle, class) in vendor_class {
            if v.contains(needle) {
                return class;
            }
        }
    }
    match h.os {
        Some("Windows") => return "Laptop / PC",
        Some("Android") => return "Phone / Tablet",
        Some("Apple (iOS / macOS)") => return "Phone / Laptop",
        Some("Embedded Linux") => return "IoT Module",
        _ => {}
    }
    if let Some(vc) = h.vendor_class.map(str::to_lowercase) {
        if vc.contains("android") {
            return "Phone / Tablet";
        }
        if vc.starts_with("msft") {
            return "Laptop / PC";
        }
        if vc.contains("udhcp") {
            return "IoT Module";
        }
    }
    if h.randomized || h.probes_many_ssids {
        return "Phone / Laptop";
    }
    "Unknown"
}

/// Categories considered "IoT" - these get stricter anomaly severities since
/// their behavior should be very predictable.
pub fn is_iot_class(class: &str) -> bool {
    matches!(
        class,
        "Smart Camera"
            | "Thermostat"
            | "Smart Home Hub/Plug"
            | "Smart Speaker"
            | "Smart Lighting"
            | "Media / TV"
            | "IoT Module"
            // user tag presets
            | "Doorbell"
            | "Smart Plug"
            | "Smart TV"
            | "Hub"
            | "Sensor"
            | "Printer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_and_classify() {
        let db = OuiDb::load(None);
        let mac: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let v = db.lookup(&mac);
        assert_eq!(v.as_deref(), Some("Hikvision"));
        let h = ClassHints {
            vendor: v.as_deref(),
            is_ap: false,
            is_gateway: false,
            hostnames: &[],
            services: &[],
            vendor_class: None,
            banners: &[],
            randomized: false,
            domains: &[],
            ports: &[],
            probes_many_ssids: false,
            os: None,
        };
        assert_eq!(classify(&h), "Smart Camera");
        let h = ClassHints {
            services: &["_googlecast._tcp"],
            vendor: None,
            ..h
        };
        assert_eq!(classify(&h), "Media / TV");
        assert_eq!(
            clean_vendor("Hangzhou Hikvision Digital Technology Co.,Ltd."),
            "Hangzhou Hikvision Digital Technology"
        );
        assert_eq!(clean_vendor("Apple, Inc."), "Apple");
        assert_eq!(
            csv_fields(r#"MA-L,D011E5,"Apple, Inc.",x"#)[2],
            "Apple, Inc."
        );
    }
}
