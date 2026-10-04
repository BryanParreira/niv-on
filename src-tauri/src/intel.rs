//! Threat intelligence: the user's watchlist plus public feeds that update
//! automatically (abuse.ch Feodo Tracker, URLhaus, ThreatFox, Tor exit
//! nodes), and CISA's Known Exploited Vulnerabilities catalog.

use crate::engine::Severity;
use crate::model::IpNet;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedKind {
    /// One IP (or CIDR) per line.
    Ips,
    /// hosts-file format: `127.0.0.1  evil.example`.
    Hosts,
}

pub struct FeedDef {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub url: &'static str,
    pub kind: FeedKind,
    pub severity: Severity,
}

pub const FEEDS: &[FeedDef] = &[
    FeedDef {
        id: "feodo",
        name: "abuse.ch Feodo Tracker",
        description: "Botnet command-and-control servers (Emotet, Dridex, QakBot…)",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        kind: FeedKind::Ips,
        severity: Severity::Critical,
    },
    FeedDef {
        id: "urlhaus",
        name: "abuse.ch URLhaus",
        description: "Hosts currently distributing malware",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        kind: FeedKind::Hosts,
        severity: Severity::High,
    },
    FeedDef {
        id: "threatfox",
        name: "abuse.ch ThreatFox",
        description: "Malware IOCs: C2 domains and payload hosts",
        url: "https://threatfox.abuse.ch/downloads/hostfile/",
        kind: FeedKind::Hosts,
        severity: Severity::High,
    },
    FeedDef {
        id: "tor",
        name: "Tor exit nodes",
        description: "Traffic to or from Tor — unusual for IoT devices",
        url: "https://check.torproject.org/torbulkexitlist",
        kind: FeedKind::Ips,
        severity: Severity::Medium,
    },
];

pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// ---------------------------------------------------------------------------
// Indicator index
// ---------------------------------------------------------------------------

struct Source {
    name: String,
    severity: Severity,
}

/// A matched indicator of compromise.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub indicator: String,
    pub source: String,
    pub severity: Severity,
}

/// All indicators from the watchlist and enabled feeds.
#[derive(Default)]
pub struct Intel {
    sources: Vec<Source>,
    ips: HashMap<IpAddr, u16>,
    nets: Vec<(IpNet, u16)>,
    domains: HashMap<String, u16>,
}

impl Intel {
    pub fn add_source(&mut self, name: &str, severity: Severity) -> u16 {
        self.sources.push(Source {
            name: name.into(),
            severity,
        });
        (self.sources.len() - 1) as u16
    }

    /// Add one indicator line (IP, CIDR or domain; `#` comments allowed).
    pub fn add(&mut self, src: u16, raw: &str) {
        let e = raw
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if e.is_empty() {
            return;
        }
        if let Ok(n) = e.parse::<IpNet>() {
            let full = if n.addr.is_ipv4() { 32 } else { 128 };
            if n.prefix == full {
                self.ips.entry(n.addr).or_insert(src);
            } else {
                self.nets.push((n, src));
            }
        } else {
            let d = e
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.');
            if !d.is_empty() && d.contains('.') && !d.contains(['/', ' ', ':']) {
                self.domains.entry(d.to_string()).or_insert(src);
            }
        }
    }

    /// The user's watchlist as the only source.
    pub fn compile(list: &[String]) -> Self {
        let mut i = Intel::default();
        let s = i.add_source("your watchlist", Severity::Critical);
        for l in list {
            i.add(s, l);
        }
        i
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.nets.is_empty() && self.domains.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.nets.len() + self.domains.len()
    }

    fn hit(&self, indicator: String, src: u16) -> Hit {
        let s = &self.sources[src as usize];
        Hit {
            indicator,
            source: s.name.clone(),
            severity: s.severity,
        }
    }

    pub fn ip(&self, ip: &IpAddr) -> Option<Hit> {
        if let Some(s) = self.ips.get(ip) {
            return Some(self.hit(ip.to_string(), *s));
        }
        self.nets
            .iter()
            .find(|(n, _)| n.contains(ip))
            .map(|(n, s)| self.hit(n.to_string(), *s))
    }

    /// Matches the name itself or any parent domain on the lists.
    pub fn domain(&self, host: &str) -> Option<Hit> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let mut cur = h.as_str();
        loop {
            if let Some(s) = self.domains.get(cur) {
                return Some(self.hit(cur.to_string(), *s));
            }
            cur = cur.split_once('.')?.1;
            if !cur.contains('.') {
                return None; // never match a bare TLD
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Feed files
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedState {
    pub updated: Option<DateTime<Utc>>,
    pub count: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IntelMeta {
    pub feeds: HashMap<String, FeedState>,
    pub kev: FeedState,
}

pub fn dir(data: &Path) -> PathBuf {
    data.join("intel")
}

pub fn read_meta(data: &Path) -> IntelMeta {
    std::fs::read(dir(data).join("meta.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_meta(data: &Path, m: &IntelMeta) {
    let _ = std::fs::create_dir_all(dir(data));
    let _ = std::fs::write(
        dir(data).join("meta.json"),
        serde_json::to_vec_pretty(m).unwrap_or_default(),
    );
}

/// Download `url` to `dest` with the system curl (PowerShell fallback on Windows).
pub fn download(url: &str, dest: &Path, min_size: u64) -> Result<(), String> {
    let tmp = dest.with_extension("download");
    let curl = std::process::Command::new(if cfg!(windows) { "curl.exe" } else { "curl" })
        .args([
            "-fsSL",
            "--max-time",
            "180",
            "-A",
            "Mozilla/5.0 (Niv.ON)",
            "-o",
        ])
        .arg(&tmp)
        .arg(url)
        .status();
    let ok = match curl {
        Ok(s) if s.success() => true,
        _ if cfg!(windows) => {
            let ps = format!("Invoke-WebRequest -UseBasicParsing -UserAgent 'Mozilla/5.0' -Uri '{url}' -OutFile '{}'", tmp.display());
            std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps])
                .status()
                .is_ok_and(|s| s.success())
        }
        Ok(_) => false,
        Err(e) => return Err(format!("curl not available: {e}")),
    };
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("download failed — check the internet connection".into());
    }
    let size = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
    if size < min_size {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("downloaded file looks wrong ({size} bytes)"));
    }
    std::fs::rename(&tmp, dest).map_err(|e| e.to_string())
}

fn parse_feed(kind: FeedKind, text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| match kind {
            FeedKind::Ips => l.split_whitespace().next().map(str::to_string),
            FeedKind::Hosts => {
                let mut it = l.split_whitespace();
                let (a, b) = (it.next()?, it.next()?);
                (a == "127.0.0.1" || a == "0.0.0.0")
                    .then(|| b.to_string())
                    .filter(|h| h != "localhost")
            }
        })
        .collect()
}

/// Refresh the given feeds (and KEV) and record the outcome.
pub fn update(data: &Path, ids: &[String], kev: bool) -> IntelMeta {
    let mut meta = read_meta(data);
    let d = dir(data);
    let _ = std::fs::create_dir_all(&d);
    for f in FEEDS.iter().filter(|f| ids.iter().any(|i| i == f.id)) {
        let path = d.join(format!("{}.txt", f.id));
        let st = meta.feeds.entry(f.id.into()).or_default();
        match download(f.url, &path, 64) {
            Ok(()) => {
                let n = std::fs::read_to_string(&path)
                    .map(|t| parse_feed(f.kind, &t).len())
                    .unwrap_or(0);
                *st = FeedState {
                    updated: Some(Utc::now()),
                    count: n,
                    error: None,
                };
            }
            Err(e) => st.error = Some(e),
        }
    }
    if kev {
        let path = d.join("kev.json");
        match download(KEV_URL, &path, 10_000) {
            Ok(()) => {
                let n = Kev::load(data).entries;
                meta.kev = FeedState {
                    updated: Some(Utc::now()),
                    count: n,
                    error: None,
                };
            }
            Err(e) => meta.kev.error = Some(e),
        }
    }
    write_meta(data, &meta);
    meta
}

/// Watchlist + every enabled feed already on disk.
pub fn load(data: &Path, enabled: &[String], watchlist: &[String]) -> Intel {
    let mut i = Intel::compile(watchlist);
    for f in FEEDS.iter().filter(|f| enabled.iter().any(|e| e == f.id)) {
        let Ok(text) = std::fs::read_to_string(dir(data).join(format!("{}.txt", f.id))) else {
            continue;
        };
        let s = i.add_source(f.name, f.severity);
        for e in parse_feed(f.kind, &text) {
            i.add(s, &e);
        }
    }
    i
}

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub added: String,
    pub ransomware: bool,
}

#[derive(Default)]
pub struct Kev {
    /// normalized vendor -> entries (newest first)
    by_vendor: Vec<(String, Vec<KevEntry>)>,
    pub entries: usize,
}

pub fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

impl Kev {
    pub fn load(data: &Path) -> Kev {
        let Ok(bytes) = std::fs::read(dir(data).join("kev.json")) else {
            return Kev::default();
        };
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Kev {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            #[serde(rename = "cveID")]
            cve_id: String,
            vendor_project: String,
            product: String,
            vulnerability_name: String,
            date_added: String,
            #[serde(default)]
            known_ransomware_campaign_use: String,
        }
        #[derive(Deserialize)]
        struct File {
            vulnerabilities: Vec<Raw>,
        }
        let Ok(f) = serde_json::from_slice::<File>(bytes) else {
            return Kev::default();
        };
        let mut map: HashMap<String, Vec<KevEntry>> = HashMap::new();
        let n = f.vulnerabilities.len();
        for r in f.vulnerabilities {
            map.entry(norm(&r.vendor_project))
                .or_default()
                .push(KevEntry {
                    cve: r.cve_id,
                    vendor: r.vendor_project,
                    product: r.product,
                    name: r.vulnerability_name,
                    added: r.date_added,
                    ransomware: r
                        .known_ransomware_campaign_use
                        .eq_ignore_ascii_case("known"),
                });
        }
        let mut by_vendor: Vec<(String, Vec<KevEntry>)> = map
            .into_iter()
            .filter(|(k, _)| k.len() >= 3)
            .map(|(k, mut v)| {
                v.sort_by(|a, b| b.added.cmp(&a.added));
                (k, v)
            })
            .collect();
        // Longest names first so "tplink" wins over "link".
        by_vendor.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
        Kev {
            by_vendor,
            entries: n,
        }
    }

    /// Catalog entries for the vendor a MAC prefix resolved to.
    pub fn for_vendor(&self, vendor: &str) -> Option<&[KevEntry]> {
        let v = norm(vendor);
        if v.len() < 3 {
            return None;
        }
        self.by_vendor
            .iter()
            .find(|(k, _)| v.contains(k.as_str()) || (k.len() >= 5 && k.contains(&v)))
            .map(|(_, e)| e.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicators_and_feed_formats() {
        let mut i = Intel::compile(&["evil.example".into(), "198.51.100.0/24 # c2".into()]);
        let s = i.add_source("Feodo", Severity::Critical);
        for e in parse_feed(FeedKind::Ips, "# comment\n203.0.113.7\n\n") {
            i.add(s, &e);
        }
        let s2 = i.add_source("URLhaus", Severity::High);
        for e in parse_feed(
            FeedKind::Hosts,
            "# hosts\n127.0.0.1\tlocalhost\n127.0.0.1\tbad.example.net\n",
        ) {
            i.add(s2, &e);
        }
        assert_eq!(
            i.ip(&"203.0.113.7".parse().unwrap()).unwrap().source,
            "Feodo"
        );
        assert_eq!(
            i.ip(&"198.51.100.9".parse().unwrap()).unwrap().indicator,
            "198.51.100.0/24"
        );
        assert_eq!(
            i.domain("cdn.bad.example.net").unwrap().severity,
            Severity::High
        );
        assert_eq!(i.domain("x.evil.example").unwrap().source, "your watchlist");
        assert!(i.domain("example.net").is_none());
        assert_eq!(i.len(), 4);
    }

    #[test]
    fn kev_vendor_matching() {
        let json = br#"{"vulnerabilities":[
            {"cveID":"CVE-2021-36260","vendorProject":"Hikvision","product":"Various","vulnerabilityName":"Hikvision Improper Input Validation","dateAdded":"2022-01-10","knownRansomwareCampaignUse":"Unknown"},
            {"cveID":"CVE-2023-1389","vendorProject":"TP-Link","product":"Archer AX21","vulnerabilityName":"TP-Link Command Injection","dateAdded":"2023-05-01","knownRansomwareCampaignUse":"Known"}]}"#;
        let k = Kev::parse(json);
        assert_eq!(k.entries, 2);
        assert_eq!(
            k.for_vendor("Hangzhou Hikvision Digital Technology")
                .unwrap()[0]
                .cve,
            "CVE-2021-36260"
        );
        assert!(k.for_vendor("TP-Link").unwrap()[0].ransomware);
        assert!(k.for_vendor("Apple").is_none());
    }
}

#[cfg(test)]
mod live {
    /// Downloads every feed and KEV: `cargo test real_intel -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_intel_update() {
        let dir = std::env::temp_dir().join("niv-intel-live");
        let ids: Vec<String> = super::FEEDS.iter().map(|f| f.id.to_string()).collect();
        let meta = super::update(&dir, &ids, true);
        for (id, st) in &meta.feeds {
            println!("{id}: {} indicators, error {:?}", st.count, st.error);
            assert!(st.error.is_none() && st.count > 0, "{id} failed");
        }
        println!("kev: {} entries", meta.kev.count);
        assert!(meta.kev.count > 1000);
        let i = super::load(&dir, &ids, &[]);
        println!("compiled {} indicators", i.len());
        let k = super::Kev::load(&dir);
        println!(
            "hikvision KEV: {:?}",
            k.for_vendor("Hangzhou Hikvision Digital Technology")
                .map(|e| e.len())
        );
    }
}
