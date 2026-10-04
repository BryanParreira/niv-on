//! Exposure & vulnerability assessment (Armis / Forescout style): what each
//! device serves or speaks that is insecure, and which vendors have
//! known-exploited vulnerabilities (CISA KEV). The same checks drive the
//! compliance view.

use crate::engine::{Device, Severity};
use crate::intel::{norm, Kev};
use crate::model::is_local_ip;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Check id, e.g. `telnet-server`.
    pub id: &'static str,
    pub title: String,
    pub severity: Severity,
    pub detail: String,
    pub cves: Vec<String>,
}

impl Finding {
    pub fn risk_points(&self) -> f64 {
        match self.severity {
            Severity::Info => 0.0,
            Severity::Low => 2.0,
            Severity::Medium => 5.0,
            Severity::High => 10.0,
            Severity::Critical => 15.0,
        }
    }
}

pub struct Check {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
}

pub const CHECKS: &[Check] = &[
    Check { id: "adb-server", name: "Android debug bridge exposed", description: "ADB on port 5555 gives anyone on the network a root shell (ADB.Miner worm).", severity: Severity::Critical },
    Check { id: "telnet-server", name: "Telnet service", description: "Cleartext remote login — the main way Mirai-style botnets take over IoT devices.", severity: Severity::High },
    Check { id: "smbv1", name: "SMBv1 in use", description: "The protocol exploited by WannaCry / EternalBlue.", severity: Severity::High },
    Check { id: "kev-product", name: "Firmware matches a known-exploited product", description: "A device banner names a product listed in CISA's Known Exploited Vulnerabilities catalog.", severity: Severity::High },
    Check { id: "kev-vendor", name: "Vendor with known-exploited vulnerabilities", description: "CISA lists actively exploited CVEs for this vendor's devices — check the firmware is current.", severity: Severity::Medium },
    Check { id: "ftp-server", name: "FTP service", description: "Cleartext file transfer with passwords sent in the clear.", severity: Severity::Medium },
    Check { id: "rtsp-server", name: "RTSP video stream", description: "Camera streams on 554 are often reachable without authentication.", severity: Severity::Medium },
    Check { id: "mqtt-cleartext", name: "Unencrypted MQTT", description: "MQTT on 1883 carries device data and commands without TLS.", severity: Severity::Medium },
    Check { id: "telnet-client", name: "Uses Telnet", description: "The device logs in to something over cleartext Telnet.", severity: Severity::Medium },
    Check { id: "ftp-client", name: "Uses FTP", description: "Credentials and files travel unencrypted.", severity: Severity::Medium },
    Check { id: "legacy-tls", name: "Legacy TLS (1.0 / 1.1)", description: "Offers only deprecated TLS versions — outdated firmware or libraries.", severity: Severity::Medium },
    Check { id: "old-upnp", name: "Outdated UPnP stack", description: "miniupnpd 1.x has several remote-code-execution and DDoS-reflection flaws.", severity: Severity::Medium },
    Check { id: "http-admin", name: "Web interface without HTTPS", description: "The device answered on HTTP and was never seen answering on HTTPS — admin passwords may cross the network in clear.", severity: Severity::Low },
    Check { id: "http-client", name: "Cleartext HTTP to the internet", description: "Firmware updates or telemetry over plain HTTP can be read or tampered with.", severity: Severity::Low },
    Check { id: "external-dns", name: "Bypasses network DNS", description: "Uses a public resolver instead of the network's — hard-coded DNS evades filtering and monitoring.", severity: Severity::Low },
    Check { id: "snmp", name: "SNMP in use", description: "SNMP v1/v2c uses cleartext community strings, often 'public'.", severity: Severity::Low },
];

fn check(id: &str) -> &'static Check {
    CHECKS.iter().find(|c| c.id == id).expect("known check")
}

fn finding(id: &'static str, detail: String, cves: Vec<String>) -> Finding {
    let c = check(id);
    Finding {
        id: c.id,
        title: c.name.into(),
        severity: c.severity,
        detail,
        cves,
    }
}

/// Every exposure finding for one device.
pub fn assess(d: &Device, kev: &Kev) -> Vec<Finding> {
    let mut out = vec![];
    let serves = |ports: &[u16]| {
        ports
            .iter()
            .copied()
            .find(|p| d.server_ports.contains_key(p))
    };
    let speaks = |p: &str| d.insecure.contains(p);

    if let Some(p) = serves(&[5555]) {
        out.push(finding(
            "adb-server",
            format!("Answering on port {p}."),
            vec![],
        ));
    }
    if let Some(p) = serves(&[23, 2323]) {
        out.push(finding(
            "telnet-server",
            format!("Answering Telnet on port {p}."),
            vec![],
        ));
    }
    if speaks("smbv1") {
        out.push(finding(
            "smbv1",
            "SMBv1 negotiation observed.".into(),
            vec!["CVE-2017-0144".into()],
        ));
    }
    if serves(&[21]).is_some() {
        out.push(finding(
            "ftp-server",
            "Answering FTP on port 21.".into(),
            vec![],
        ));
    }
    if let Some(p) = serves(&[554, 8554]) {
        out.push(finding(
            "rtsp-server",
            format!("Serving RTSP on port {p}."),
            vec![],
        ));
    }
    if serves(&[1883]).is_some() || speaks("mqtt") {
        out.push(finding(
            "mqtt-cleartext",
            "MQTT without TLS (port 1883).".into(),
            vec![],
        ));
    }
    if speaks("telnet") && serves(&[23, 2323]).is_none() {
        out.push(finding(
            "telnet-client",
            "Opened Telnet connections.".into(),
            vec![],
        ));
    }
    if speaks("ftp") && serves(&[21]).is_none() {
        out.push(finding(
            "ftp-client",
            "Opened FTP connections.".into(),
            vec![],
        ));
    }
    if speaks("legacy-tls") {
        out.push(finding(
            "legacy-tls",
            "A ClientHello offered nothing newer than TLS 1.1.".into(),
            vec![],
        ));
    }
    if let Some(b) = d
        .banners
        .iter()
        .find(|b| b.to_ascii_lowercase().contains("miniupnpd/1."))
    {
        out.push(finding("old-upnp", format!("Banner: {b}"), vec![]));
    }
    if serves(&[80, 8080]).is_some() && serves(&[443, 8443]).is_none() {
        out.push(finding(
            "http-admin",
            "Answered on HTTP (80/8080); no HTTPS answers observed.".into(),
            vec![],
        ));
    }
    if speaks("http")
        && d.destinations
            .values()
            .any(|x| x.external && (x.ports.contains(&80) || x.ports.contains(&8080)))
    {
        out.push(finding(
            "http-client",
            "Plain-HTTP requests to internet hosts.".into(),
            vec![],
        ));
    }
    if let Some(r) = d.resolvers.iter().find(|r| !is_local_ip(r)) {
        out.push(finding(
            "external-dns",
            format!("Queries {r} directly."),
            vec![],
        ));
    }
    if speaks("snmp") || serves(&[161]).is_some() {
        out.push(finding("snmp", "SNMP traffic observed.".into(), vec![]));
    }

    // CISA KEV: product named in a banner (strong), or the vendor (weaker,
    // only for embedded / network gear where firmware lags).
    if kev.entries > 0 {
        if let Some(entries) = d.vendor.as_deref().and_then(|v| kev.for_vendor(v)) {
            let banner = norm(
                &d.banners
                    .iter()
                    .chain(d.hostnames.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            let product: Vec<&crate::intel::KevEntry> = entries
                .iter()
                .filter(|e| {
                    let p = norm(&e.product);
                    p.len() >= 5 && !p.starts_with("multiple") && banner.contains(&p)
                })
                .collect();
            if !product.is_empty() {
                out.push(finding(
                    "kev-product",
                    format!("Banner names {} — {}.", product[0].product, product[0].name),
                    product.iter().take(8).map(|e| e.cve.clone()).collect(),
                ));
            }
            let embedded = d.is_iot()
                || d.is_gateway
                || d.is_ap
                || matches!(
                    d.class(),
                    "Network Device" | "Printer" | "Single-board Computer"
                );
            if embedded && product.is_empty() {
                let ransom = entries.iter().filter(|e| e.ransomware).count();
                let mut f = finding(
                    "kev-vendor",
                    format!(
                        "{} actively exploited CVE{} for {} products{}. Latest: {} — {}.",
                        entries.len(),
                        if entries.len() == 1 { "" } else { "s" },
                        entries[0].vendor,
                        if ransom > 0 {
                            format!(", {ransom} used by ransomware")
                        } else {
                            String::new()
                        },
                        entries[0].cve,
                        entries[0].name
                    ),
                    entries.iter().take(8).map(|e| e.cve.clone()).collect(),
                );
                if ransom > 0 {
                    f.severity = Severity::High;
                }
                out.push(f);
            }
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    /// (mac, label, detail)
    pub failing: Vec<(String, String, String)>,
    pub evaluated: usize,
}

/// Compliance matrix across every device on the network.
pub fn compliance<'a>(devices: impl Iterator<Item = &'a Device>, kev: &Kev) -> Vec<CheckResult> {
    let mut results: Vec<CheckResult> = CHECKS
        .iter()
        .map(|c| CheckResult {
            id: c.id,
            name: c.name,
            description: c.description,
            severity: c.severity,
            failing: vec![],
            evaluated: 0,
        })
        .collect();
    for d in devices.filter(|d| d.on_network) {
        let f = assess(d, kev);
        for r in results.iter_mut() {
            r.evaluated += 1;
            if let Some(x) = f.iter().find(|x| x.id == r.id) {
                r.failing
                    .push((d.mac.to_string(), d.label(), x.detail.clone()));
            }
        }
    }
    results
}
