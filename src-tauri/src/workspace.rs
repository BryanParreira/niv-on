//! Network workspaces: every network Niv.ON captures on keeps its own device
//! profiles, baselines and alerts, so moving between networks (or running the
//! demo) never mixes inventories.
//!
//! The engine always holds the *current* workspace's data; switching snapshots
//! it into the store and loads the next one. The demo workspace is ephemeral:
//! it starts empty on every simulator run and is never written to disk.

use crate::engine::{Alert, Device, Engine};
use crate::model::Mac;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEMO_ID: &str = "demo";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetKind {
    Live,
    File,
    Demo,
    /// Data recorded before workspaces existed.
    Legacy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    /// The user renamed it; don't overwrite with the detected SSID.
    #[serde(default)]
    pub custom_name: bool,
    pub kind: NetKind,
    pub created: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub interface: Option<String>,
    pub subnet: Option<String>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
    /// LAN subnets learned on this network (incl. global IPv6 prefixes).
    #[serde(default)]
    pub lan_nets: Vec<crate::model::IpNet>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub alerts: Vec<Alert>,
    #[serde(default)]
    pub next_alert_id: u64,
}

/// What the UI shows in the networks list (no device payloads).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSummary {
    pub id: String,
    pub name: String,
    pub kind: NetKind,
    pub created: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub interface: Option<String>,
    pub subnet: Option<String>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
    pub devices: usize,
    pub open_alerts: usize,
    pub current: bool,
}

/// Identity of the network a capture is about to run on.
#[derive(Clone, Debug)]
pub struct NetMeta {
    pub id: String,
    pub name: String,
    pub kind: NetKind,
    pub interface: Option<String>,
    pub subnet: Option<String>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkStore {
    pub current: Option<String>,
    pub records: BTreeMap<String, NetworkRecord>,
}

impl NetworkStore {
    /// Copy the engine's live data into the current record.
    pub fn snapshot(&mut self, eng: &Engine) {
        let Some(id) = self.current.clone() else {
            return;
        };
        if let Some(r) = self.records.get_mut(&id) {
            remember_router(r, eng);
            r.devices = eng.devices.values().cloned().collect();
            r.alerts = eng.alerts.iter().rev().take(500).rev().cloned().collect();
            r.next_alert_id = eng.next_alert_id;
        }
    }

    /// Make `meta` the active workspace, loading its data into the engine.
    /// `fresh` discards any previous data for it (demo runs, file replays).
    pub fn activate(&mut self, eng: &mut Engine, meta: NetMeta, fresh: bool) {
        self.snapshot(eng);
        let now = Utc::now();
        if fresh {
            self.records.remove(&meta.id);
        }
        let rec = self
            .records
            .entry(meta.id.clone())
            .or_insert_with(|| NetworkRecord {
                id: meta.id.clone(),
                name: meta.name.clone(),
                custom_name: false,
                kind: meta.kind.clone(),
                created: now,
                last_used: now,
                interface: None,
                subnet: None,
                gateway_mac: None,
                ssid: None,
                lan_nets: vec![],
                devices: vec![],
                alerts: vec![],
                next_alert_id: 1,
            });
        rec.last_used = now;
        if !rec.custom_name {
            rec.name = meta.name;
        }
        rec.interface = meta.interface.or(rec.interface.take());
        rec.subnet = meta.subnet.or(rec.subnet.take());
        rec.gateway_mac = meta.gateway_mac.or(rec.gateway_mac.take());
        rec.ssid = meta.ssid.or(rec.ssid.take());

        eng.clear_all();
        eng.gateway_macs.clear();
        eng.gateway_macs.extend(saved_gateway(rec));
        for n in &rec.lan_nets {
            if !eng.lan_nets.contains(n) {
                eng.lan_nets.push(*n);
            }
        }
        eng.restore(rec.devices.clone(), rec.alerts.clone(), rec.next_alert_id);
        eng.dirty = false;
        self.current = Some(meta.id);
    }

    /// Load the most recently used saved network (used after deleting/clearing).
    pub fn activate_latest(&mut self, eng: &mut Engine) {
        eng.clear_all();
        self.current = None;
        let latest = self
            .records
            .values()
            .filter(|r| r.kind != NetKind::Demo)
            .max_by_key(|r| r.last_used)
            .map(|r| r.id.clone());
        eng.gateway_macs.clear();
        if let Some(id) = latest {
            let r = &self.records[&id];
            eng.gateway_macs.extend(saved_gateway(r));
            eng.lan_nets = r.lan_nets.clone();
            eng.restore(r.devices.clone(), r.alerts.clone(), r.next_alert_id);
            self.current = Some(id);
        }
        eng.dirty = false;
    }

    pub fn summaries(&self, eng: &Engine) -> Vec<NetworkSummary> {
        let mut v: Vec<NetworkSummary> = self
            .records
            .values()
            .map(|r| {
                let current = self.current.as_deref() == Some(&r.id);
                let (devices, open_alerts) = if current {
                    (
                        eng.devices.len(),
                        eng.alerts.iter().filter(|a| !a.acknowledged).count(),
                    )
                } else {
                    (
                        r.devices.len(),
                        r.alerts.iter().filter(|a| !a.acknowledged).count(),
                    )
                };
                NetworkSummary {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    kind: r.kind.clone(),
                    created: r.created,
                    last_used: r.last_used,
                    interface: r.interface.clone(),
                    subnet: r.subnet.clone(),
                    gateway_mac: r.gateway_mac.clone(),
                    ssid: r.ssid.clone(),
                    devices,
                    open_alerts,
                    current,
                }
            })
            .collect();
        v.sort_by_key(|n| (!n.current, std::cmp::Reverse(n.last_used)));
        v
    }

    /// Everything that should be written to disk (demo excluded).
    pub fn persistable(&self, eng: &Engine) -> NetworkStore {
        let mut out = NetworkStore {
            current: None,
            records: BTreeMap::new(),
        };
        for (id, r) in &self.records {
            if r.kind == NetKind::Demo {
                continue;
            }
            let mut r = r.clone();
            if self.current.as_deref() == Some(id) {
                remember_router(&mut r, eng);
                r.devices = eng.devices.values().cloned().collect();
                r.alerts = eng.alerts.iter().rev().take(500).rev().cloned().collect();
                r.next_alert_id = eng.next_alert_id;
            }
            out.records.insert(id.clone(), r);
        }
        out.current = self.current.clone().filter(|c| out.records.contains_key(c));
        out
    }

    /// When the router's MAC wasn't known at start (cold ARP cache), learn it
    /// from captured traffic and re-key the workspace to `net:<router-mac>`,
    /// joining an existing workspace for that router if there is one.
    /// Returns true when the active workspace changed.
    pub fn adopt_gateway_mac(&mut self, eng: &mut Engine) -> bool {
        let Some(cur) = self.current.clone() else {
            return false;
        };
        let Some(rec) = self.records.get(&cur) else {
            return false;
        };
        if rec.kind != NetKind::Live || rec.gateway_mac.is_some() {
            return false;
        }
        let Some(gw_ip) = eng.gateway_ip else {
            return false;
        };
        let Some(mac) = eng
            .devices
            .values()
            .find(|d| d.is_gateway && d.ips.contains(&gw_ip))
            .map(|d| d.mac.to_string())
        else {
            return false;
        };
        let new_id = format!("net:{mac}");
        if self.records.contains_key(&new_id) {
            // Known router: merge what was seen so far into that workspace.
            self.snapshot(eng);
            let seen = self
                .records
                .remove(&cur)
                .map(|r| r.devices)
                .unwrap_or_default();
            let target = self.records.get_mut(&new_id).expect("checked");
            for d in seen {
                if !target.devices.iter().any(|x| x.mac == d.mac) {
                    target.devices.push(d);
                }
            }
            target.last_used = Utc::now();
            let (devs, alerts, next) = (
                target.devices.clone(),
                target.alerts.clone(),
                target.next_alert_id,
            );
            let (gw, ips, macs, host) = (
                eng.gateway_ip,
                eng.self_ips.clone(),
                eng.self_macs.clone(),
                eng.self_hostname.clone(),
            );
            eng.clear_all();
            eng.restore(devs, alerts, next);
            eng.gateway_ip = gw;
            eng.self_ips = ips;
            eng.self_macs = macs;
            eng.self_hostname = host;
            self.current = Some(new_id);
        } else {
            let mut r = self.records.remove(&cur).expect("checked");
            r.id = new_id.clone();
            r.gateway_mac = Some(mac);
            self.records.insert(new_id.clone(), r);
            self.current = Some(new_id);
        }
        true
    }

    pub fn current_record(&self) -> Option<&NetworkRecord> {
        self.current.as_ref().and_then(|c| self.records.get(c))
    }
}

/// Keep the router's MAC once it was identified with certainty (ARP for the
/// gateway IP, DHCP, router advertisement), so saved networks show it.
/// The router saved for a network: the recorded MAC, or else the single
/// device that was flagged as the gateway when the record was written.
pub fn saved_gateway(r: &NetworkRecord) -> Option<Mac> {
    if let Some(m) = r.gateway_mac.as_deref().and_then(|m| m.parse::<Mac>().ok()) {
        return Some(m);
    }
    if r.kind != NetKind::Live {
        return None;
    }
    let mut gws = r.devices.iter().filter(|d| d.is_gateway);
    match (gws.next(), gws.next()) {
        (Some(g), None) => Some(g.mac),
        _ => None,
    }
}

fn remember_router(r: &mut NetworkRecord, eng: &Engine) {
    for n in &eng.lan_nets {
        if !r.lan_nets.contains(n) && r.lan_nets.len() < 32 {
            r.lan_nets.push(*n);
        }
    }
    if r.gateway_mac.is_some() || r.kind != NetKind::Live {
        return;
    }
    if eng.gateway_macs.len() == 1 {
        r.gateway_mac = eng.gateway_macs.iter().next().map(|m| m.to_string());
        return;
    }
    // Identified from router advertisements or forwarding instead of the OS
    // route / ARP: keep it only when it is unambiguous.
    let mut gws = eng.devices.values().filter(|d| d.is_gateway);
    if let (Some(g), None) = (gws.next(), gws.next()) {
        r.gateway_mac = Some(g.mac.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FrameKind, PacketInfo};
    use crate::oui::OuiDb;
    use crate::settings::RuleSettings;

    fn meta(id: &str, kind: NetKind) -> NetMeta {
        NetMeta {
            id: id.into(),
            name: id.into(),
            kind,
            interface: None,
            subnet: None,
            gateway_mac: None,
            ssid: None,
        }
    }

    fn see(eng: &mut Engine, mac: &str) {
        let mut p = PacketInfo::new(Utc::now(), FrameKind::Ethernet, "ipv4", 60);
        p.src = Some(mac.parse().unwrap());
        eng.process(&p);
    }

    #[test]
    fn networks_are_isolated_and_demo_is_ephemeral() {
        let mut eng = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let mut store = NetworkStore::default();

        store.activate(&mut eng, meta("net:home", NetKind::Live), false);
        see(&mut eng, "02:00:00:00:00:01");
        store.activate(&mut eng, meta(DEMO_ID, NetKind::Demo), true);
        assert!(eng.devices.is_empty(), "demo starts empty");
        see(&mut eng, "02:00:00:00:00:99");
        store.activate(&mut eng, meta("net:office", NetKind::Live), false);
        assert!(eng.devices.is_empty(), "new network starts empty");
        see(&mut eng, "02:00:00:00:00:02");

        store.activate(&mut eng, meta("net:home", NetKind::Live), false);
        assert_eq!(eng.devices.len(), 1);
        assert!(eng
            .devices
            .contains_key(&"02:00:00:00:00:01".parse().unwrap()));

        // Cold ARP cache: workspace keyed by subnet until the router is seen.
        store.activate(
            &mut eng,
            meta("net:10.0.0.0/24@10.0.0.1", NetKind::Live),
            false,
        );
        eng.gateway_ip = Some("10.0.0.1".parse().unwrap());
        let mut arp = PacketInfo::new(Utc::now(), FrameKind::Ethernet, "arp", 60);
        let gw: crate::model::Mac = "94:83:c4:be:eb:ac".parse().unwrap();
        arp.src = Some(gw);
        arp.arp = Some(crate::model::ArpInfo {
            sender_mac: gw,
            sender_ip: "10.0.0.1".parse().unwrap(),
            target_ip: "10.0.0.5".parse().unwrap(),
            reply: true,
        });
        eng.process(&arp);
        assert!(store.adopt_gateway_mac(&mut eng));
        assert_eq!(store.current.as_deref(), Some("net:94:83:c4:be:eb:ac"));

        let saved = store.persistable(&eng);
        assert!(!saved.records.contains_key(DEMO_ID), "demo never saved");
        assert_eq!(saved.records.len(), 3);
    }

    /// A router found from IPv6 router advertisements (not the OS route) and
    /// the LAN's IPv6 prefix survive a reload of the saved network.
    #[test]
    fn reload_keeps_router_and_ipv6_lan() {
        let mut eng = Engine::new(RuleSettings::default(), OuiDb::load(None));
        let mut store = NetworkStore::default();
        store.activate(&mut eng, meta("net:home", NetKind::Live), false);
        let gw: Mac = "a0:8a:06:2e:ff:9a".parse().unwrap();
        let phone: std::net::IpAddr = "2600:6c46:4500:6f0::d029".parse().unwrap();
        see(&mut eng, "a0:8a:06:2e:ff:9a");
        eng.devices.get_mut(&gw).unwrap().is_gateway = true;
        eng.lan_nets
            .push("2600:6c46:4500:6f0::/64".parse().unwrap());
        store.snapshot(&eng);
        assert_eq!(
            store.records["net:home"].gateway_mac.as_deref(),
            Some("a0:8a:06:2e:ff:9a")
        );

        // Older saves: no router MAC recorded, but the device carries the flag.
        let mut rec = store.records["net:home"].clone();
        rec.gateway_mac = None;
        assert_eq!(saved_gateway(&rec), Some(gw));

        store.activate(&mut eng, meta("net:other", NetKind::Live), false);
        store.activate(&mut eng, meta("net:home", NetKind::Live), false);
        assert!(eng.devices[&gw].is_gateway, "router still identified");
        assert!(eng.is_lan(&phone), "IPv6 LAN prefix restored");
    }
}
