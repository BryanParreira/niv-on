//! Shared data types passed between the capture, parsing, profiling and
//! anomaly-detection stages (and serialized to the UI).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// 48-bit IEEE MAC address. Serialized as `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xff; 6]);

    pub fn from_slice(b: &[u8]) -> Option<Mac> {
        b.get(..6).map(|s| {
            let mut m = [0u8; 6];
            m.copy_from_slice(s);
            Mac(m)
        })
    }

    /// Group (multicast/broadcast) bit.
    pub fn is_group(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Locally-administered bit. Phones/laptops set this when they use
    /// MAC-address randomization, so the vendor prefix is meaningless.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_group() && self.0 != [0; 6]
    }

    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Mac {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address: {s}"));
        }
        let mut m = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            m[i] = u8::from_str_radix(p, 16).map_err(|_| format!("invalid MAC address: {s}"))?;
        }
        Ok(Mac(m))
    }
}

impl Serialize for Mac {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// 802.11 frame type. `Ethernet` is used when capturing on a normal (managed)
/// interface where the OS hands us Ethernet-II frames instead of raw 802.11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    Management,
    Control,
    Data,
    Ethernet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// Layer 3/4 details. Only available for unencrypted frames: Ethernet
/// captures, open Wi-Fi networks, or WPA traffic decrypted upstream.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub transport: Transport,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// TCP SYN without ACK - a connection attempt.
    pub tcp_syn: bool,
    /// Name asked for in a DNS query.
    pub dns_query: Option<String>,
    /// (name, address) pairs from a DNS response's A/AAAA records.
    pub dns_answers: Vec<(String, IpAddr)>,
    /// Server name from a TLS ClientHello.
    pub sni: Option<String>,
    /// Identity clues from discovery / plaintext protocols.
    #[serde(default)]
    pub hints: Vec<Hint>,
}

/// Device identity clues leaked by LAN discovery and plaintext protocols.
/// These are what make passive identification work on real networks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Hint {
    /// DHCP option 12, mDNS `<name>.local` A record, mDNS instance name.
    Hostname(String),
    /// DHCP option 60 (e.g. `android-dhcp-14`, `MSFT 5.0`, `udhcp 1.31`).
    VendorClass(String),
    /// mDNS / DNS-SD service type advertised (e.g. `_googlecast._tcp`).
    Service(String),
    /// SSDP/UPnP `SERVER:` header.
    Server(String),
    /// HTTP `User-Agent:` (plaintext port 80).
    UserAgent(String),
}

/// ARP sender binding (MAC <-> IPv4) - discovers LAN devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpInfo {
    pub sender_mac: Mac,
    pub sender_ip: std::net::Ipv4Addr,
    pub target_ip: std::net::Ipv4Addr,
    pub reply: bool,
}

/// One captured frame, decoded into the fields the analyzer cares about.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketInfo {
    pub ts: DateTime<Utc>,
    pub kind: FrameKind,
    pub subtype: &'static str,
    /// Transmitter / source address.
    pub src: Option<Mac>,
    /// Receiver / destination address.
    pub dst: Option<Mac>,
    pub bssid: Option<Mac>,
    /// Signal strength in dBm (radiotap antenna signal).
    pub rssi: Option<i8>,
    pub channel: Option<u16>,
    pub len: u32,
    /// SSID from beacons / probe responses / probe requests / assoc requests.
    pub ssid: Option<String>,
    /// Frame body is encrypted (WEP/WPA protected bit).
    pub protected: bool,
    /// Station is sending to the distribution system (client -> AP).
    pub to_ds: bool,
    pub from_ds: bool,
    pub net: Option<NetInfo>,
    pub arp: Option<ArpInfo>,
}

impl PacketInfo {
    pub fn new(ts: DateTime<Utc>, kind: FrameKind, subtype: &'static str, len: u32) -> Self {
        PacketInfo {
            ts,
            kind,
            subtype,
            src: None,
            dst: None,
            bssid: None,
            rssi: None,
            channel: None,
            len,
            ssid: None,
            protected: false,
            to_ds: false,
            from_ds: false,
            net: None,
            arp: None,
        }
    }
}

/// RFC 1918 / loopback / link-local / multicast / ULA etc. Anything that is
/// not a routable internet address counts as "local" for the anomaly rules.
pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // unique local
                || (seg0 & 0xffc0) == 0xfe80 // link local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip_and_bits() {
        let m: Mac = "B8:27:EB:01:02:03".parse().unwrap();
        assert_eq!(m.to_string(), "b8:27:eb:01:02:03");
        assert!(m.is_unicast());
        assert!(!m.is_local());
        assert!(Mac::BROADCAST.is_group());
        let r: Mac = "da:a1:19:00:00:01".parse().unwrap();
        assert!(r.is_local());
    }

    #[test]
    fn local_ip_detection() {
        assert!(is_local_ip(&"192.168.1.4".parse().unwrap()));
        assert!(is_local_ip(&"224.0.0.251".parse().unwrap()));
        assert!(is_local_ip(&"fe80::1".parse().unwrap()));
        assert!(!is_local_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_local_ip(&"2606:4700::1111".parse().unwrap()));
    }
}
