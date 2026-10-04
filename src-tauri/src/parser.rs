//! Zero-copy decoders for the link types libpcap hands us:
//!
//! * `DLT_IEEE802_11_RADIO` (127) - monitor mode with a radiotap header
//! * `DLT_IEEE802_11` (105)      - monitor mode without radiotap
//! * `DLT_EN10MB` (1)            - normal managed-mode / wired capture
//! * `DLT_LINUX_SLL` (113)       - Linux "any" pseudo-interface
//!
//! From there we walk LLC/SNAP -> IPv4/IPv6 -> TCP/UDP and pull out DNS
//! names and TLS SNI, which is what the behavioral baseline is built on.

use crate::model::{ArpInfo, FrameKind, Hint, Mac, NetInfo, PacketInfo, Transport};
use chrono::{DateTime, Utc};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DLT_EN10MB: i32 = 1;
pub const DLT_IEEE802_11: i32 = 105;
pub const DLT_LINUX_SLL: i32 = 113;
pub const DLT_IEEE802_11_RADIO: i32 = 127;

pub fn supported_linktype(lt: i32) -> bool {
    matches!(lt, DLT_EN10MB | DLT_IEEE802_11 | DLT_LINUX_SLL | DLT_IEEE802_11_RADIO)
}

pub fn linktype_name(lt: i32) -> &'static str {
    match lt {
        DLT_EN10MB => "Ethernet (managed mode)",
        DLT_IEEE802_11 => "802.11 (monitor, no radiotap)",
        DLT_LINUX_SLL => "Linux cooked capture",
        DLT_IEEE802_11_RADIO => "802.11 + radiotap (monitor)",
        _ => "unsupported",
    }
}

/// Decode one captured frame. Returns `None` for truncated / unsupported data.
pub fn parse(linktype: i32, data: &[u8], ts: DateTime<Utc>, wire_len: u32) -> Option<PacketInfo> {
    match linktype {
        DLT_IEEE802_11_RADIO => {
            let rt = parse_radiotap(data)?;
            if rt.bad_fcs {
                return None; // corrupted frames would create phantom MACs
            }
            let mut frame = data.get(rt.header_len..)?;
            if rt.has_fcs && frame.len() >= 4 {
                frame = &frame[..frame.len() - 4];
            }
            let mut p = parse_80211(frame, ts, wire_len)?;
            p.rssi = rt.rssi;
            p.channel = rt.freq.and_then(freq_to_channel);
            Some(p)
        }
        DLT_IEEE802_11 => parse_80211(data, ts, wire_len),
        DLT_EN10MB => parse_ethernet(data, ts, wire_len),
        DLT_LINUX_SLL => parse_sll(data, ts, wire_len),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Radiotap
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Radiotap {
    pub header_len: usize,
    pub rssi: Option<i8>,
    pub freq: Option<u16>,
    pub has_fcs: bool,
    pub bad_fcs: bool,
}

/// Parse the radiotap fields we need (flags, channel, antenna signal). The
/// fields are laid out in present-bit order, each naturally aligned relative
/// to the start of the header.
pub fn parse_radiotap(d: &[u8]) -> Option<Radiotap> {
    if d.len() < 8 || d[0] != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([d[2], d[3]]) as usize;
    if header_len > d.len() || header_len < 8 {
        return None;
    }
    let present = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);

    // Skip any extended present bitmaps (bit 31 = another word follows).
    let mut off = 8;
    let mut word = present;
    while word & 0x8000_0000 != 0 {
        word = u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?);
        off += 4;
    }

    let mut rt = Radiotap { header_len, ..Default::default() };
    // (bit, alignment, size) for fields 0..=5
    const FIELDS: [(u32, usize, usize); 6] = [
        (0, 8, 8), // TSFT
        (1, 1, 1), // Flags
        (2, 1, 1), // Rate
        (3, 2, 4), // Channel: freq u16 + flags u16
        (4, 2, 2), // FHSS
        (5, 1, 1), // dBm antenna signal
    ];
    for (bit, align, size) in FIELDS {
        if present & (1 << bit) == 0 {
            continue;
        }
        off = (off + align - 1) & !(align - 1);
        if off + size > header_len {
            break;
        }
        match bit {
            1 => {
                rt.has_fcs = d[off] & 0x10 != 0;
                rt.bad_fcs = d[off] & 0x40 != 0;
            }
            3 => rt.freq = Some(u16::from_le_bytes([d[off], d[off + 1]])),
            5 => rt.rssi = Some(d[off] as i8),
            _ => {}
        }
        off += size;
    }
    Some(rt)
}

pub fn freq_to_channel(f: u16) -> Option<u16> {
    match f {
        2484 => Some(14),
        2412..=2472 => Some((f - 2407) / 5),
        5955..=7115 => Some((f - 5950) / 5),
        5000..=5895 => Some((f - 5000) / 5),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 802.11
// ---------------------------------------------------------------------------

fn mgmt_subtype(s: u8) -> &'static str {
    match s {
        0 => "assoc-req",
        1 => "assoc-resp",
        2 => "reassoc-req",
        3 => "reassoc-resp",
        4 => "probe-req",
        5 => "probe-resp",
        8 => "beacon",
        9 => "atim",
        10 => "disassoc",
        11 => "auth",
        12 => "deauth",
        13 => "action",
        _ => "mgmt-other",
    }
}

fn ctrl_subtype(s: u8) -> &'static str {
    match s {
        8 => "block-ack-req",
        9 => "block-ack",
        10 => "ps-poll",
        11 => "rts",
        12 => "cts",
        13 => "ack",
        14 => "cf-end",
        _ => "ctrl-other",
    }
}

fn data_subtype(s: u8) -> &'static str {
    match s {
        0 => "data",
        4 => "null",
        8 => "qos-data",
        12 => "qos-null",
        _ => "data-other",
    }
}

pub fn parse_80211(f: &[u8], ts: DateTime<Utc>, wire_len: u32) -> Option<PacketInfo> {
    if f.len() < 10 {
        return None;
    }
    let fc0 = f[0];
    let flags = f[1];
    let ftype = (fc0 >> 2) & 0x3;
    let subtype = (fc0 >> 4) & 0xf;
    let to_ds = flags & 0x01 != 0;
    let from_ds = flags & 0x02 != 0;
    let protected = flags & 0x40 != 0;
    let addr1 = Mac::from_slice(&f[4..]);
    let addr2 = f.get(10..16).and_then(Mac::from_slice);
    let addr3 = f.get(16..22).and_then(Mac::from_slice);

    match ftype {
        0 => {
            let st = mgmt_subtype(subtype);
            let mut p = PacketInfo::new(ts, FrameKind::Management, st, wire_len);
            p.dst = addr1;
            p.src = addr2;
            p.bssid = addr3;
            p.protected = protected;
            // Fixed parameters before the tagged IEs.
            let fixed = match subtype {
                0 => Some(4),      // assoc req: capability + listen interval
                2 => Some(10),     // reassoc req: + current AP
                4 => Some(0),      // probe request
                5 | 8 => Some(12), // probe resp / beacon: timestamp + interval + cap
                _ => None,
            };
            if let (Some(fixed), false) = (fixed, protected) {
                if let Some(ies) = f.get(24 + fixed..) {
                    p.ssid = find_ssid(ies);
                }
            }
            Some(p)
        }
        1 => {
            let st = ctrl_subtype(subtype);
            let mut p = PacketInfo::new(ts, FrameKind::Control, st, wire_len);
            p.dst = addr1;
            // ACK and CTS only carry the receiver address.
            if !matches!(subtype, 12 | 13) {
                p.src = addr2;
            }
            Some(p)
        }
        2 => {
            let st = data_subtype(subtype);
            let mut p = PacketInfo::new(ts, FrameKind::Data, st, wire_len);
            p.protected = protected;
            p.to_ds = to_ds;
            p.from_ds = from_ds;
            let mut hdr = 24;
            match (to_ds, from_ds) {
                (false, false) => {
                    p.dst = addr1;
                    p.src = addr2;
                    p.bssid = addr3;
                }
                (true, false) => {
                    p.bssid = addr1;
                    p.src = addr2;
                    p.dst = addr3;
                }
                (false, true) => {
                    p.dst = addr1;
                    p.bssid = addr2;
                    p.src = addr3;
                }
                (true, true) => {
                    // WDS / mesh: addr4 is the original source.
                    p.dst = addr3;
                    p.src = f.get(24..30).and_then(Mac::from_slice);
                    hdr = 30;
                }
            }
            let qos = subtype & 0x8 != 0;
            if qos {
                hdr += 2;
                // HT control field present when the +HTC/Order bit is set.
                if flags & 0x80 != 0 {
                    hdr += 4;
                }
            }
            // Null-function frames carry no body; encrypted bodies are opaque.
            if subtype & 0x4 == 0 && !protected {
                if let Some(body) = f.get(hdr..) {
                    // LLC/SNAP: AA AA 03 00 00 00 <ethertype>
                    if body.len() >= 8 && body[..6] == [0xaa, 0xaa, 0x03, 0, 0, 0] {
                        let et = u16::from_be_bytes([body[6], body[7]]);
                        p.net = parse_l3(et, &body[8..]);
                        p.arp = parse_arp(et, &body[8..]);
                    }
                }
            }
            Some(p)
        }
        _ => None,
    }
}

/// Walk tagged information elements looking for SSID (element ID 0).
fn find_ssid(mut ies: &[u8]) -> Option<String> {
    while ies.len() >= 2 {
        let id = ies[0];
        let len = ies[1] as usize;
        let val = ies.get(2..2 + len)?;
        if id == 0 {
            // Hidden networks advertise an empty or all-zero SSID.
            if val.is_empty() || val.iter().all(|&b| b == 0) {
                return None;
            }
            return Some(String::from_utf8_lossy(val).into_owned());
        }
        ies = &ies[2 + len..];
    }
    None
}

// ---------------------------------------------------------------------------
// Ethernet / Linux cooked
// ---------------------------------------------------------------------------

pub fn parse_ethernet(d: &[u8], ts: DateTime<Utc>, wire_len: u32) -> Option<PacketInfo> {
    if d.len() < 14 {
        return None;
    }
    let mut p = PacketInfo::new(ts, FrameKind::Ethernet, "ethernet", wire_len);
    p.dst = Mac::from_slice(&d[0..6]);
    p.src = Mac::from_slice(&d[6..12]);
    let mut et = u16::from_be_bytes([d[12], d[13]]);
    let mut off = 14;
    // 802.1Q / QinQ VLAN tags
    while (et == 0x8100 || et == 0x88a8) && d.len() >= off + 4 {
        et = u16::from_be_bytes([d[off + 2], d[off + 3]]);
        off += 4;
    }
    p.subtype = match et {
        0x0800 => "ipv4",
        0x86dd => "ipv6",
        0x0806 => "arp",
        0x888e => "eapol",
        _ => "ethernet",
    };
    p.net = parse_l3(et, &d[off..]);
    p.arp = parse_arp(et, &d[off..]);
    Some(p)
}

pub fn parse_sll(d: &[u8], ts: DateTime<Utc>, wire_len: u32) -> Option<PacketInfo> {
    if d.len() < 16 {
        return None;
    }
    let mut p = PacketInfo::new(ts, FrameKind::Ethernet, "sll", wire_len);
    let halen = u16::from_be_bytes([d[4], d[5]]);
    if halen == 6 {
        p.src = Mac::from_slice(&d[6..12]);
    }
    let et = u16::from_be_bytes([d[14], d[15]]);
    p.net = parse_l3(et, &d[16..]);
    p.arp = parse_arp(et, &d[16..]);
    Some(p)
}

// ---------------------------------------------------------------------------
// IP / TCP / UDP
// ---------------------------------------------------------------------------

pub fn parse_l3(ethertype: u16, d: &[u8]) -> Option<NetInfo> {
    let (src, dst, proto, l4) = match ethertype {
        0x0800 => {
            if d.len() < 20 || d[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((d[0] & 0x0f) as usize) * 4;
            let total = (u16::from_be_bytes([d[2], d[3]]) as usize).clamp(ihl, d.len());
            // Later fragments have no L4 header.
            let frag_off = u16::from_be_bytes([d[6], d[7]]) & 0x1fff;
            let src = IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19]));
            let l4 = if frag_off == 0 { d.get(ihl..total).unwrap_or(&[]) } else { &[][..] };
            (src, dst, d[9], l4)
        }
        0x86dd => {
            if d.len() < 40 || d[0] >> 4 != 6 {
                return None;
            }
            let s: [u8; 16] = d[8..24].try_into().ok()?;
            let t: [u8; 16] = d[24..40].try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(t)), d[6], &d[40..])
        }
        _ => return None,
    };

    let mut n = NetInfo {
        src_ip: src,
        dst_ip: dst,
        transport: Transport::Other,
        src_port: None,
        dst_port: None,
        tcp_syn: false,
        dns_query: None,
        dns_answers: vec![],
        sni: None,
        hints: vec![],
    };

    match proto {
        6 if l4.len() >= 20 => {
            n.transport = Transport::Tcp;
            n.src_port = Some(u16::from_be_bytes([l4[0], l4[1]]));
            n.dst_port = Some(u16::from_be_bytes([l4[2], l4[3]]));
            let flags = l4[13];
            n.tcp_syn = flags & 0x02 != 0 && flags & 0x10 == 0;
            let doff = ((l4[12] >> 4) as usize) * 4;
            if let Some(payload) = l4.get(doff..) {
                if !payload.is_empty() {
                    n.sni = parse_tls_sni(payload);
                    if n.sni.is_none() {
                        if let Some(ua) = parse_http_ua(payload) {
                            n.hints.push(Hint::UserAgent(ua));
                        }
                    }
                }
            }
        }
        17 if l4.len() >= 8 => {
            n.transport = Transport::Udp;
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            n.src_port = Some(sp);
            n.dst_port = Some(dp);
            let payload = &l4[8..];
            if sp == 53 || dp == 53 {
                if let Some((q, answers)) = parse_dns(payload) {
                    n.dns_query = Some(q);
                    n.dns_answers = answers;
                }
            } else if (sp == 68 && dp == 67) || (sp == 67 && dp == 68) {
                n.hints = parse_dhcp(payload);
            } else if sp == 5353 {
                n.hints = parse_mdns(payload, &src);
            } else if sp == 1900 || dp == 1900 {
                n.hints = parse_ssdp(payload);
            }
        }
        1 | 58 => n.transport = Transport::Icmp,
        6 => n.transport = Transport::Tcp,
        17 => n.transport = Transport::Udp,
        _ => {}
    }
    Some(n)
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// Read a (possibly compressed) DNS name starting at `off`. Returns the name
/// and the offset just past it in the original (uncompressed) position.
fn dns_name(msg: &[u8], off: usize) -> Option<(String, usize)> {
    dns_name_case(msg, off, true)
}

fn dns_name_case(msg: &[u8], mut off: usize, lower: bool) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    for _ in 0..64 {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(off + 1)? as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            if ptr >= off {
                return None; // forward pointers would allow loops
            }
            off = ptr;
            continue;
        }
        let label = msg.get(off + 1..off + 1 + len)?;
        let l = String::from_utf8_lossy(label);
        labels.push(if lower { l.to_ascii_lowercase() } else { l.into_owned() });
        off += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(off)))
}

/// Returns the first question name and any A/AAAA answers (mapped to the
/// question name, so CNAME chains resolve to the name the device asked for).
pub fn parse_dns(msg: &[u8]) -> Option<(String, Vec<(String, IpAddr)>)> {
    if msg.len() < 12 {
        return None;
    }
    let is_response = msg[2] & 0x80 != 0;
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    if qd == 0 {
        return None;
    }
    let mut off = 12;
    let (qname, next) = dns_name(msg, off)?;
    off = next + 4; // qtype + qclass
    for _ in 1..qd {
        let (_, next) = dns_name(msg, off)?;
        off = next + 4;
    }
    let mut answers = Vec::new();
    if is_response {
        for _ in 0..an.min(64) {
            let Some((_, next)) = dns_name(msg, off) else { break };
            let Some(rr) = msg.get(next..next + 10) else { break };
            let rtype = u16::from_be_bytes([rr[0], rr[1]]);
            let rdlen = u16::from_be_bytes([rr[8], rr[9]]) as usize;
            let Some(rdata) = msg.get(next + 10..next + 10 + rdlen) else { break };
            match (rtype, rdlen) {
                (1, 4) => answers.push((
                    qname.clone(),
                    IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                )),
                (28, 16) => {
                    let a: [u8; 16] = rdata.try_into().ok()?;
                    answers.push((qname.clone(), IpAddr::V6(Ipv6Addr::from(a))));
                }
                _ => {}
            }
            off = next + 10 + rdlen;
        }
    }
    if qname.is_empty() {
        return None;
    }
    Some((qname, answers))
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI
// ---------------------------------------------------------------------------

pub fn parse_tls_sni(d: &[u8]) -> Option<String> {
    // TLS record: handshake(0x16), version, length
    if d.len() < 43 || d[0] != 0x16 || d[1] != 0x03 {
        return None;
    }
    let hs = &d[5..];
    if hs[0] != 0x01 {
        return None; // not ClientHello
    }
    let mut off = 4 + 2 + 32; // handshake header + client_version + random
    let sid_len = *hs.get(off)? as usize;
    off += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*hs.get(off)?, *hs.get(off + 1)?]) as usize;
    off += 2 + cs_len;
    let comp_len = *hs.get(off)? as usize;
    off += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*hs.get(off)?, *hs.get(off + 1)?]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(hs.len());
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[off], hs[off + 1]]);
        let elen = u16::from_be_bytes([hs[off + 2], hs[off + 3]]) as usize;
        off += 4;
        if etype == 0 {
            // server_name_list: len(2) type(1) name_len(2) name
            let name_len = u16::from_be_bytes([*hs.get(off + 3)?, *hs.get(off + 4)?]) as usize;
            let name = hs.get(off + 5..off + 5 + name_len)?;
            return Some(String::from_utf8_lossy(name).to_ascii_lowercase());
        }
        off += elen;
    }
    None
}

// ---------------------------------------------------------------------------
// LAN discovery protocols: ARP, DHCP, mDNS, SSDP, HTTP
// ---------------------------------------------------------------------------

pub fn parse_arp(ethertype: u16, d: &[u8]) -> Option<ArpInfo> {
    // Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4
    if ethertype != 0x0806 || d.len() < 28 || d[0..2] != [0, 1] || d[2..4] != [8, 0] || d[4] != 6 || d[5] != 4 {
        return None;
    }
    let op = u16::from_be_bytes([d[6], d[7]]);
    let sender_mac = Mac::from_slice(&d[8..14])?;
    let sender_ip = Ipv4Addr::new(d[14], d[15], d[16], d[17]);
    let target_ip = Ipv4Addr::new(d[24], d[25], d[26], d[27]);
    if !sender_mac.is_unicast() || sender_ip.is_unspecified() {
        return None;
    }
    Some(ArpInfo { sender_mac, sender_ip, target_ip, reply: op == 2 })
}

fn clean(s: &[u8]) -> Option<String> {
    let t: String = String::from_utf8_lossy(s).chars().filter(|c| !c.is_control()).collect();
    let t = t.trim();
    (!t.is_empty()).then(|| t.chars().take(160).collect())
}

/// DHCP client requests carry the hostname (12) and vendor class (60).
pub fn parse_dhcp(d: &[u8]) -> Vec<Hint> {
    let mut out = vec![];
    // op=1 BOOTREQUEST, magic cookie at 236
    if d.len() < 240 || d[0] != 1 || d[236..240] != [99, 130, 83, 99] {
        return out;
    }
    let mut i = 240;
    while i + 1 < d.len() {
        let code = d[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = d[i + 1] as usize;
        let Some(val) = d.get(i + 2..i + 2 + len) else { break };
        match code {
            12 => out.extend(clean(val).map(Hint::Hostname)),
            60 => out.extend(clean(val).map(Hint::VendorClass)),
            _ => {}
        }
        i += 2 + len;
    }
    out
}

/// Walk every resource record in a DNS message: (name, type, rdata offset, rdlen).
fn dns_records(msg: &[u8]) -> Vec<(String, u16, usize, usize)> {
    let mut out = vec![];
    if msg.len() < 12 {
        return out;
    }
    let count = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
    let (qd, rr) = (count(4), count(6) + count(8) + count(10));
    let mut off = 12;
    for _ in 0..qd.min(32) {
        let Some((_, next)) = dns_name(msg, off) else { return out };
        off = next + 4;
    }
    for _ in 0..rr.min(64) {
        let Some((name, next)) = dns_name(msg, off) else { break };
        let Some(h) = msg.get(next..next + 10) else { break };
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        if next + 10 + rdlen > msg.len() {
            break;
        }
        out.push((name, rtype, next + 10, rdlen));
        off = next + 10 + rdlen;
    }
    out
}

/// mDNS responses announce `<host>.local` and DNS-SD services
/// (`Living Room._googlecast._tcp.local`).
pub fn parse_mdns(msg: &[u8], src: &IpAddr) -> Vec<Hint> {
    let mut out: Vec<Hint> = vec![];
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return out; // queries only tell us what a device looks for
    }
    let mut push = |h: Hint| {
        if !out.contains(&h) {
            out.push(h);
        }
    };
    for (name, rtype, rd, rdlen) in dns_records(msg) {
        match rtype {
            // A / AAAA for the sender itself -> hostname
            1 | 28 => {
                let matches_src = match (rtype, src) {
                    (1, IpAddr::V4(v4)) => rdlen == 4 && msg[rd..rd + 4] == v4.octets(),
                    (28, IpAddr::V6(v6)) => rdlen == 16 && msg[rd..rd + 16] == v6.octets(),
                    _ => false,
                };
                if matches_src {
                    if let Some(h) = name.strip_suffix(".local").filter(|h| !h.is_empty()) {
                        push(Hint::Hostname(h.to_string()));
                    }
                }
            }
            // PTR: service type -> instance
            12 => {
                if name.starts_with("_services.") {
                    continue;
                }
                if let Some(svc) = name.strip_suffix(".local").filter(|n| n.starts_with('_')) {
                    push(Hint::Service(svc.to_string()));
                    if let Some((inst, _)) = dns_name_case(msg, rd, false) {
                        if let Some(i) = inst.find("._") {
                            let friendly = &inst[..i];
                            if !friendly.is_empty() && friendly.len() < 64 && !friendly.contains('@') {
                                push(Hint::Hostname(friendly.to_string()));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn header_value(text: &str, header: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(header).then(|| v.trim().to_string()).filter(|v| !v.is_empty())
    })
}

/// SSDP NOTIFY / M-SEARCH responses carry `SERVER: OS/ver UPnP/1.0 Product/ver`.
pub fn parse_ssdp(d: &[u8]) -> Vec<Hint> {
    let text = String::from_utf8_lossy(&d[..d.len().min(1500)]);
    header_value(&text, "server").and_then(|v| clean(v.as_bytes())).map(Hint::Server).into_iter().collect()
}

pub fn parse_http_ua(d: &[u8]) -> Option<String> {
    let head = &d[..d.len().min(2048)];
    let is_req = [&b"GET "[..], b"POST ", b"PUT ", b"HEAD "].iter().any(|m| head.starts_with(m));
    if !is_req {
        return None;
    }
    header_value(&String::from_utf8_lossy(head), "user-agent").and_then(|v| clean(v.as_bytes()))
}

// ---------------------------------------------------------------------------
// Tests: hand-built frames
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut v = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 17, 0, 0];
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn dns_response() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in ["cam", "example", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        // answer: pointer to offset 12, A, IN, ttl, len 4, 93.184.216.34
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        m
    }

    #[test]
    fn radiotap_80211_data_with_dns() {
        // radiotap: flags + channel + antenna signal
        let present: u32 = (1 << 1) | (1 << 3) | (1 << 5);
        let mut rt = vec![0, 0, 0, 0];
        rt.extend_from_slice(&present.to_le_bytes());
        rt.push(0x00); // flags (off 8)
        rt.push(0x00); // pad to align channel at 10
        rt.extend_from_slice(&2437u16.to_le_bytes());
        rt.extend_from_slice(&0x00a0u16.to_le_bytes());
        rt.push((-48i8) as u8); // antenna signal at 14
        let hl = rt.len() as u16;
        rt[2..4].copy_from_slice(&hl.to_le_bytes());

        // 802.11 data, FromDS: addr1 = DA (station), addr2 = BSSID, addr3 = SA
        let sta = [0xb8, 0x27, 0xeb, 1, 2, 3];
        let ap = [0x50, 0xc7, 0xbf, 9, 9, 9];
        let gw = [0x50, 0xc7, 0xbf, 9, 9, 1];
        let mut f = vec![0x08, 0x02, 0, 0];
        f.extend_from_slice(&sta);
        f.extend_from_slice(&ap);
        f.extend_from_slice(&gw);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
        f.extend_from_slice(&ipv4_udp([1, 1, 1, 1], [192, 168, 1, 20], 53, 40000, &dns_response()));

        let mut pkt = rt;
        pkt.extend_from_slice(&f);
        let p = parse(DLT_IEEE802_11_RADIO, &pkt, Utc::now(), pkt.len() as u32).unwrap();
        assert_eq!(p.kind, FrameKind::Data);
        assert_eq!(p.rssi, Some(-48));
        assert_eq!(p.channel, Some(6));
        assert_eq!(p.dst, Some(Mac(sta)));
        assert_eq!(p.src, Some(Mac(gw)));
        assert_eq!(p.bssid, Some(Mac(ap)));
        let n = p.net.unwrap();
        assert_eq!(n.dns_query.as_deref(), Some("cam.example.com"));
        assert_eq!(n.dns_answers[0].1, "93.184.216.34".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn arp_dhcp_mdns_ssdp() {
        // ARP reply 192.168.1.50 is-at 44:19:b6:...
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2, 0x44, 0x19, 0xb6, 1, 2, 3, 192, 168, 1, 50];
        arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 192, 168, 1, 2]);
        let a = parse_arp(0x0806, &arp).unwrap();
        assert!(a.reply);
        assert_eq!(a.sender_ip, Ipv4Addr::new(192, 168, 1, 50));

        let mut dhcp = vec![0u8; 240];
        dhcp[0] = 1;
        dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        dhcp.extend_from_slice(&[12, 9]);
        dhcp.extend_from_slice(b"Pixel-8a!");
        dhcp.extend_from_slice(&[60, 14]);
        dhcp.extend_from_slice(b"android-dhcp-1");
        dhcp.push(255);
        let h = parse_dhcp(&dhcp);
        assert_eq!(h[0], Hint::Hostname("Pixel-8a!".into()));
        assert_eq!(h[1], Hint::VendorClass("android-dhcp-1".into()));

        // mDNS response: PTR _googlecast._tcp.local -> "Living Room._googlecast._tcp.local", A tv.local
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        let name = |v: &mut Vec<u8>, labels: &[&str]| {
            for l in labels {
                v.push(l.len() as u8);
                v.extend_from_slice(l.as_bytes());
            }
            v.push(0);
        };
        name(&mut m, &["_googlecast", "_tcp", "local"]);
        let mut rdata = vec![];
        name(&mut rdata, &["Living Room", "_googlecast", "_tcp", "local"]);
        m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120]);
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
        name(&mut m, &["tv", "local"]);
        m.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 40]);
        let h = parse_mdns(&m, &"192.168.1.40".parse().unwrap());
        assert!(h.contains(&Hint::Service("_googlecast._tcp".into())));
        assert!(h.contains(&Hint::Hostname("Living Room".into())));
        assert!(h.contains(&Hint::Hostname("tv".into())));

        let s = parse_ssdp(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Linux/3.14 UPnP/1.0 Sonos/70.3\r\n\r\n");
        assert_eq!(s, vec![Hint::Server("Linux/3.14 UPnP/1.0 Sonos/70.3".into())]);
        assert_eq!(parse_http_ua(b"GET / HTTP/1.1\r\nUser-Agent: Wyze/2.1\r\n\r\n").as_deref(), Some("Wyze/2.1"));
    }

    #[test]
    fn beacon_ssid() {
        let mut f = vec![0x80, 0, 0, 0];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x50, 0xc7, 0xbf, 9, 9, 9]);
        f.extend_from_slice(&[0x50, 0xc7, 0xbf, 9, 9, 9]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0; 12]);
        f.extend_from_slice(&[0, 6]);
        f.extend_from_slice(b"HomeAP");
        let p = parse(DLT_IEEE802_11, &f, Utc::now(), f.len() as u32).unwrap();
        assert_eq!(p.subtype, "beacon");
        assert_eq!(p.ssid.as_deref(), Some("HomeAP"));
    }

    #[test]
    fn ethernet_tls_sni() {
        let host = b"evil.example.net";
        let mut ext = vec![0, 0];
        let list_len = (3 + host.len()) as u16;
        ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut tls = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
        tls.extend_from_slice(&hs);

        let mut tcp = vec![0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0];
        tcp.extend_from_slice(&tls);
        let total = 20 + tcp.len();
        let mut ip = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 5, 203, 0, 113, 9];
        ip.extend_from_slice(&tcp);
        let mut eth = vec![0x02, 0, 0, 0, 0, 1, 0x44, 0x19, 0xb6, 1, 2, 3, 0x08, 0x00];
        eth.extend_from_slice(&ip);

        let p = parse(DLT_EN10MB, &eth, Utc::now(), eth.len() as u32).unwrap();
        let n = p.net.unwrap();
        assert_eq!(n.dst_port, Some(443));
        assert_eq!(n.sni.as_deref(), Some("evil.example.net"));
        assert!(!n.tcp_syn);
    }
}
