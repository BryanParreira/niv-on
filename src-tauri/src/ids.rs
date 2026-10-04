//! Signature detection: a practical subset of Suricata / Snort rules.
//!
//! Supported: `alert|drop|reject` rules on tcp/udp/icmp/ip (and app-layer
//! protocols mapped to their transport), `$HOME_NET` / `$EXTERNAL_NET` / IP
//! and CIDR lists, port lists and ranges, `content` (with `|hex|`, `nocase`,
//! `offset`, `depth`, `distance`, `within`, negation), `dsize`, `msg`, `sid`,
//! `rev`, `classtype`, `priority`. Rules using state or regex keywords
//! (`pcre`, `flowbits`, `byte_test`, ...) are skipped rather than matched
//! loosely, so imported rule sets never produce false positives from
//! features we can't evaluate.
//!
//! Matching runs on the first bytes of each packet's payload (no stream
//! reassembly). An Aho-Corasick automaton over each rule's longest content
//! keeps it fast with tens of thousands of rules.

use crate::model::IpNet;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Clone, Debug)]
enum Addr {
    Any,
    Home(bool),
    Nets(Vec<IpNet>, bool),
}

#[derive(Clone, Debug)]
enum Ports {
    Any,
    Set(Vec<(u16, u16)>, bool),
}

#[derive(Clone, Debug)]
struct Content {
    bytes: Vec<u8>,
    nocase: bool,
    negated: bool,
    offset: Option<usize>,
    depth: Option<usize>,
    distance: Option<isize>,
    within: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub sid: u32,
    pub rev: u32,
    pub msg: String,
    pub classtype: Option<String>,
    pub priority: u8,
    proto: Proto,
    src: Addr,
    sport: Ports,
    dst: Addr,
    dport: Ports,
    bidir: bool,
    contents: Vec<Content>,
    dsize: Option<(u8, usize, usize)>,
    /// Where the rule came from (file name).
    pub source: String,
}

/// One packet, as seen by the matcher.
pub struct Packet<'a> {
    pub proto: Proto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub src_home: bool,
    pub dst_home: bool,
    pub payload: &'a [u8],
}

#[derive(Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// (source, loaded, skipped as unsupported)
    pub stats: Vec<(String, usize, usize)>,
    ac: Option<AhoCorasick>,
    /// Pattern index -> rules whose fast pattern it is.
    by_pattern: Vec<Vec<usize>>,
}

impl RuleSet {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Parse rule text; unsupported rules are counted and skipped.
    pub fn add_text(&mut self, source: &str, text: &str) {
        let (mut ok, mut skipped) = (0, 0);
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            match parse_rule(l, source) {
                Some(r) if self.rules.len() < 50_000 => {
                    self.rules.push(r);
                    ok += 1;
                }
                _ => skipped += 1,
            }
        }
        self.stats.push((source.to_string(), ok, skipped));
    }

    /// Build the prefilter. Call after adding all rule text.
    pub fn build(&mut self) {
        let mut patterns: Vec<Vec<u8>> = vec![];
        let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
        self.by_pattern.clear();
        for (i, r) in self.rules.iter().enumerate() {
            let fast = r
                .contents
                .iter()
                .filter(|c| !c.negated)
                .max_by_key(|c| c.bytes.len())
                .expect("rules have a positive content");
            let key = fast.bytes.to_ascii_lowercase();
            let pi = *index.entry(key.clone()).or_insert_with(|| {
                patterns.push(key);
                self.by_pattern.push(vec![]);
                patterns.len() - 1
            });
            self.by_pattern[pi].push(i);
        }
        self.ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .ok();
    }

    /// Rules matching this packet (deduplicated, ordered by priority).
    pub fn matches(&self, p: &Packet) -> Vec<&Rule> {
        let Some(ac) = &self.ac else { return vec![] };
        if p.payload.is_empty() {
            return vec![];
        }
        let mut cand: BTreeSet<usize> = BTreeSet::new();
        for m in ac.find_overlapping_iter(p.payload) {
            cand.extend(self.by_pattern[m.pattern().as_usize()].iter().copied());
        }
        let mut lower: Option<Vec<u8>> = None;
        let mut out: Vec<&Rule> = cand
            .into_iter()
            .map(|i| &self.rules[i])
            .filter(|r| {
                r.header_matches(p) && r.dsize_ok(p.payload.len()) && {
                    let low = lower.get_or_insert_with(|| p.payload.to_ascii_lowercase());
                    r.contents_match(p.payload, low)
                }
            })
            .collect();
        out.sort_by_key(|r| (r.priority, r.sid));
        out
    }
}

impl Rule {
    fn header_matches(&self, p: &Packet) -> bool {
        if !(self.proto == Proto::Any || self.proto == p.proto) {
            return false;
        }
        let fwd = self.src.ok(&p.src, p.src_home)
            && self.dst.ok(&p.dst, p.dst_home)
            && self.sport.ok(p.sport)
            && self.dport.ok(p.dport);
        fwd || (self.bidir
            && self.src.ok(&p.dst, p.dst_home)
            && self.dst.ok(&p.src, p.src_home)
            && self.sport.ok(p.dport)
            && self.dport.ok(p.sport))
    }

    fn dsize_ok(&self, n: usize) -> bool {
        match self.dsize {
            None => true,
            Some((b'<', a, _)) => n < a,
            Some((b'>', a, _)) => n > a,
            Some((b'r', a, b)) => n > a && n < b,
            Some((_, a, _)) => n == a,
        }
    }

    fn contents_match(&self, payload: &[u8], lower: &[u8]) -> bool {
        // Position just past the previous positive match (for distance/within).
        let mut prev_end: usize = 0;
        for c in &self.contents {
            let hay = if c.nocase { lower } else { payload };
            let needle: Vec<u8> = if c.nocase {
                c.bytes.to_ascii_lowercase()
            } else {
                c.bytes.clone()
            };
            let relative = c.distance.is_some() || c.within.is_some();
            let mut start = if relative {
                (prev_end as isize + c.distance.unwrap_or(0)).max(0) as usize
            } else {
                c.offset.unwrap_or(0)
            };
            let mut end = hay.len();
            if relative {
                if let Some(w) = c.within {
                    end = end.min(
                        prev_end
                            .saturating_add(c.distance.unwrap_or(0).max(0) as usize)
                            .saturating_add(w),
                    );
                }
            } else if let Some(d) = c.depth {
                end = end.min(start + d);
            }
            start = start.min(hay.len());
            let found = if end > start {
                memchr::memmem::find(&hay[start..end], &needle).map(|i| start + i)
            } else {
                None
            };
            match (found, c.negated) {
                (Some(i), false) => prev_end = i + needle.len(),
                (None, true) => {}
                _ => return false,
            }
        }
        true
    }
}

impl Addr {
    fn ok(&self, ip: &IpAddr, home: bool) -> bool {
        match self {
            Addr::Any => true,
            Addr::Home(h) => home == *h,
            Addr::Nets(n, neg) => n.iter().any(|n| n.contains(ip)) != *neg,
        }
    }
}

impl Ports {
    fn ok(&self, p: u16) -> bool {
        match self {
            Ports::Any => true,
            Ports::Set(s, neg) => s.iter().any(|(a, b)| p >= *a && p <= *b) != *neg,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn parse_addr(s: &str) -> Option<Addr> {
    let (neg, s) = match s.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let u = s.to_ascii_uppercase();
    if u == "ANY" {
        return Some(if neg {
            Addr::Nets(vec![], false)
        } else {
            Addr::Any
        });
    }
    if u == "$HOME_NET" || u.ends_with("_SERVERS") && u != "$DNS_SERVERS" {
        return Some(Addr::Home(!neg));
    }
    if u == "$EXTERNAL_NET" {
        return Some(Addr::Home(neg));
    }
    if u.starts_with('$') {
        return Some(Addr::Any);
    }
    let inner = s.trim_start_matches('[').trim_end_matches(']');
    let mut nets = vec![];
    for part in inner.split(',') {
        let p = part.trim();
        if p.starts_with('!') || p.starts_with('$') {
            return Some(Addr::Any); // nested negation/variables: don't guess
        }
        nets.push(p.parse::<IpNet>().ok()?);
    }
    Some(Addr::Nets(nets, neg))
}

fn port_var(v: &str) -> Option<Vec<(u16, u16)>> {
    Some(match v {
        "$HTTP_PORTS" => vec![
            (80, 80),
            (81, 81),
            (8000, 8000),
            (8008, 8008),
            (8080, 8080),
            (8081, 8081),
            (8888, 8888),
        ],
        "$SHELLCODE_PORTS" => return None,
        "$ORACLE_PORTS" => vec![(1521, 1521)],
        "$SSH_PORTS" => vec![(22, 22)],
        "$FTP_PORTS" => vec![(21, 21)],
        "$FILE_DATA_PORTS" => vec![(80, 80), (110, 110), (143, 143)],
        "$DNP3_PORTS" => vec![(20000, 20000)],
        "$MODBUS_PORTS" => vec![(502, 502)],
        _ => return None,
    })
}

fn parse_ports(s: &str) -> Option<Ports> {
    let (neg, s) = match s.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, s),
    };
    if s.eq_ignore_ascii_case("any") {
        return Some(Ports::Any);
    }
    if s.starts_with('$') {
        return Some(match port_var(s) {
            Some(v) => Ports::Set(v, neg),
            None => Ports::Any,
        });
    }
    let mut set = vec![];
    for part in s.trim_start_matches('[').trim_end_matches(']').split(',') {
        let p = part.trim();
        if p.starts_with('!') || p.starts_with('$') {
            return Some(Ports::Any);
        }
        let range = match p.split_once(':') {
            Some((a, b)) => (
                if a.is_empty() { 0 } else { a.parse().ok()? },
                if b.is_empty() { 65535 } else { b.parse().ok()? },
            ),
            None => {
                let v = p.parse().ok()?;
                (v, v)
            }
        };
        set.push(range);
    }
    Some(Ports::Set(set, neg))
}

/// Split `key:value;` options, honouring quotes and backslash escapes.
fn split_options(s: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut cur = String::new();
    let (mut q, mut esc) = (false, false);
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' => {
                cur.push(c);
                esc = true;
            }
            '"' => {
                q = !q;
                cur.push(c);
            }
            ';' if !q => {
                let t = cur.trim();
                if !t.is_empty() {
                    let (k, v) = t
                        .split_once(':')
                        .map(|(k, v)| (k.trim(), v.trim()))
                        .unwrap_or((t, ""));
                    out.push((k.to_ascii_lowercase(), v.to_string()));
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    out
}

fn unquote(v: &str) -> &str {
    v.trim()
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(v.trim())
}

/// `"abc|0d 0a|def"` -> bytes; handles `\"`, `\;`, `\\` escapes.
fn content_bytes(v: &str) -> Option<Vec<u8>> {
    let mut out = vec![];
    let mut hex = false;
    let mut chars = v.chars().peekable();
    let mut hexbuf = String::new();
    while let Some(c) = chars.next() {
        if c == '|' {
            if hex {
                for h in hexbuf.split_whitespace() {
                    out.push(u8::from_str_radix(h, 16).ok()?);
                }
                hexbuf.clear();
            }
            hex = !hex;
            continue;
        }
        if hex {
            hexbuf.push(c);
        } else if c == '\\' {
            let n = chars.next()?;
            let mut b = [0u8; 4];
            out.extend_from_slice(n.encode_utf8(&mut b).as_bytes());
        } else {
            let mut b = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
        }
    }
    (!hex && !out.is_empty()).then_some(out)
}

const UNSUPPORTED: &[&str] = &[
    "pcre",
    "flowbits",
    "xbits",
    "byte_test",
    "byte_jump",
    "byte_extract",
    "byte_math",
    "isdataat",
    "base64_decode",
    "base64_data",
    "lua",
    "luajit",
    "ja3.hash",
    "ja3s.hash",
    "stream_size",
    "app-layer-event",
    "decode-event",
    "stream-event",
    "datasets",
    "dataset",
    "iprep",
    "urilen",
    "file.data",
    "file_data",
    "filemd5",
    "filesha256",
    "filemagic",
    "fileext",
    "asn1",
    "entropy",
    "bsize",
    "detection_filter",
    "tag",
];

pub fn parse_rule(line: &str, source: &str) -> Option<Rule> {
    let open = line.find('(')?;
    let header: Vec<&str> = line[..open].split_whitespace().collect();
    if header.len() != 7 || !matches!(header[0], "alert" | "drop" | "reject") {
        return None;
    }
    let proto = match header[1].to_ascii_lowercase().as_str() {
        "tcp" | "http" | "http1" | "http2" | "tls" | "smb" | "ftp" | "ftp-data" | "ssh"
        | "smtp" | "imap" | "pop3" | "tcp-pkt" | "tcp-stream" | "rdp" | "mqtt" | "modbus"
        | "dnp3" => Proto::Tcp,
        "udp" | "ntp" | "sip" | "tftp" | "dhcp" | "snmp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        "ip" | "dns" => Proto::Any,
        _ => return None,
    };
    let bidir = match header[4] {
        "->" => false,
        "<>" => true,
        _ => return None,
    };
    let body = line[open + 1..].trim_end().strip_suffix(')')?;
    let mut r = Rule {
        sid: 0,
        rev: 1,
        msg: String::new(),
        classtype: None,
        priority: 3,
        proto,
        src: parse_addr(header[2])?,
        sport: parse_ports(header[3])?,
        dst: parse_addr(header[5])?,
        dport: parse_ports(header[6])?,
        bidir,
        contents: vec![],
        dsize: None,
        source: source.to_string(),
    };
    for (k, v) in split_options(body) {
        let num = || v.trim().parse::<isize>().ok();
        match k.as_str() {
            "msg" => r.msg = unquote(&v).replace("\\\"", "\"").replace("\\;", ";"),
            "sid" => r.sid = v.trim().parse().ok()?,
            "rev" => r.rev = v.trim().parse().unwrap_or(1),
            "classtype" => r.classtype = Some(v.trim().to_string()),
            "priority" => r.priority = v.trim().parse().unwrap_or(3),
            "content" => {
                let (neg, val) = match v.trim().strip_prefix('!') {
                    Some(x) => (true, x),
                    None => (false, v.trim()),
                };
                let bytes = content_bytes(unquote(val))?;
                r.contents.push(Content {
                    bytes,
                    nocase: false,
                    negated: neg,
                    offset: None,
                    depth: None,
                    distance: None,
                    within: None,
                });
            }
            "nocase" => r.contents.last_mut()?.nocase = true,
            "offset" => r.contents.last_mut()?.offset = Some(num()?.max(0) as usize),
            "depth" => r.contents.last_mut()?.depth = Some(num()?.max(0) as usize),
            "distance" => r.contents.last_mut()?.distance = Some(num()?),
            "within" => r.contents.last_mut()?.within = Some(num()?.max(0) as usize),
            "dsize" => {
                let t = v.trim();
                r.dsize = if let Some(x) = t.strip_prefix('<') {
                    Some((b'<', x.trim().parse().ok()?, 0))
                } else if let Some(x) = t.strip_prefix('>') {
                    Some((b'>', x.trim().parse().ok()?, 0))
                } else if let Some((a, b)) = t.split_once("<>") {
                    Some((b'r', a.trim().parse().ok()?, b.trim().parse().ok()?))
                } else {
                    Some((b'=', t.parse().ok()?, 0))
                };
            }
            k if UNSUPPORTED.contains(&k) => return None,
            _ => {} // reference, metadata, flow, sticky buffers, fast_pattern, threshold...
        }
    }
    if r.sid == 0
        || r.msg.is_empty()
        || !r.contents.iter().any(|c| !c.negated && c.bytes.len() >= 3)
    {
        return None;
    }
    Some(r)
}

/// MITRE ATT&CK technique for a Suricata classtype.
pub fn classtype_attack(c: Option<&str>) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match c? {
        "trojan-activity" | "command-and-control" | "domain-c2" => {
            ("T1071", "Application Layer Protocol", "Command and Control")
        }
        "attempted-admin"
        | "attempted-user"
        | "web-application-attack"
        | "successful-admin"
        | "successful-user"
        | "shellcode-detect" => (
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
        ),
        "attempted-recon"
        | "network-scan"
        | "successful-recon-limited"
        | "successful-recon-largescale" => ("T1046", "Network Service Discovery", "Discovery"),
        "attempted-dos" | "successful-dos" | "denial-of-service" => {
            ("T1498", "Network Denial of Service", "Impact")
        }
        "coin-mining" => ("T1496", "Resource Hijacking", "Impact"),
        "credential-theft" | "default-login-attempt" | "suspicious-login" | "unsuccessful-user" => {
            ("T1110", "Brute Force", "Credential Access")
        }
        "exploit-kit" => ("T1189", "Drive-by Compromise", "Initial Access"),
        _ => return None,
    })
}

/// Curated rules for common IoT / home-network threats. sid 9_000_000+.
pub const BUILTIN: &str = r#"
alert tcp any any -> $HOME_NET any (msg:"NIV Log4Shell JNDI lookup (CVE-2021-44228)"; content:"${jndi:"; nocase; classtype:attempted-admin; sid:9000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Log4Shell obfuscated JNDI lookup"; content:"${${"; content:"jndi"; nocase; distance:0; within:40; classtype:attempted-admin; sid:9000002; rev:1;)
alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"NIV Shellshock attempt (CVE-2014-6271)"; content:"() {"; content:"|3b|"; distance:0; within:20; classtype:attempted-admin; sid:9000003; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Hikvision command injection (CVE-2021-36260)"; content:"PUT /SDK/webLanguage"; nocase; classtype:attempted-admin; sid:9000004; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Huawei HG532 exploit (CVE-2017-17215, Mirai)"; content:"/ctrlt/DeviceUpgrade_1"; nocase; classtype:attempted-admin; sid:9000005; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Realtek SDK UPnP exploit (CVE-2014-8361)"; content:"/picsdesc.xml"; nocase; content:"NewInternalClient"; nocase; classtype:attempted-admin; sid:9000006; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Netgear setup.cgi command execution"; content:"setup.cgi?next_file=netgear.cfg"; nocase; classtype:attempted-admin; sid:9000007; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV D-Link HNAP command injection"; content:"/HNAP1/"; nocase; content:"SOAPAction"; nocase; content:"`"; classtype:attempted-admin; sid:9000008; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV GPON router RCE (CVE-2018-10561)"; content:"/GponForm/diag_Form?images/"; nocase; classtype:attempted-admin; sid:9000009; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Shell download-and-execute in web request"; content:"wget http"; nocase; content:"chmod"; nocase; distance:0; within:120; classtype:attempted-admin; sid:9000010; rev:1;)
alert tcp any any -> any any (msg:"NIV BusyBox payload staging (Mirai/Gafgyt loader)"; content:"/bin/busybox"; nocase; content:"chmod 777"; nocase; classtype:trojan-activity; sid:9000011; rev:1;)
alert tcp any any -> any 23 (msg:"NIV Mirai default-credential Telnet login"; content:"xc3511"; classtype:default-login-attempt; sid:9000012; rev:1;)
alert tcp any any -> any [23,2323] (msg:"NIV Telnet login with factory credentials"; content:"vizxv"; classtype:default-login-attempt; sid:9000013; rev:1;)
alert tcp any any -> any 5555 (msg:"NIV Android ADB shell over network (ADB.Miner)"; content:"CNXN"; depth:4; classtype:attempted-admin; sid:9000014; rev:1;)
alert tcp $HOME_NET any -> any any (msg:"NIV Cryptocurrency mining (Stratum login)"; content:"\"method\""; content:"mining.subscribe"; distance:0; classtype:coin-mining; sid:9000015; rev:1;)
alert tcp $HOME_NET any -> any any (msg:"NIV XMRig miner login"; content:"\"method\":\"login\""; content:"\"agent\":\"XMRig"; nocase; classtype:coin-mining; sid:9000016; rev:1;)
alert tcp any any -> any 21 (msg:"NIV Cleartext FTP password"; content:"PASS "; depth:5; classtype:policy-violation; sid:9000017; rev:1;)
alert tcp any any -> any $HTTP_PORTS (msg:"NIV Cleartext HTTP Basic authentication"; content:"Authorization: Basic "; nocase; classtype:policy-violation; sid:9000018; rev:1;)
alert tcp any any -> any 445 (msg:"NIV SMBv1 negotiation (EternalBlue-era protocol)"; content:"|ff|SMB|72|"; offset:4; depth:5; classtype:policy-violation; sid:9000019; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Internet scanner User-Agent (zgrab/masscan/Nmap)"; content:"User-Agent: "; nocase; content:"zgrab"; nocase; distance:0; within:40; classtype:attempted-recon; sid:9000020; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Nmap Scripting Engine probe"; content:"Nmap Scripting Engine"; nocase; classtype:attempted-recon; sid:9000021; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV sqlmap SQL injection tool"; content:"sqlmap/"; nocase; classtype:web-application-attack; sid:9000022; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Spring4Shell exploit (CVE-2022-22965)"; content:"class.module.classLoader"; nocase; classtype:attempted-admin; sid:9000023; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Path traversal to /etc/passwd"; content:"../../"; content:"etc/passwd"; distance:0; within:60; classtype:web-application-attack; sid:9000024; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"NIV Reverse shell banner"; content:"sh: no job control in this shell"; classtype:trojan-activity; sid:9000025; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV TP-Link Archer command injection (CVE-2023-1389)"; content:"/cgi-bin/luci/;stok=/locale"; nocase; content:"country="; nocase; classtype:attempted-admin; sid:9000026; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"NIV Zyxel command injection (CVE-2022-30525)"; content:"/ztp/cgi-bin/handler"; nocase; classtype:attempted-admin; sid:9000027; rev:1;)
alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"NIV UPnP SSDP from the internet (reflection / exposure)"; content:"M-SEARCH"; depth:8; classtype:attempted-recon; sid:9000028; rev:1;)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> RuleSet {
        let mut s = RuleSet::default();
        s.add_text("test", text);
        s.build();
        s
    }

    fn pkt<'a>(dport: u16, payload: &'a [u8], dst_home: bool) -> Packet<'a> {
        Packet {
            proto: Proto::Tcp,
            src: "203.0.113.9".parse().unwrap(),
            dst: "192.168.1.20".parse().unwrap(),
            sport: 40000,
            dport,
            src_home: false,
            dst_home,
            payload,
        }
    }

    #[test]
    fn builtin_rules_parse_and_match() {
        let s = set(BUILTIN);
        assert_eq!(s.stats[0].2, 0, "every built-in rule parses");
        let hit = |dport, p: &[u8]| {
            s.matches(&pkt(dport, p, true))
                .iter()
                .map(|r| r.sid)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hit(8080, b"GET /?x=${jndi:ldap://e.vil/a} HTTP/1.1\r\n"),
            vec![9000001]
        );
        assert_eq!(hit(80, b"PUT /SDK/webLanguage HTTP/1.1\r\n"), vec![9000004]);
        assert_eq!(hit(23, b"root\r\nxc3511\r\n"), vec![9000012]);
        assert!(hit(80, b"GET /index.html HTTP/1.1\r\nHost: cam\r\n").is_empty());
        // HTTP_PORTS restriction: Basic auth on 443 is not plaintext.
        assert_eq!(
            hit(
                80,
                b"GET / HTTP/1.1\r\nauthorization: basic YWRtaW46YWRtaW4=\r\n"
            ),
            vec![9000018]
        );
        assert!(hit(443, b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW4=\r\n").is_empty());
        // $HOME_NET destination required
        assert!(s
            .matches(&pkt(80, b"PUT /SDK/webLanguage", false))
            .is_empty());
        // distance/within
        assert!(hit(80, b"() { :;}; /bin/id").contains(&9000003));
        assert!(hit(
            80,
            b"() { this is a very long function body with no semicolon nearby .... ;"
        )
        .is_empty());
    }

    #[test]
    fn suricata_syntax() {
        let s = set(concat!(
            r#"alert http $EXTERNAL_NET any -> $HOME_NET [80,8000:8100] (msg:"ET EXPLOIT x"; flow:established,to_server; http.uri; content:"/boaform/admin/formLogin"; nocase; fast_pattern; reference:url,x; classtype:attempted-admin; sid:2030000; rev:2; metadata:created_at 2020;)"#,
            "\n",
            r#"alert tcp any any -> any any (msg:"needs pcre"; content:"abc"; pcre:"/a.c/"; sid:1;)"#,
            "\n",
            r#"alert tcp any any -> any any (msg:"too short"; content:"a"; sid:2;)"#,
            "\n",
            r#"alert udp any any -> any 53 (msg:"hex"; content:"|07|example|03|com|00|"; sid:3;)"#,
        ));
        assert_eq!(s.stats[0], ("test".into(), 2, 2));
        assert_eq!(
            s.matches(&pkt(8050, b"POST /boaform/admin/formLogin", true))
                .len(),
            1
        );
        assert!(s
            .matches(&pkt(9000, b"POST /boaform/admin/formLogin", true))
            .is_empty());
        let mut p = pkt(
            53,
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01",
            false,
        );
        p.proto = Proto::Udp;
        assert_eq!(s.matches(&p).len(), 1);
    }
}

#[cfg(test)]
mod live {
    /// `cargo test real_et -- --ignored --nocapture` (downloads ET Open categories)
    #[test]
    #[ignore]
    fn real_et_rules() {
        let dir = std::env::temp_dir().join("niv-et-live");
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = super::RuleSet::default();
        s.add_text("built-in", super::BUILTIN);
        for c in [
            "emerging-exploit",
            "emerging-scan",
            "emerging-attack_response",
            "emerging-coinminer",
            "emerging-malware",
        ] {
            let p = dir.join(format!("{c}.rules"));
            crate::intel::download(
                &format!("https://rules.emergingthreats.net/open/suricata-7.0/rules/{c}.rules"),
                &p,
                1000,
            )
            .unwrap();
            s.add_text(c, &std::fs::read_to_string(&p).unwrap());
        }
        for (n, ok, skip) in &s.stats {
            println!("{n}: {ok} loaded, {skip} skipped");
        }
        let t = std::time::Instant::now();
        s.build();
        println!(
            "built prefilter for {} rules in {:?}",
            s.rules.len(),
            t.elapsed()
        );
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".repeat(8);
        let p = super::Packet {
            proto: super::Proto::Tcp,
            src: "192.168.1.5".parse().unwrap(),
            dst: "93.184.216.34".parse().unwrap(),
            sport: 50000,
            dport: 80,
            src_home: true,
            dst_home: false,
            payload: &payload,
        };
        let t = std::time::Instant::now();
        let mut hits = 0;
        for _ in 0..10_000 {
            hits += s.matches(&p).len();
        }
        println!("10k packets in {:?} ({} hits)", t.elapsed(), hits);
    }
}
