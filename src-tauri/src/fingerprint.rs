//! Passive client fingerprints: TLS ClientHello (JA3, JA4) and DHCP
//! parameter-request lists. A device's TLS stack and DHCP client rarely
//! change, so a different fingerprint on the same MAC hints at spoofing or
//! new (possibly malicious) software.

use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// What a TLS ClientHello reveals about the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientHello {
    pub sni: Option<String>,
    pub ja3: String,
    pub ja3_hash: String,
    pub ja4: String,
    /// Highest protocol version offered, e.g. 0x0304 for TLS 1.3.
    pub max_version: u16,
}

impl ClientHello {
    /// Offers nothing newer than TLS 1.1.
    pub fn legacy(&self) -> bool {
        self.max_version < 0x0303
    }
}

fn grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn u16s(d: &[u8]) -> Vec<u16> {
    d.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

fn hex12(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    h.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Parse a TLS record carrying a ClientHello (first TCP payload of a connection).
pub fn client_hello(d: &[u8]) -> Option<ClientHello> {
    if d.len() < 43 || d[0] != 0x16 || d[1] != 0x03 {
        return None;
    }
    let hs = &d[5..];
    if hs.first() != Some(&0x01) {
        return None;
    }
    let client_version = u16::from_be_bytes([*hs.get(4)?, *hs.get(5)?]);
    let mut off = 4 + 2 + 32;
    let sid_len = *hs.get(off)? as usize;
    off += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*hs.get(off)?, *hs.get(off + 1)?]) as usize;
    let ciphers: Vec<u16> = u16s(hs.get(off + 2..off + 2 + cs_len)?)
        .into_iter()
        .filter(|c| !grease(*c))
        .collect();
    off += 2 + cs_len;
    let comp_len = *hs.get(off)? as usize;
    off += 1 + comp_len;

    let (mut exts, mut groups, mut formats, mut sigs) = (vec![], vec![], vec![], vec![]);
    let (mut sni, mut alpn, mut versions) = (None, None::<String>, vec![]);
    if let (Some(a), Some(b)) = (hs.get(off), hs.get(off + 1)) {
        let total = u16::from_be_bytes([*a, *b]) as usize;
        off += 2;
        let end = (off + total).min(hs.len());
        while off + 4 <= end {
            let ty = u16::from_be_bytes([hs[off], hs[off + 1]]);
            let len = u16::from_be_bytes([hs[off + 2], hs[off + 3]]) as usize;
            let body = hs
                .get(off + 4..(off + 4 + len).min(hs.len()))
                .unwrap_or(&[]);
            off += 4 + len;
            if grease(ty) {
                continue;
            }
            exts.push(ty);
            match ty {
                0 if body.len() >= 5 => {
                    let n = u16::from_be_bytes([body[3], body[4]]) as usize;
                    sni = body
                        .get(5..5 + n)
                        .map(|s| String::from_utf8_lossy(s).to_ascii_lowercase());
                }
                10 if body.len() >= 2 => {
                    groups = u16s(&body[2..])
                        .into_iter()
                        .filter(|g| !grease(*g))
                        .collect()
                }
                11 if !body.is_empty() => formats = body[1..].iter().map(|b| *b as u16).collect(),
                13 if body.len() >= 2 => sigs = u16s(&body[2..]),
                16 if body.len() >= 3 => {
                    let n = body[2] as usize;
                    alpn = body
                        .get(3..3 + n)
                        .map(|s| String::from_utf8_lossy(s).into_owned());
                }
                43 if !body.is_empty() => {
                    versions = u16s(&body[1..])
                        .into_iter()
                        .filter(|v| !grease(*v))
                        .collect()
                }
                _ => {}
            }
        }
    }

    let join = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join("-");
    let ja3 = format!(
        "{client_version},{},{},{},{}",
        join(&ciphers),
        join(&exts),
        join(&groups),
        join(&formats)
    );
    let ja3_hash = Md5::digest(ja3.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let max_version = versions
        .iter()
        .copied()
        .max()
        .unwrap_or(client_version)
        .max(client_version);
    let ver = match max_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let alpn_code = alpn
        .as_deref()
        .filter(|a| !a.is_empty())
        .map(|a| {
            let (f, l) = (
                a.chars().next().unwrap_or('0'),
                a.chars().last().unwrap_or('0'),
            );
            if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
                format!("{f}{l}")
            } else {
                "99".into()
            }
        })
        .unwrap_or_else(|| "00".into());
    let ja4_a = format!(
        "t{ver}{}{:02}{:02}{alpn_code}",
        if sni.is_some() { 'd' } else { 'i' },
        ciphers.len().min(99),
        exts.len().min(99)
    );
    let hexlist = |v: &[u16]| {
        v.iter()
            .map(|x| format!("{x:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut sc = ciphers.clone();
    sc.sort_unstable();
    let ja4_b = if sc.is_empty() {
        "000000000000".into()
    } else {
        hex12(&hexlist(&sc))
    };
    let mut se: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|e| *e != 0 && *e != 16)
        .collect();
    se.sort_unstable();
    let c_in = if sigs.is_empty() {
        hexlist(&se)
    } else {
        format!("{}_{}", hexlist(&se), hexlist(&sigs))
    };
    let ja4_c = if se.is_empty() {
        "000000000000".into()
    } else {
        hex12(&c_in)
    };

    Some(ClientHello {
        sni,
        ja3,
        ja3_hash,
        ja4: format!("{ja4_a}_{ja4_b}_{ja4_c}"),
        max_version,
    })
}

/// Operating-system family from a DHCP parameter request list (option 55,
/// e.g. "1,121,3,6,15,108,114,119,252") and vendor class.
pub fn dhcp_os(params: &str, vendor_class: Option<&str>) -> Option<&'static str> {
    let vc = vendor_class.unwrap_or("").to_ascii_lowercase();
    if vc.starts_with("msft") {
        return Some("Windows");
    }
    if vc.contains("android") {
        return Some("Android");
    }
    if vc.contains("udhcp") {
        return Some("Embedded Linux");
    }
    let opts: Vec<u16> = params
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    let has = |o: u16| opts.contains(&o);
    if opts.is_empty() {
        return None;
    }
    if has(249) && has(252) && has(43) {
        return Some("Windows");
    }
    if has(108) && has(114) && has(121) && has(95) {
        return Some("Apple (iOS / macOS)");
    }
    if has(108) && has(114) && has(26) {
        return Some("Android");
    }
    if opts == [1, 3, 6, 12, 15, 28, 42] || (opts.len() <= 8 && has(12) && has(42) && !has(119)) {
        return Some("Embedded Linux");
    }
    if has(119) && has(121) && has(28) {
        return Some("Linux");
    }
    None
}

#[cfg(test)]
pub mod tests_support {
    /// A ClientHello with GREASE, SNI, groups, point formats, sig algs, ALPN and supported_versions.
    pub fn hello(sni: &str, tls13: bool) -> Vec<u8> {
        let mut ext = vec![];
        let mut push = |ty: u16, body: &[u8]| {
            ext.extend_from_slice(&ty.to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(body);
        };
        push(0x0a0a, &[]); // GREASE
        let mut s = vec![];
        s.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
        s.push(0);
        s.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        s.extend_from_slice(sni.as_bytes());
        push(0, &s);
        push(10, &[0, 6, 0x1a, 0x1a, 0, 29, 0, 23]);
        push(11, &[1, 0]);
        push(13, &[0, 4, 4, 3, 8, 4]);
        push(16, &[0, 3, 2, b'h', b'2']);
        if tls13 {
            push(43, &[4, 3, 4, 3, 3]);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 6, 0x2a, 0x2a, 0x13, 0x01, 0xc0, 0x2f]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::hello;
    use super::*;

    #[test]
    fn ja3_ja4() {
        let h = client_hello(&hello("api.example.com", true)).unwrap();
        assert_eq!(h.sni.as_deref(), Some("api.example.com"));
        // GREASE removed everywhere.
        assert_eq!(h.ja3, "771,4865-49199,0-10-11-13-16-43,29-23,0");
        assert_eq!(h.ja3_hash.len(), 32);
        assert!(h.ja4.starts_with("t13d0206h2_"), "{}", h.ja4);
        assert_eq!(h.ja4.len(), "t13d0206h2_".len() + 12 + 1 + 12);
        assert!(!h.legacy());
        let old = client_hello(&hello("x.example", false)).unwrap();
        assert!(old.ja4.starts_with("t12d0205h2_"));
        assert_ne!(old.ja3_hash, h.ja3_hash);
    }

    #[test]
    fn dhcp_os_families() {
        assert_eq!(
            dhcp_os("1,121,3,6,15,108,114,119,252,95,44,46", None),
            Some("Apple (iOS / macOS)")
        );
        assert_eq!(
            dhcp_os("1,3,6,15,31,33,43,44,46,47,119,121,249,252", None),
            Some("Windows")
        );
        assert_eq!(
            dhcp_os("1,3,6,15,26,28,51,58,59,43,114,108", None),
            Some("Android")
        );
        assert_eq!(dhcp_os("1,3,6,12,15,28,42", None), Some("Embedded Linux"));
        assert_eq!(dhcp_os("", Some("udhcp 1.31.1")), Some("Embedded Linux"));
    }
}
