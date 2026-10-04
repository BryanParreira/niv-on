//! Packet evidence: the last couple of minutes of raw frames are kept in a
//! ring buffer; when an alert fires, the frames involving that device are
//! written to a `.pcap` that opens in Wireshark.

use crate::model::{Mac, PacketInfo};
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const KEEP_SECS: i64 = 120;
const MAX_BYTES: usize = 64 * 1024 * 1024;

struct Frame {
    ts: DateTime<Utc>,
    src: Option<Mac>,
    dst: Option<Mac>,
    wire_len: u32,
    data: Vec<u8>,
}

struct Ring {
    linktype: Option<i32>,
    frames: VecDeque<Frame>,
    bytes: usize,
    dir: PathBuf,
}

static RING: OnceLock<Mutex<Ring>> = OnceLock::new();

fn ring() -> &'static Mutex<Ring> {
    RING.get_or_init(|| {
        Mutex::new(Ring {
            linktype: None,
            frames: VecDeque::new(),
            bytes: 0,
            dir: std::env::temp_dir(),
        })
    })
}

pub fn init(data_dir: &Path) {
    ring().lock().dir = data_dir.join("evidence");
}

/// New capture: frames from the previous source are discarded. `None` (the
/// simulator) disables evidence.
pub fn begin(linktype: Option<i32>) {
    let mut r = ring().lock();
    r.linktype = linktype;
    r.frames.clear();
    r.bytes = 0;
}

pub fn push(p: &mut PacketInfo) {
    let Some(data) = p.raw.take() else { return };
    let mut r = ring().lock();
    if r.linktype.is_none() {
        return;
    }
    r.bytes += data.len();
    r.frames.push_back(Frame {
        ts: p.ts,
        src: p.src,
        dst: p.dst,
        wire_len: p.len,
        data,
    });
    let cutoff = p.ts - Duration::seconds(KEEP_SECS);
    while r.frames.front().is_some_and(|f| f.ts < cutoff) || r.bytes > MAX_BYTES {
        if let Some(f) = r.frames.pop_front() {
            r.bytes -= f.data.len();
        }
    }
}

pub fn available() -> bool {
    ring().lock().linktype.is_some()
}

/// Write the buffered frames of `mac` (or all frames) to a pcap file.
pub fn save(name: &str, mac: Option<Mac>) -> Result<PathBuf, String> {
    let r = ring().lock();
    let lt = r
        .linktype
        .ok_or("No packet evidence for this source (simulator, or capture not running).")?;
    let frames: Vec<&Frame> = r
        .frames
        .iter()
        .filter(|f| mac.is_none_or(|m| f.src == Some(m) || f.dst == Some(m)))
        .collect();
    if frames.is_empty() {
        return Err("No buffered packets for this device in the last two minutes.".into());
    }
    std::fs::create_dir_all(&r.dir).map_err(|e| e.to_string())?;
    let path = r.dir.join(format!("{name}.pcap"));
    let mut out = Vec::with_capacity(24 + frames.iter().map(|f| 16 + f.data.len()).sum::<usize>());
    // Global header: magic, v2.4, tz 0, sigfigs 0, snaplen, linktype (little-endian).
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&(lt as u32).to_le_bytes());
    for f in frames {
        out.extend_from_slice(&(f.ts.timestamp() as u32).to_le_bytes());
        out.extend_from_slice(&f.ts.timestamp_subsec_micros().to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.wire_len.max(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.data);
    }
    let mut file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(&out).map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FrameKind;

    #[test]
    fn writes_a_pcap_that_libpcap_reads_back() {
        let dir = std::env::temp_dir().join(format!("niv-ev-{}", std::process::id()));
        init(&dir);
        begin(Some(crate::parser::DLT_EN10MB));
        let a: Mac = "02:00:00:00:00:0a".parse().unwrap();
        let b: Mac = "02:00:00:00:00:0b".parse().unwrap();
        for (i, (s, d)) in [(a, b), (b, a), (b, Mac::BROADCAST)]
            .into_iter()
            .enumerate()
        {
            let mut frame = d.0.to_vec();
            frame.extend_from_slice(&s.0);
            frame.extend_from_slice(&[0x08, 0x06]);
            frame.extend_from_slice(&[i as u8; 28]);
            let mut p = PacketInfo::new(Utc::now(), FrameKind::Ethernet, "arp", frame.len() as u32);
            p.src = Some(s);
            p.dst = Some(d);
            p.raw = Some(frame);
            push(&mut p);
        }
        let path = save("test", Some(a)).unwrap();
        let mut cap = pcap::Capture::from_file(&path).unwrap();
        assert_eq!(cap.get_datalink().0, crate::parser::DLT_EN10MB);
        let mut n = 0;
        while cap.next_packet().is_ok() {
            n += 1;
        }
        assert_eq!(n, 2, "only frames involving the device");
        let _ = std::fs::remove_dir_all(dir);
    }
}
