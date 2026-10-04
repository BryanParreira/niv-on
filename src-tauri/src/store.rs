//! Long-term event store (SQLite): the connection log and DNS log, kept per
//! network for the configured retention period so searches and device
//! timelines can look back weeks, not just at what is in memory.

use crate::engine::{DnsRecord, Flow};
use crate::model::Mac;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub struct Store {
    db: Mutex<Connection>,
    path: PathBuf,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StoreStats {
    pub connections: u64,
    pub dns: u64,
    pub bytes: u64,
    pub oldest: Option<DateTime<Utc>>,
}

fn ms(t: DateTime<Utc>) -> i64 {
    t.timestamp_millis()
}

fn from_ms(v: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(v).unwrap_or_default()
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, String> {
        let db = Connection::open(path).map_err(|e| e.to_string())?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS conn (
                net TEXT NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL, mac TEXT NOT NULL,
                local_ip TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER, proto TEXT,
                service INTEGER, domain TEXT, bytes_out INTEGER, bytes_in INTEGER, packets INTEGER,
                external INTEGER, outbound INTEGER);
             CREATE INDEX IF NOT EXISTS conn_net_start ON conn(net, start);
             CREATE INDEX IF NOT EXISTS conn_net_mac ON conn(net, mac, start);
             CREATE TABLE IF NOT EXISTS dns (
                net TEXT NOT NULL, ts INTEGER NOT NULL, mac TEXT NOT NULL, query TEXT, answers TEXT,
                rcode INTEGER, resolver TEXT);
             CREATE INDEX IF NOT EXISTS dns_net_ts ON dns(net, ts);
             CREATE INDEX IF NOT EXISTS dns_net_mac ON dns(net, mac, ts);",
        )
        .map_err(|e| e.to_string())?;
        Ok(Store {
            db: Mutex::new(db),
            path: path.to_path_buf(),
        })
    }

    pub fn insert(&self, net: &str, flows: &[Flow], dns: &[DnsRecord]) -> Result<(), String> {
        if flows.is_empty() && dns.is_empty() {
            return Ok(());
        }
        let mut db = self.db.lock();
        let tx = db.transaction().map_err(|e| e.to_string())?;
        {
            let mut c = tx
                .prepare_cached(
                    "INSERT INTO conn VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                )
                .map_err(|e| e.to_string())?;
            for f in flows {
                c.execute(params![
                    net,
                    ms(f.start),
                    ms(f.end),
                    f.mac.to_string(),
                    f.local_ip.to_string(),
                    f.local_port,
                    f.remote_ip.to_string(),
                    f.remote_port,
                    f.proto,
                    f.service,
                    f.domain,
                    f.bytes_out as i64,
                    f.bytes_in as i64,
                    f.packets as i64,
                    f.external,
                    f.outbound
                ])
                .map_err(|e| e.to_string())?;
            }
            let mut d = tx
                .prepare_cached("INSERT INTO dns VALUES (?1,?2,?3,?4,?5,?6,?7)")
                .map_err(|e| e.to_string())?;
            for r in dns {
                d.execute(params![
                    net,
                    ms(r.ts),
                    r.mac.to_string(),
                    r.query,
                    r.answers.join(","),
                    r.rcode,
                    r.resolver.to_string()
                ])
                .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn connections(
        &self,
        net: &str,
        mac: Option<Mac>,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Vec<Flow> {
        let db = self.db.lock();
        let sql = "SELECT start,end,mac,local_ip,local_port,remote_ip,remote_port,proto,service,domain,bytes_out,bytes_in,packets,external,outbound
                   FROM conn WHERE net=?1 AND start>=?2 AND (?3 IS NULL OR mac=?3) ORDER BY start DESC LIMIT ?4";
        let Ok(mut st) = db.prepare_cached(sql) else {
            return vec![];
        };
        let rows = st.query_map(
            params![net, ms(since), mac.map(|m| m.to_string()), limit as i64],
            |r| {
                Ok(Flow {
                    start: from_ms(r.get(0)?),
                    end: from_ms(r.get(1)?),
                    mac: r.get::<_, String>(2)?.parse().unwrap_or_default(),
                    local_ip: r
                        .get::<_, String>(3)?
                        .parse()
                        .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
                    local_port: r.get(4)?,
                    remote_ip: r
                        .get::<_, String>(5)?
                        .parse()
                        .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
                    remote_port: r.get(6)?,
                    proto: r.get(7)?,
                    service: r.get(8)?,
                    domain: r.get(9)?,
                    bytes_out: r.get::<_, i64>(10)? as u64,
                    bytes_in: r.get::<_, i64>(11)? as u64,
                    packets: r.get::<_, i64>(12)? as u64,
                    external: r.get(13)?,
                    outbound: r.get(14)?,
                })
            },
        );
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    pub fn dns(
        &self,
        net: &str,
        mac: Option<Mac>,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Vec<DnsRecord> {
        let db = self.db.lock();
        let sql = "SELECT ts,mac,query,answers,rcode,resolver FROM dns
                   WHERE net=?1 AND ts>=?2 AND (?3 IS NULL OR mac=?3) ORDER BY ts DESC LIMIT ?4";
        let Ok(mut st) = db.prepare_cached(sql) else {
            return vec![];
        };
        let rows = st.query_map(
            params![net, ms(since), mac.map(|m| m.to_string()), limit as i64],
            |r| {
                Ok(DnsRecord {
                    ts: from_ms(r.get(0)?),
                    mac: r.get::<_, String>(1)?.parse().unwrap_or_default(),
                    query: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    answers: r
                        .get::<_, Option<String>>(3)?
                        .unwrap_or_default()
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                    rcode: r.get(4)?,
                    resolver: r
                        .get::<_, String>(5)?
                        .parse()
                        .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
                })
            },
        );
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    /// Delete records older than `days` (0 keeps everything). Returns rows removed.
    pub fn purge(&self, days: u32) -> usize {
        if days == 0 {
            return 0;
        }
        let cutoff = ms(Utc::now() - Duration::days(days as i64));
        let db = self.db.lock();
        let a = db
            .execute("DELETE FROM conn WHERE end < ?1", [cutoff])
            .unwrap_or(0);
        let b = db
            .execute("DELETE FROM dns WHERE ts < ?1", [cutoff])
            .unwrap_or(0);
        if a + b > 10_000 {
            let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
        }
        a + b
    }

    pub fn delete_network(&self, net: &str) {
        let db = self.db.lock();
        let _ = db.execute("DELETE FROM conn WHERE net=?1", [net]);
        let _ = db.execute("DELETE FROM dns WHERE net=?1", [net]);
    }

    pub fn stats(&self, net: &str) -> StoreStats {
        let db = self.db.lock();
        let count = |sql: &str| {
            db.query_row(sql, [net], |r| r.get::<_, i64>(0))
                .unwrap_or(0) as u64
        };
        let oldest: Option<i64> = db
            .query_row("SELECT MIN(start) FROM conn WHERE net=?1", [net], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten()
            .flatten();
        let bytes = ["", "-wal"]
            .iter()
            .filter_map(|s| std::fs::metadata(format!("{}{s}", self.path.display())).ok())
            .map(|m| m.len())
            .sum();
        StoreStats {
            connections: count("SELECT COUNT(*) FROM conn WHERE net=?1"),
            dns: count("SELECT COUNT(*) FROM dns WHERE net=?1"),
            bytes,
            oldest: oldest.map(from_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_retention() {
        let dir = std::env::temp_dir().join(format!("niv-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("t.db")).unwrap();
        let mac: Mac = "44:19:b6:00:00:01".parse().unwrap();
        let now = Utc::now();
        let f = |start: DateTime<Utc>| Flow {
            start,
            end: start,
            mac,
            local_ip: "192.168.1.5".parse().unwrap(),
            local_port: Some(50000),
            remote_ip: "52.1.1.1".parse().unwrap(),
            remote_port: Some(443),
            proto: "tcp".into(),
            service: Some(443),
            domain: Some("api.example.com".into()),
            bytes_out: 100,
            bytes_in: 2000,
            packets: 5,
            external: true,
            outbound: true,
        };
        let dns = DnsRecord {
            ts: now,
            mac,
            query: "x.example".into(),
            answers: vec!["1.2.3.4".into()],
            rcode: 0,
            resolver: "192.168.1.1".parse().unwrap(),
        };
        s.insert("net:a", &[f(now), f(now - Duration::days(40))], &[dns])
            .unwrap();
        s.insert("net:b", &[f(now)], &[]).unwrap();
        assert_eq!(
            s.connections("net:a", Some(mac), now - Duration::days(60), 100)
                .len(),
            2
        );
        assert_eq!(
            s.connections("net:a", None, now - Duration::days(1), 100)[0]
                .domain
                .as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            s.dns("net:a", None, now - Duration::hours(1), 10)[0].answers,
            vec!["1.2.3.4".to_string()]
        );
        assert_eq!(s.purge(30), 1);
        assert_eq!(s.stats("net:a").connections, 1);
        s.delete_network("net:a");
        assert_eq!(s.stats("net:a").dns, 0);
        assert_eq!(s.stats("net:b").connections, 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
