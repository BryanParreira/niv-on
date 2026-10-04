// A small subset of Splunk's Search Processing Language over Niv.ON's data.
//
//   index=alerts severity>=high rule=risky-port | stats count by device_label
//   index=devices class="Smart Camera" risk>0 | sort -risk | table label ip vendor risk
//   index=feed protocol=DNS | top 10 info
//
// Search terms are ANDed: field=value (wildcards *), field!=value, field>N,
// >=, <, <=, NOT term, a OR b (binds tighter than AND, as in Splunk), and
// bare words that match any field. Commands: search/where, stats, timechart,
// top, rare, sort, head, tail, table/fields, dedup, rename.

import type { Alert, DeviceSummary, DnsRow, FeedItem, Flow, Lookup } from "./api";

export type Row = Record<string, unknown>;
export type Index = "alerts" | "devices" | "feed" | "conn" | "dns";
export const INDEXES: Index[] = ["alerts", "devices", "feed", "conn", "dns"];

export interface Result {
  index: Index;
  rows: Row[];
  /** Columns to show, in order. */
  columns: string[];
  /** Rows matched by the search terms, before transforming commands. */
  events: Row[];
  /** A transforming command (stats/top) ran: rows are aggregates. */
  transformed: boolean;
  /** Rows are time buckets from `timechart` (first column is _time). */
  timechart: boolean;
}

const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function alertRow(a: Alert): Row {
  return {
    _time: a.ts,
    severity: a.severity,
    rule: a.rule,
    title: a.title,
    message: a.message,
    device: a.device,
    device_label: a.deviceLabel,
    remote: a.remote,
    port: a.port,
    value: a.value,
    status: a.status,
    open: !a.acknowledged,
    owner: a.owner,
    urgency: a.urgency ?? a.severity,
    mitre: a.mitreId,
    mitre_name: a.mitreName,
    tactic: a.tactic,
    id: a.id,
  };
}

export function deviceRow(d: DeviceSummary): Row {
  return {
    _time: d.lastSeen,
    label: d.label,
    mac: d.mac,
    ip: d.ips.find((i) => i.includes(".")) ?? d.ips[0] ?? null,
    ips: d.ips,
    vendor: d.vendor,
    class: d.class,
    tag: d.tag,
    hostname: d.hostname,
    ssid: d.ssid,
    iot: d.isIot,
    risk: d.risk,
    priority: d.priority,
    alerts: d.openAlerts,
    hosts: d.destinations,
    tx: d.txBytes,
    rx: d.rxBytes,
    bytes: d.txBytes + d.rxBytes,
    rssi: d.rssi,
    channel: d.channel,
    gateway: d.isGateway,
    ap: d.isAp,
    self: d.isSelf,
    randomized: d.randomized,
    learning: d.learning,
    first_seen: d.firstSeen,
    last_seen: d.lastSeen,
  };
}

export function connRow(f: Flow): Row {
  return {
    _time: f.start,
    end: f.end,
    duration: Math.round((Date.parse(f.end) - Date.parse(f.start)) / 1000),
    mac: f.mac,
    device_label: f.label,
    device: f.mac,
    local_ip: f.localIp,
    local_port: f.localPort,
    remote_ip: f.remoteIp,
    remote_port: f.remotePort,
    proto: f.proto,
    service: f.service,
    domain: f.domain,
    bytes_out: f.bytesOut,
    bytes_in: f.bytesIn,
    bytes: f.bytesOut + f.bytesIn,
    packets: f.packets,
    external: f.external,
    direction: f.outbound ? "outbound" : "inbound",
    state: f.open ? "open" : "closed",
  };
}

const RCODES: Record<number, string> = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" };

export function dnsRow(r: DnsRow): Row {
  return {
    _time: r.ts,
    mac: r.mac,
    device: r.mac,
    device_label: r.label,
    query: r.query,
    answers: r.answers,
    rcode: RCODES[r.rcode] ?? String(r.rcode),
    resolver: r.resolver,
  };
}

export function feedRow(f: FeedItem, labels: Map<string, string>): Row {
  return {
    _time: f.ts,
    protocol: f.protocol,
    kind: f.kind,
    src: f.src,
    dst: f.dst,
    src_label: f.src ? labels.get(f.src) ?? null : null,
    dst_label: f.dst ? labels.get(f.dst) ?? null : null,
    info: f.info,
    len: f.len,
    rssi: f.rssi,
    channel: f.channel,
  };
}

// ---------------------------------------------------------------------------
// Tokenizing
// ---------------------------------------------------------------------------

/** Split on `sep` outside double quotes. */
function splitOutside(s: string, sep: (c: string) => boolean): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (const c of s) {
    if (c === '"') q = !q;
    if (!q && sep(c)) {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

const words = (s: string) => splitOutside(s.trim(), (c) => /\s/.test(c)).filter(Boolean);
const unquote = (s: string) => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);
const csv = (s: string) => splitOutside(s, (c) => c === ",").map((x) => x.trim()).filter(Boolean);

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

type Op = "=" | "!=" | ">" | ">=" | "<" | "<=";
interface Term {
  field?: string;
  op?: Op;
  value: string;
  not: boolean;
}

const TERM = /^([A-Za-z_][\w.]*)(!=|>=|<=|=|>|<)(.*)$/;

/** Conjunction of disjunctions: every clause must have one matching term. */
type Clauses = Term[][];

function parseTerms(ws: string[]): Clauses {
  const clauses: Clauses = [];
  let not = false;
  let or = false;
  for (const w of ws) {
    if (w === "AND") continue;
    if (w === "NOT") {
      not = !not;
      continue;
    }
    if (w === "OR") {
      if (!clauses.length) throw new Error("OR needs a term on its left, e.g. severity=high OR severity=critical");
      or = true;
      continue;
    }
    const m = TERM.exec(w);
    const t: Term = m ? { field: m[1].toLowerCase(), op: m[2] as Op, value: unquote(m[3]), not } : { value: unquote(w), not };
    if (or) clauses[clauses.length - 1].push(t);
    else clauses.push([t]);
    not = false;
    or = false;
  }
  if (or) throw new Error("OR needs a term on its right");
  return clauses;
}

const matchesAll = (row: Row, clauses: Clauses) => clauses.every((c) => c.some((t) => matches(row, t)));

const wildcard = (pattern: string) =>
  new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");

function str(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.join(" ");
  return String(v);
}

function cmp(field: string, rowVal: unknown, op: Op, value: string): boolean {
  const vals = Array.isArray(rowVal) ? rowVal : [rowVal];
  const test = (v: unknown): boolean => {
    if (op === "=" || op === "!=") {
      const hit = value === "*" ? v != null && v !== "" : wildcard(value).test(str(v));
      return op === "=" ? hit : !hit;
    }
    let a: number, b: number;
    if (field === "severity") {
      a = SEV_RANK[str(v).toLowerCase()] ?? NaN;
      b = SEV_RANK[value.toLowerCase()] ?? NaN;
    } else if (field === "_time" || field.endsWith("_seen")) {
      a = Date.parse(str(v));
      b = Date.parse(value);
      if (isNaN(b)) b = relativeTime(value);
    } else {
      a = Number(v);
      b = Number(value);
    }
    if (v == null || isNaN(a) || isNaN(b)) return false;
    return op === ">" ? a > b : op === ">=" ? a >= b : op === "<" ? a < b : a <= b;
  };
  return op === "!=" ? vals.every(test) : vals.some(test);
}

/** "-15m", "-2h", "-1d" relative to now. */
function relativeTime(v: string): number {
  const m = /^-(\d+)([smhd])$/.exec(v.trim());
  if (!m) return NaN;
  const mult = { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2] as "s" | "m" | "h" | "d"];
  return Date.now() - Number(m[1]) * mult;
}

function matches(row: Row, t: Term): boolean {
  let hit: boolean;
  if (t.field) {
    hit = cmp(t.field, row[t.field], t.op!, t.value);
  } else {
    const re = t.value.includes("*") ? wildcard(`*${t.value}*`) : null;
    const needle = t.value.toLowerCase();
    hit = Object.values(row).some((v) => (re ? re.test(str(v)) : str(v).toLowerCase().includes(needle)));
  }
  return t.not ? !hit : hit;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

interface Agg {
  fn: "count" | "dc" | "sum" | "avg" | "min" | "max" | "values";
  field?: string;
  as: string;
}

function parseAggs(spec: string): Agg[] {
  return csv(spec.replace(/\s+as\s+/gi, " as ").replace(/\)\s+(?!as\b)/gi, "), ")).map((part) => {
    const [expr, alias] = part.split(/\s+as\s+/i);
    const m = /^(count|dc|distinct_count|sum|avg|mean|min|max|values)(?:\(([\w.]*)\))?$/i.exec(expr.trim());
    if (!m) throw new Error(`stats: unknown function “${expr}” — use count, dc(f), sum(f), avg(f), min(f), max(f), values(f)`);
    let fn = m[1].toLowerCase();
    if (fn === "distinct_count") fn = "dc";
    if (fn === "mean") fn = "avg";
    const field = m[2]?.toLowerCase() || undefined;
    if (fn !== "count" && !field) throw new Error(`stats: ${fn}() needs a field, e.g. ${fn}(bytes)`);
    return { fn: fn as Agg["fn"], field, as: alias?.trim() || (field ? `${fn}(${field})` : fn) };
  });
}

function aggregate(rows: Row[], aggs: Agg[], by: string[]): Row[] {
  const groups = new Map<string, Row[]>();
  for (const r of rows) {
    const key = JSON.stringify(by.map((b) => str(r[b])));
    if (by.some((b) => r[b] == null || r[b] === "")) continue;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
  }
  if (by.length === 0 && !groups.size) groups.set("[]", rows);
  return [...groups.entries()].map(([key, rs]) => {
    const out: Row = {};
    JSON.parse(key).forEach((v: string, i: number) => (out[by[i]] = rs[0][by[i]] ?? v));
    for (const a of aggs) {
      const nums = a.field ? rs.map((r) => Number(r[a.field!])).filter((n) => !isNaN(n)) : [];
      switch (a.fn) {
        case "count":
          out[a.as] = a.field ? rs.filter((r) => r[a.field!] != null && r[a.field!] !== "").length : rs.length;
          break;
        case "dc":
          out[a.as] = new Set(rs.map((r) => str(r[a.field!])).filter(Boolean)).size;
          break;
        case "values":
          out[a.as] = [...new Set(rs.map((r) => str(r[a.field!])).filter(Boolean))].sort().slice(0, 20);
          break;
        case "sum":
          out[a.as] = nums.reduce((x, y) => x + y, 0);
          break;
        case "avg":
          out[a.as] = nums.length ? Math.round((nums.reduce((x, y) => x + y, 0) / nums.length) * 100) / 100 : null;
          break;
        case "min":
          out[a.as] = nums.length ? Math.min(...nums) : null;
          break;
        case "max":
          out[a.as] = nums.length ? Math.max(...nums) : null;
          break;
      }
    }
    return out;
  });
}

function sortRows(rows: Row[], spec: string[]): Row[] {
  const keys: { f: string; desc: boolean }[] = [];
  let pendingDesc: boolean | null = null;
  for (const s of spec.flatMap((x) => csv(x))) {
    if (s === "-" || s === "+") {
      pendingDesc = s === "-";
      continue;
    }
    const desc = pendingDesc ?? s.startsWith("-");
    keys.push({ f: s.replace(/^[-+]/, "").toLowerCase(), desc });
    pendingDesc = null;
  }
  const val = (r: Row, f: string): number | string => {
    const v = r[f];
    if (f === "severity") return SEV_RANK[str(v)] ?? -1;
    if (typeof v === "number" || typeof v === "boolean") return Number(v);
    if (f === "_time" || f.endsWith("_seen")) return Date.parse(str(v)) || 0;
    const n = Number(v);
    return v != null && v !== "" && !isNaN(n) ? n : str(v).toLowerCase();
  };
  return [...rows].sort((a, b) => {
    for (const k of keys) {
      const x = val(a, k.f), y = val(b, k.f);
      if (x < y) return k.desc ? 1 : -1;
      if (x > y) return k.desc ? -1 : 1;
    }
    return 0;
  });
}

const DEFAULT_COLS: Record<Index, string[]> = {
  alerts: ["_time", "urgency", "severity", "rule", "device_label", "title", "mitre", "status", "owner"],
  devices: ["label", "ip", "mac", "class", "vendor", "priority", "risk", "alerts", "hosts", "bytes", "last_seen"],
  feed: ["_time", "protocol", "src_label", "src", "dst_label", "dst", "info", "len"],
  conn: ["_time", "device_label", "direction", "proto", "remote_ip", "remote_port", "domain", "bytes_out", "bytes_in", "duration", "state"],
  dns: ["_time", "device_label", "query", "rcode", "answers", "resolver"],
};

/** Run a query over the given data. Throws Error with a readable message on syntax errors. */
export function runSearch(query: string, data: Record<Index, Row[]>, lookups: Lookup[] = []): Result {
  const table = (name: string) => {
    const l = lookups.find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!l) throw new Error(`No lookup named “${name}” — import a CSV under Search → Lookups.`);
    return l;
  };
  const lookupRows = (l: Lookup): Row[] => l.rows.map((r) => Object.fromEntries(l.columns.map((c, i) => [c.toLowerCase(), r[i] ?? ""])));
  const stages = splitOutside(query.trim(), (c) => c === "|").map((s) => s.trim());
  let first = words(stages[0] ?? "");
  let index: Index = "alerts";
  first = first.filter((w) => {
    const m = /^index=(\w+)$/i.exec(w);
    if (!m) return true;
    const i = m[1].toLowerCase() as Index;
    if (!INDEXES.includes(i)) throw new Error(`Unknown index “${m[1]}” — use ${INDEXES.join(", ")}`);
    index = i;
    return false;
  });
  if (first[0]?.toLowerCase() === "search") first = first.slice(1);

  const where = parseTerms(first);
  let rows = data[index].filter((r) => matchesAll(r, where));
  let columns: string[] | null = null;
  let transformed = false;
  let timechart = false;
  let events = rows;

  for (const stage of stages.slice(1)) {
    const ws = words(stage);
    const cmd = ws[0]?.toLowerCase();
    const rest = ws.slice(1);
    const restStr = stage.slice(ws[0]?.length ?? 0).trim();
    switch (cmd) {
      case "search":
      case "where":
        {
          const c = parseTerms(rest);
          rows = rows.filter((r) => matchesAll(r, c));
        }
        if (!transformed) events = rows;
        break;
      case "stats": {
        const byIdx = rest.findIndex((w) => w.toLowerCase() === "by");
        const spec = (byIdx >= 0 ? rest.slice(0, byIdx) : rest).join(" ") || "count";
        const by = byIdx >= 0 ? csv(rest.slice(byIdx + 1).join(",")).map((b) => b.toLowerCase()) : [];
        const aggs = parseAggs(spec);
        rows = aggregate(rows, aggs, by);
        columns = [...by, ...aggs.map((a) => a.as)];
        if (aggs[0]?.fn === "count") rows = sortRows(rows, [`-${aggs[0].as}`]);
        transformed = true;
        break;
      }
      case "timechart": {
        let spanMs = 0;
        const args = rest.filter((w) => {
          const m = /^span=(\d+)([smhd])$/i.exec(w);
          if (!m) return true;
          spanMs = Number(m[1]) * { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2].toLowerCase() as "s" | "m" | "h" | "d"];
          return false;
        });
        const byIdx = args.findIndex((w) => w.toLowerCase() === "by");
        const agg = parseAggs((byIdx >= 0 ? args.slice(0, byIdx) : args).join(" ") || "count")[0];
        const by = byIdx >= 0 ? args[byIdx + 1]?.toLowerCase() : undefined;
        const times = rows.map((r) => Date.parse(str(r._time))).filter((t) => !isNaN(t));
        if (!times.length) {
          rows = [];
          columns = ["_time", agg.as];
        } else {
          const min = Math.min(...times), max = Math.max(...times);
          if (!spanMs) {
            const nice = [1e3, 5e3, 1e4, 3e4, 6e4, 3e5, 9e5, 18e5, 36e5, 108e5, 216e5, 432e5, 864e5];
            spanMs = nice.find((n) => (max - min) / n <= 60) ?? 864e5;
          }
          const start = Math.floor(min / spanMs) * spanMs;
          const nb = Math.floor((max - start) / spanMs) + 1;
          // Series: the `by` field's 8 most common values, the rest as OTHER.
          let series = [agg.as];
          const seriesOf = (r: Row) => (by ? str(r[by]) || "NULL" : agg.as);
          if (by) {
            const counts = new Map<string, number>();
            for (const r of rows) counts.set(seriesOf(r), (counts.get(seriesOf(r)) ?? 0) + 1);
            series = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k);
            if (series.length > 8) series = [...series.slice(0, 8), "OTHER"];
          }
          const buckets: Row[][] = Array.from({ length: nb }, () => []);
          for (const r of rows) {
            const t = Date.parse(str(r._time));
            if (!isNaN(t)) buckets[Math.floor((t - start) / spanMs)].push(r);
          }
          rows = buckets.map((b, i) => {
            const out: Row = { _time: new Date(start + i * spanMs).toISOString() };
            for (const sname of series) {
              const members = by ? b.filter((r) => (series.includes(seriesOf(r)) ? seriesOf(r) : "OTHER") === sname) : b;
              out[sname] = aggregate(members, [{ ...agg, as: "v" }], [])[0]?.v ?? 0;
            }
            return out;
          });
          columns = ["_time", ...series];
        }
        transformed = true;
        timechart = true;
        break;
      }
      case "top":
      case "rare": {
        let n = 10;
        const fs = rest.filter((w) => {
          if (/^\d+$/.test(w)) return (n = Number(w)), false;
          const m = /^limit=(\d+)$/i.exec(w);
          if (m) return (n = Number(m[1])), false;
          return true;
        });
        const by = csv(fs.join(",")).map((b) => b.toLowerCase());
        if (!by.length) throw new Error(`${cmd}: name a field, e.g. “${cmd} rule”`);
        const total = rows.length || 1;
        rows = aggregate(rows, [{ fn: "count", as: "count" }], by).map((r) => ({ ...r, percent: Math.round(((r.count as number) / total) * 1000) / 10 }));
        rows = sortRows(rows, [cmd === "top" ? "-count" : "count"]).slice(0, n);
        columns = [...by, "count", "percent"];
        transformed = true;
        break;
      }
      case "sort":
        rows = sortRows(rows, rest.filter((w) => !/^\d+$/.test(w)));
        if (/^\d+$/.test(rest[0] ?? "")) rows = rows.slice(0, Number(rest[0]));
        break;
      case "head":
        rows = rows.slice(0, Number(rest[0] ?? 10) || 10);
        break;
      case "tail":
        rows = rows.slice(-(Number(rest[0] ?? 10) || 10));
        break;
      case "table":
      case "fields": {
        const fs = csv(rest.join(",")).filter((f) => f !== "-" && f !== "+").map((f) => f.toLowerCase());
        if (cmd === "fields" && rest[0] === "-") {
          const drop = new Set(fs);
          columns = (columns ?? DEFAULT_COLS[index]).filter((c) => !drop.has(c));
        } else columns = fs;
        break;
      }
      case "dedup": {
        const fs = csv(rest.join(",")).map((f) => f.toLowerCase());
        const seen = new Set<string>();
        rows = rows.filter((r) => {
          const k = JSON.stringify(fs.map((f) => str(r[f])));
          return seen.has(k) ? false : (seen.add(k), true);
        });
        break;
      }
      case "inputlookup": {
        rows = lookupRows(table(rest[0] ?? ""));
        events = rows;
        columns = table(rest[0]).columns.map((c) => c.toLowerCase());
        break;
      }
      case "lookup": {
        // lookup <name> <field> [as <lookup column>]
        const [name, field, asKw, keyCol] = rest;
        if (!name || !field) throw new Error("lookup: usage | lookup <name> <field> [as <lookup column>]");
        const l = table(name);
        const cols = l.columns.map((c) => c.toLowerCase());
        const key = (asKw?.toLowerCase() === "as" && keyCol ? keyCol : cols[0]).toLowerCase();
        if (!cols.includes(key)) throw new Error(`lookup: “${l.name}” has no column “${key}” (columns: ${cols.join(", ")})`);
        const byKey = new Map(lookupRows(l).map((r) => [String(r[key]).toLowerCase(), r]));
        const f = field.toLowerCase();
        rows = rows.map((r) => {
          const hit = byKey.get(String(r[f] ?? "").toLowerCase());
          if (!hit) return r;
          const o: Row = { ...r };
          for (const c of cols) if (c !== key && o[c] == null) o[c] = hit[c];
          return o;
        });
        if (columns) columns = [...columns, ...cols.filter((c) => c !== key && !columns!.includes(c))];
        else columns = [...DEFAULT_COLS[index], ...cols.filter((c) => c !== key)];
        break;
      }
      case "rename": {
        // rename a as b, c as d
        const pairs = csv(restStr).map((p) => p.split(/\s+as\s+/i).map((x) => unquote(x.trim())));
        rows = rows.map((r) => {
          const o: Row = { ...r };
          for (const [from, to] of pairs) {
            if (!to) continue;
            o[to] = o[from.toLowerCase()];
            delete o[from.toLowerCase()];
          }
          return o;
        });
        if (columns) columns = columns.map((c) => pairs.find(([f]) => f.toLowerCase() === c)?.[1] ?? c);
        break;
      }
      case undefined:
        break;
      default:
        throw new Error(`Unknown command “${ws[0]}” — supported: search, where, stats, timechart, top, rare, sort, head, tail, table, fields, dedup, rename, lookup, inputlookup`);
    }
  }

  return { index, rows, columns: columns ?? DEFAULT_COLS[index], events, transformed, timechart };
}

export const EXAMPLES: { q: string; d: string }[] = [
  { q: "index=alerts open=true | stats count by urgency", d: "Open alerts by urgency" },
  { q: "index=alerts | timechart count by severity", d: "Alerts over time" },
  { q: "index=feed | timechart span=10s count by protocol", d: "Live traffic mix over time" },
  { q: "index=alerts rule=arp-spoof OR rule=rogue-router OR rule=ip-conflict", d: "Man-in-the-middle activity" },
  { q: "index=alerts | stats count, dc(device) as devices by tactic, mitre, mitre_name", d: "MITRE ATT&CK coverage" },
  { q: "index=alerts severity>=high _time>-24h | table _time severity device_label title", d: "High-severity alerts, last 24 h" },
  { q: "index=devices risk>0 | sort -risk | table label ip class vendor risk alerts", d: "Riskiest devices" },
  { q: "index=devices iot=true | stats count, sum(bytes) as bytes by class", d: "IoT inventory by type" },
  { q: "index=devices vendor=* | top 10 vendor", d: "Most common vendors" },
  { q: "index=devices gateway=true | table label ip mac vendor", d: "Which device is the router?" },
  { q: "index=devices priority=high OR priority=critical | table label ip class priority risk", d: "Critical assets" },
  { q: "index=dns | top 15 query", d: "Most frequent DNS lookups" },
  { q: "index=dns rcode=NXDOMAIN | stats count, dc(query) as names by device_label", d: "Failed lookups per device (DGA hint)" },
  { q: "index=conn external=true | stats sum(bytes_out) as sent, dc(remote_ip) as hosts by device_label | sort -sent", d: "Who sends the most to the internet" },
  { q: "index=conn service=23 OR service=2323 OR service=21", d: "Cleartext Telnet / FTP connections" },
  { q: "index=devices | lookup owners mac | table label mac owner room", d: "Join a lookup table (import owners.csv first)" },
  { q: "index=feed protocol=TLS | stats count by src_label, info | sort -count | head 20", d: "TLS destinations per device" },
];
