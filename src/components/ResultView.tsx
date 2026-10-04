import type { Severity, Viz } from "../api";
import { dateTime, fmtNum } from "../format";
import { useNav } from "../nav";
import type { Result, Row } from "../search";
import { Icon } from "./Icon";
import { SeverityBadge } from "./Severity";
import { TimeSeriesChart } from "./TimeSeriesChart";

const SERIES_COLORS = ["var(--s1)", "var(--s2)", "var(--s3)", "var(--s4)", "var(--mono-series)"];
const PLAIN = ["port", "id", "channel", "rssi", "len", "value", "percent", "risk"];
const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

/** Best visualization for a result when the user hasn't picked one. */
export function autoViz(r: Result): Viz {
  if (r.timechart) return "line";
  if (r.transformed && r.rows.length === 1 && r.columns.length === 1) return "single";
  return "table";
}

function numericCol(r: Result): string | undefined {
  return r.columns.find((c) => c !== "_time" && r.rows.some((row) => typeof row[c] === "number"));
}

export function Cell({ col, v, row }: { col: string; v: unknown; row: Row }) {
  const nav = useNav();
  if (v == null || v === "") return <span className="muted">—</span>;
  if (col === "severity" || col === "urgency") return <SeverityBadge s={v as Severity} />;
  if (col === "_time" || col.endsWith("_seen")) return <span className="mono small">{dateTime(String(v))}</span>;
  const linked = ["mac", "device", "src", "dst"].includes(col)
    ? String(v)
    : ({ label: row.mac, device_label: row.device, src_label: row.src, dst_label: row.dst } as Record<string, unknown>)[col];
  const text = Array.isArray(v) ? v.join(", ") : typeof v === "number" && !PLAIN.includes(col) ? fmtNum(v) : String(v);
  if (typeof linked === "string" && MAC.test(linked) && linked !== "ff:ff:ff:ff:ff:ff") {
    return <button className="linkish" onClick={() => nav.openDevice(linked)}>{text}</button>;
  }
  return <span className={typeof v === "number" ? "num" : ["ip", "remote", "mitre", "info"].includes(col) ? "mono small" : ""}>{text}</span>;
}

/** Render a search result as a table, bar chart, line chart or single value. */
export function ResultView({ r, viz, limit = 500, height = 220 }: { r: Result; viz: Viz; limit?: number; height?: number }) {
  if (!r.rows.length) {
    return <div className="empty"><Icon name="search" size={24} />No results.</div>;
  }
  if (viz === "single") {
    const col = numericCol(r) ?? r.columns[0];
    const v = r.rows[0][col];
    return (
      <div className="single-value">
        <div className="value num">{typeof v === "number" ? fmtNum(v) : String(v ?? "—")}</div>
        <div className="muted small">{col}</div>
      </div>
    );
  }
  if (viz === "line") {
    const rows = r.rows.filter((x) => !isNaN(Date.parse(String(x._time))));
    const cols = r.columns.filter((c) => c !== "_time" && rows.some((x) => typeof x[c] === "number"));
    if (rows.length < 2 || !cols.length) return <div className="empty small">A line chart needs a time series — end the search with <span className="mono">| timechart count</span>.</div>;
    return (
      <TimeSeriesChart
        times={rows.map((x) => Math.floor(Date.parse(String(x._time)) / 1000))}
        series={cols.map((c, i) => ({ key: c, label: c, color: SERIES_COLORS[i % SERIES_COLORS.length], values: rows.map((x) => Number(x[c]) || 0) }))}
        format={(v) => fmtNum(Math.round(v))}
        height={height}
      />
    );
  }
  if (viz === "bar") {
    const val = numericCol(r);
    const label = r.columns.find((c) => c !== val) ?? r.columns[0];
    if (!val) return <div className="empty small">A bar chart needs a number column — try <span className="mono">| stats count by field</span>.</div>;
    const rows = r.rows.slice(0, 15);
    const max = Math.max(1, ...rows.map((x) => Number(x[val]) || 0));
    return (
      <div className="bars">
        {rows.map((x, i) => (
          <div key={i} className="bar-row">
            <span className="ellipsis">{Array.isArray(x[label]) ? (x[label] as unknown[]).join(", ") : String(x[label] ?? "—")}</span>
            <span className="num dim">{fmtNum(Number(x[val]) || 0)}</span>
            <div className="track"><div style={{ width: `${((Number(x[val]) || 0) / max) * 100}%` }} /></div>
          </div>
        ))}
      </div>
    );
  }
  return (
    <>
      <table className="t compact">
        <thead><tr>{r.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>
          {r.rows.slice(0, limit).map((row, i) => (
            <tr key={i}>{r.columns.map((c) => <td key={c} style={{ maxWidth: 420, overflowWrap: "anywhere" }}><Cell col={c} v={row[c]} row={row} /></td>)}</tr>
          ))}
        </tbody>
      </table>
      {r.rows.length > limit && <div className="muted small" style={{ padding: 12 }}>Showing {limit} of {fmtNum(r.rows.length)} rows.</div>}
    </>
  );
}
