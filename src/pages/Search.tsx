import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, inTauri, newId, updateLibrary, type Library, type Severity, type Viz } from "../api";
import { Icon } from "../components/Icon";
import { autoViz, ResultView } from "../components/ResultView";
import { SEVERITY_ORDER } from "../components/Severity";
import { dateTime, fmtNum } from "../format";
import { useNav } from "../nav";
import { EXAMPLES, type Result, type Row } from "../search";
import { executeSearch } from "../searchData";

const LAST_KEY = "niv.lastSearch";
const VIZ: { id: Viz | "auto"; label: string }[] = [
  { id: "auto", label: "Auto" },
  { id: "table", label: "Table" },
  { id: "bar", label: "Bar" },
  { id: "line", label: "Line" },
  { id: "single", label: "Single value" },
];

function lastQuery(): string {
  try {
    return localStorage.getItem(LAST_KEY) ?? EXAMPLES[0].q;
  } catch {
    return EXAMPLES[0].q;
  }
}

/** Event histogram over the matched events' _time. */
function Timeline({ events }: { events: Row[] }) {
  const bins = useMemo(() => {
    const ts = events.map((e) => Date.parse(String(e._time ?? ""))).filter((t) => !isNaN(t));
    if (ts.length < 2) return null;
    const min = Math.min(...ts), max = Math.max(...ts);
    const n = 48;
    const span = Math.max(1, max - min);
    const counts = new Array(n).fill(0);
    for (const t of ts) counts[Math.min(n - 1, Math.floor(((t - min) / span) * n))]++;
    return { counts, min, max, peak: Math.max(...counts) };
  }, [events]);
  if (!bins) return null;
  return (
    <div className="timeline" aria-label="Events over time">
      <div className="timeline-bars">
        {bins.counts.map((c, i) => (
          <div key={i} title={`${c} event${c === 1 ? "" : "s"}`} style={{ height: `${c ? Math.max(6, (c / bins.peak) * 100) : 0}%` }} />
        ))}
      </div>
      <div className="timeline-axis muted small">
        <span>{dateTime(new Date(bins.min).toISOString())}</span>
        <span>{dateTime(new Date(bins.max).toISOString())}</span>
      </div>
    </div>
  );
}

type SaveMode = "search" | "panel" | "detection";

/** Minimal RFC 4180 CSV parser (quotes, escaped quotes, CRLF). */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      row.push(cur);
      cur = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cur);
      cur = "";
      if (row.some((x) => x.trim())) rows.push(row);
      row = [];
    } else cur += c;
  }
  row.push(cur);
  if (row.some((x) => x.trim())) rows.push(row);
  return rows;
}

/** Splunk-style search over alerts, devices and the live frame feed. */
export function Search({ onMessage }: { onMessage: (m: string) => void }) {
  const nav = useNav();
  const [q, setQ] = useState(lastQuery);
  const [res, setRes] = useState<Result | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ms, setMs] = useState(0);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(false);
  const [viz, setViz] = useState<Viz | "auto">("auto");
  const [lib, setLib] = useState<Library | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [saving, setSaving] = useState<SaveMode | null>(null);
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const input = useRef<HTMLInputElement>(null);
  const csvInput = useRef<HTMLInputElement>(null);

  const run = useCallback(async (query: string) => {
    if (!inTauri) return;
    setBusy(true);
    try {
      const t0 = performance.now();
      setRes(await executeSearch(query));
      setErr(null);
      setMs(Math.round(performance.now() - t0));
      try {
        localStorage.setItem(LAST_KEY, query);
      } catch {
        /* per-viewer convenience only */
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    run(q);
    input.current?.focus();
    if (inTauri) api.getSettings().then((s) => setLib(s.library)).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Real-time mode re-runs the search every 5 s.
  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => run(q), 5000);
    return () => clearInterval(id);
  }, [live, q, run]);

  const shownViz: Viz = viz === "auto" ? (res ? autoViz(res) : "table") : viz;

  function startSave(mode: SaveMode) {
    setSaving(mode);
    setName(q.replace(/^index=\w+\s*/, "").slice(0, 60));
  }

  async function commitSave() {
    const n = name.trim();
    if (!n) return;
    try {
      const next = await updateLibrary((l) => {
        if (saving === "search") return { ...l, savedSearches: [...l.savedSearches.filter((s) => s.name !== n), { name: n, query: q }] };
        if (saving === "panel")
          return { ...l, panels: [...l.panels, { id: newId(), title: n, query: q, viz: shownViz, width: shownViz === "line" || shownViz === "table" ? 2 : 1 }] };
        return { ...l, detections: [...l.detections, { id: newId(), name: n, query: q, severity, enabled: true, throttleMinutes: 60 }] };
      });
      setLib(next);
      onMessage(
        saving === "search" ? `Saved “${n}”.`
          : saving === "panel" ? `Added “${n}” to Dashboards.`
          : `Detection “${n}” is live — it runs every minute and alerts when the search returns results.`,
      );
      setSaving(null);
    } catch (e) {
      onMessage(String(e));
    }
  }

  async function importLookup(file: File) {
    try {
      const rows = parseCsv(await file.text());
      if (rows.length < 2) throw new Error("the CSV needs a header row and at least one data row");
      const [header, ...body] = rows;
      const columns = header.map((h, i) => h.trim().replace(/\s+/g, "_") || `col${i + 1}`);
      const name = file.name.replace(/\.[^.]+$/, "").replace(/[^\w-]+/g, "_").toLowerCase();
      const next = await updateLibrary((l) => ({ ...l, lookups: [...l.lookups.filter((x) => x.name !== name), { name, columns, rows: body.slice(0, 50_000) }] }));
      setLib(next);
      onMessage(`Lookup “${name}” imported: ${body.length} rows, columns ${columns.join(", ")}. Use | lookup ${name} ${columns[0]}`);
    } catch (e) {
      onMessage(`Could not import ${file.name}: ${e instanceof Error ? e.message : e}`);
    }
  }
  async function removeLookup(n: string) {
    setLib(await updateLibrary((l) => ({ ...l, lookups: l.lookups.filter((x) => x.name !== n) })));
  }

  async function removeSaved(n: string) {
    setLib(await updateLibrary((l) => ({ ...l, savedSearches: l.savedSearches.filter((s) => s.name !== n) })));
  }
  function pick(query: string) {
    setQ(query);
    run(query);
  }

  async function exportCsv() {
    if (!res) return;
    const esc = (v: unknown) => `"${(Array.isArray(v) ? v.join(" ") : String(v ?? "")).replace(/"/g, '""')}"`;
    const lines = [res.columns.join(","), ...res.rows.map((r) => res.columns.map((c) => esc(r[c])).join(","))];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      onMessage(`Copied ${res.rows.length} results as CSV to the clipboard.`);
    } catch (e) {
      onMessage(`Could not copy to the clipboard: ${e}`);
    }
  }

  return (
    <>
      <div className="card">
        <form className="search-bar" onSubmit={(e) => { e.preventDefault(); run(q); }}>
          <Icon name="search" size={16} />
          <input ref={input} className="input mono" value={q} spellCheck={false} onChange={(e) => setQ(e.target.value)}
            placeholder="index=alerts severity>=high | stats count by device_label" aria-label="Search query" />
          <button className="btn primary" type="submit" disabled={busy}>{busy ? "Searching…" : "Search"}</button>
        </form>
        <div className="row" style={{ marginTop: 10, gap: 8 }}>
          <label className="toggle small">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
            Real-time (every 5 s)
          </label>
          <div className="seg">
            {VIZ.map((v) => <button key={v.id} className={viz === v.id ? "on" : ""} onClick={() => setViz(v.id)}>{v.label}</button>)}
          </div>
          <button className="btn sm ghost" onClick={() => startSave("search")}><Icon name="check" size={12} /> Save</button>
          <button className="btn sm ghost" onClick={() => startSave("panel")}><Icon name="dashboard" size={12} /> Add to dashboard</button>
          <button className="btn sm ghost" onClick={() => startSave("detection")}><Icon name="shield" size={12} /> Save as detection</button>
          <button className="btn sm ghost" onClick={exportCsv} disabled={!res?.rows.length}><Icon name="download" size={12} /> CSV</button>
          <button className="btn sm ghost" onClick={() => setShowHelp((v) => !v)}><Icon name="info" size={12} /> Syntax</button>
          <div style={{ flex: 1 }} />
          {res && !err && (
            <span className="muted small">
              index=<b>{res.index}</b> · {fmtNum(res.events.length)} events{res.transformed ? ` · ${fmtNum(res.rows.length)} results` : ""} · {ms} ms
            </span>
          )}
        </div>
        {saving && (
          <form className="row" style={{ marginTop: 12, gap: 8 }} onSubmit={(e) => { e.preventDefault(); commitSave(); }}>
            <span className="small dim">
              {saving === "search" ? "Save search as" : saving === "panel" ? `Dashboard panel (${shownViz}) titled` : "Detection name"}
            </span>
            <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} style={{ width: 280 }} />
            {saving === "detection" && (
              <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} aria-label="Severity">
                {[...SEVERITY_ORDER].reverse().map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            )}
            <button className="btn sm primary" type="submit" disabled={!name.trim()}>Save</button>
            <button className="btn sm ghost" type="button" onClick={() => setSaving(null)}>Cancel</button>
            {saving === "detection" && (
              <span className="hint">Runs every minute while Niv.ON is open; each result row with a device raises an alert (once per hour per device).</span>
            )}
          </form>
        )}
        {showHelp && (
          <div className="banner" style={{ marginTop: 12 }}>
            <Icon name="info" />
            <div className="grow small">
              <div><b>Indexes:</b> <span className="mono">index=alerts</span> (default), <span className="mono">index=devices</span>, <span className="mono">index=conn</span> (connection log), <span className="mono">index=dns</span> (DNS log), <span className="mono">index=feed</span> (last 500 frames). conn/dns cover 7 days unless the search says <span className="mono">_time&gt;-30d</span>.</div>
              <div><b>Terms</b>: <span className="mono">field=value</span> with <span className="mono">*</span> wildcards, <span className="mono">!=</span>, <span className="mono">&gt; &gt;= &lt; &lt;=</span> (numbers, severity, <span className="mono">_time&gt;-1h</span>), <span className="mono">NOT</span>, <span className="mono">a OR b</span>, bare words. Terms are ANDed; OR binds tighter.</div>
              <div><b>Commands:</b> <span className="mono">| stats count, dc(f), sum(f), avg(f), min(f), max(f), values(f) [as name] by f1, f2</span> · <span className="mono">| timechart [span=5m] count by f</span> · <span className="mono">| top N f</span> · <span className="mono">| rare f</span> · <span className="mono">| sort -f</span> · <span className="mono">| head N</span> · <span className="mono">| table f1 f2</span> · <span className="mono">| where …</span> · <span className="mono">| dedup f</span> · <span className="mono">| rename a as b</span> · <span className="mono">| lookup table field [as column]</span> · <span className="mono">| inputlookup table</span></div>
              <div className="muted"><b>Fields</b> — alerts: severity urgency rule title message device device_label remote port status open owner mitre mitre_name tactic · devices: label mac ip vendor class tag priority hostname iot risk alerts hosts bytes rssi gateway ap self · feed: protocol kind src dst src_label dst_label info len rssi · conn: device_label mac direction proto local_ip local_port remote_ip remote_port service domain bytes_out bytes_in bytes packets external duration state · dns: device_label mac query rcode answers resolver</div>
            </div>
          </div>
        )}
        {err && <div className="banner error" style={{ marginTop: 12 }}><Icon name="octagon" /><div className="grow mono small">{err}</div></div>}
      </div>

      <div className="split">
        <div className="card pad0">
          {res && !res.transformed && res.events.length > 1 && (
            <div style={{ padding: "16px 16px 0" }}><Timeline events={res.events} /></div>
          )}
          <div className="table-wrap" style={{ maxHeight: "calc(100vh - 330px)", padding: shownViz === "table" ? 0 : 16 }}>
            {res && !err && <ResultView r={res} viz={shownViz} height={300} />}
          </div>
        </div>

        <div className="grid" style={{ alignSelf: "start" }}>
          <div className="card">
            <div className="card-head">
              <h3>Saved searches</h3>
              <div className="right"><button className="btn sm ghost" onClick={() => nav.go("dashboards")}>Dashboards <Icon name="chevron" size={12} /></button></div>
            </div>
            {!lib?.savedSearches.length && <div className="muted small">Save a search to re-run it in one click.</div>}
            {lib?.savedSearches.map((s) => (
              <div key={s.name} className="saved-search">
                <button className="linkish ellipsis" onClick={() => pick(s.query)} title={s.query}>{s.name}</button>
                <button className="btn sm ghost icon" onClick={() => removeSaved(s.name)} title="Delete"><Icon name="x" size={12} /></button>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="card-head">
              <h3>Lookups</h3>
              <div className="right">
                <button className="btn sm ghost" onClick={() => csvInput.current?.click()}><Icon name="download" size={12} /> Import CSV</button>
                <input ref={csvInput} type="file" accept=".csv,text/csv" hidden
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) importLookup(f); e.target.value = ""; }} />
              </div>
            </div>
            {!lib?.lookups.length && (
              <div className="muted small">
                Enrich results with your own data — e.g. <span className="mono">owners.csv</span> with columns <span className="mono">mac,owner,room</span>, then
                <span className="mono"> | lookup owners mac</span>.
              </div>
            )}
            {lib?.lookups.map((l) => (
              <div key={l.name} className="saved-search">
                <button className="linkish ellipsis" onClick={() => pick(`| inputlookup ${l.name}`)} title={l.columns.join(", ")}>
                  {l.name} <span className="muted small">· {l.rows.length} rows</span>
                </button>
                <button className="btn sm ghost icon" onClick={() => removeLookup(l.name)} title="Delete"><Icon name="x" size={12} /></button>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="card-head"><h3>Examples</h3></div>
            {EXAMPLES.map((e) => (
              <button key={e.q} className="example" onClick={() => pick(e.q)}>
                <span className="small">{e.d}</span>
                <span className="mono muted ellipsis" style={{ fontSize: 11 }}>{e.q}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
