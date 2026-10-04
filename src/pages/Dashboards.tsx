import { useCallback, useEffect, useState } from "react";
import { api, inTauri, newId, updateLibrary, type Panel as PanelCfg, type Viz } from "../api";
import { Icon } from "../components/Icon";
import { ResultView } from "../components/ResultView";
import { useNav } from "../nav";
import type { Result } from "../search";
import { executeSearch } from "../searchData";

const REFRESH_MS = 10_000;

const STARTER: Omit<PanelCfg, "id">[] = [
  { title: "Open alerts", query: "index=alerts open=true | stats count", viz: "single", width: 1 },
  { title: "Alerts over time", query: "index=alerts | timechart count by severity", viz: "line", width: 2 },
  { title: "Open alerts by urgency", query: "index=alerts open=true | stats count by urgency", viz: "bar", width: 1 },
  { title: "Riskiest devices", query: "index=devices risk>0 | sort -risk | head 10 | table label ip class priority risk alerts", viz: "table", width: 2 },
  { title: "ATT&CK tactics (open)", query: "index=alerts open=true tactic=* | stats count by tactic", viz: "bar", width: 1 },
  { title: "Live traffic by protocol", query: "index=feed | timechart count by protocol", viz: "line", width: 2 },
  { title: "Top talkers", query: "index=devices | sort -bytes | head 8 | table label bytes", viz: "bar", width: 1 },
  { title: "IoT devices", query: "index=devices iot=true | stats count", viz: "single", width: 1 },
  { title: "Top DNS lookups", query: "index=dns | top 10 query", viz: "bar", width: 1 },
  { title: "Internet traffic by device", query: "index=conn external=true | stats sum(bytes) as bytes, dc(remote_ip) as hosts by device_label | sort -bytes | head 10", viz: "table", width: 2 },
  { title: "Incidents in progress", query: "index=alerts status=in-progress | table _time urgency device_label title owner", viz: "table", width: 2 },
];

function Panel({ p, onChange, onRemove, onOpen }: { p: PanelCfg; onChange: (p: PanelCfg) => void; onRemove: () => void; onOpen: () => void }) {
  const [res, setRes] = useState<Result | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    executeSearch(p.query).then((r) => { setRes(r); setErr(null); }).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [p.query]);

  useEffect(() => {
    if (!inTauri) return;
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  return (
    <div className={`card ${p.width === 2 ? "w2" : ""}`}>
      <div className="card-head">
        <h3 className="ellipsis">{p.title}</h3>
        <div className="right">
          <select className="select" value={p.viz} onChange={(e) => onChange({ ...p, viz: e.target.value as Viz })} aria-label="Visualization">
            <option value="table">Table</option>
            <option value="bar">Bar</option>
            <option value="line">Line</option>
            <option value="single">Single value</option>
          </select>
          <button className="btn sm ghost icon" title={p.width === 2 ? "Make narrow" : "Make wide"} onClick={() => onChange({ ...p, width: p.width === 2 ? 1 : 2 })}>
            <Icon name={p.width === 2 ? "back" : "chevron"} size={12} />
          </button>
          <button className="btn sm ghost icon" title="Open in Search" onClick={onOpen}><Icon name="search" size={12} /></button>
          <button className="btn sm ghost icon" title="Remove panel" onClick={onRemove}><Icon name="x" size={12} /></button>
        </div>
      </div>
      <div className="panel-body">
        {err ? <div className="banner error small"><Icon name="octagon" /><div className="grow mono">{err}</div></div>
          : res ? <ResultView r={res} viz={p.viz} limit={50} height={180} />
          : <div className="empty small">Loading…</div>}
      </div>
      <div className="panel-query ellipsis" title={p.query}>{p.query}</div>
    </div>
  );
}

/** Splunk-style dashboards: every panel is a live search. */
export function Dashboards({ onMessage }: { onMessage: (m: string) => void }) {
  const nav = useNav();
  const [panels, setPanels] = useState<PanelCfg[] | null>(null);

  useEffect(() => {
    if (inTauri) api.getSettings().then((s) => setPanels(s.library.panels)).catch((e) => onMessage(String(e)));
  }, [onMessage]);

  async function save(next: PanelCfg[]) {
    setPanels(next);
    try {
      await updateLibrary((l) => ({ ...l, panels: next }));
    } catch (e) {
      onMessage(String(e));
    }
  }

  function openInSearch(q: string) {
    try {
      localStorage.setItem("niv.lastSearch", q);
    } catch {
      /* falls back to the default query */
    }
    nav.go("search");
  }

  if (!panels) return <div className="card"><div className="empty">Loading…</div></div>;

  return (
    <>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span className="muted small">Each panel is a saved search, refreshed every 10 s. Build new ones in Search → “Add to dashboard”.</span>
        <div className="row">
          {panels.length > 0 && (
            <button className="btn sm ghost" onClick={() => confirm("Remove every panel?") && save([])}>Clear</button>
          )}
          <button className="btn sm" onClick={() => save([...panels, ...STARTER.map((p) => ({ ...p, id: newId() }))])}>
            <Icon name="dashboard" size={12} /> Add SOC starter panels
          </button>
          <button className="btn sm primary" onClick={() => nav.go("search")}><Icon name="search" size={12} /> New panel</button>
        </div>
      </div>
      {panels.length === 0 ? (
        <div className="card hero">
          <h2>No dashboards yet</h2>
          <p>Start with a security-operations overview — open alerts, urgency, ATT&amp;CK tactics, riskiest devices and live traffic — or build panels from any search.</p>
          <div className="row" style={{ marginTop: 14 }}>
            <button className="btn primary" onClick={() => save(STARTER.map((p) => ({ ...p, id: newId() })))}>Create SOC overview</button>
            <button className="btn" onClick={() => nav.go("search")}>Open Search</button>
          </div>
        </div>
      ) : (
        <div className="panels">
          {panels.map((p) => (
            <Panel key={p.id} p={p}
              onChange={(np) => save(panels.map((x) => (x.id === p.id ? np : x)))}
              onRemove={() => save(panels.filter((x) => x.id !== p.id))}
              onOpen={() => openInSearch(p.query)} />
          ))}
        </div>
      )}
    </>
  );
}
