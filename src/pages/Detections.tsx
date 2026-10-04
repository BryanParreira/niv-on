import { useEffect, useState } from "react";
import { api, inTauri, newId, updateLibrary, type Detection, type Severity } from "../api";
import { Icon } from "../components/Icon";
import { SEVERITY_ORDER } from "../components/Severity";
import { lastRuns, runDetection, STARTER_DETECTIONS, type RunResult } from "../detections";
import { ago } from "../format";
import { useNav } from "../nav";

/** Custom detections (Splunk "correlation searches"): any search that returns results raises an alert. */
export function Detections({ onMessage }: { onMessage: (m: string) => void }) {
  const nav = useNav();
  const [list, setList] = useState<Detection[] | null>(null);
  const [runs, setRuns] = useState<Map<string, RunResult>>(new Map(lastRuns));
  const [running, setRunning] = useState<string | null>(null);

  useEffect(() => {
    if (inTauri) api.getSettings().then((s) => setList(s.library.detections)).catch((e) => onMessage(String(e)));
    const id = setInterval(() => setRuns(new Map(lastRuns)), 5000);
    return () => clearInterval(id);
  }, [onMessage]);

  async function save(next: Detection[]) {
    setList(next);
    try {
      await updateLibrary((l) => ({ ...l, detections: next }));
    } catch (e) {
      onMessage(String(e));
    }
  }
  const patch = (id: string, p: Partial<Detection>) => save(list!.map((d) => (d.id === id ? { ...d, ...p } : d)));

  async function runNow(d: Detection) {
    setRunning(d.id);
    const r = await runDetection(d);
    setRuns(new Map(lastRuns));
    setRunning(null);
    onMessage(r.error ? `${d.name}: ${r.error}` : `${d.name}: ${r.matches} result(s), ${r.raised} new alert(s).`);
  }

  function edit(d: Detection) {
    try {
      localStorage.setItem("niv.lastSearch", d.query);
    } catch {
      /* default query */
    }
    nav.go("search");
  }

  if (!list) return <div className="card"><div className="empty">Loading…</div></div>;

  return (
    <>
      <div className="banner">
        <Icon name="info" />
        <div className="grow">
          A detection is a saved search that runs every minute. When it returns results, Niv.ON raises an alert — one per device found
          (a <span className="mono">mac</span>, <span className="mono">device</span> or <span className="mono">src</span> column), throttled so the same device isn't alerted again within the window.
          Build them in <button className="linkish" onClick={() => nav.go("search")}>Search</button> → “Save as detection”.
        </div>
      </div>
      <div className="card pad0">
        <div className="card-head">
          <h2>Custom detections</h2>
          <span className="sub">{list.filter((d) => d.enabled).length} enabled · built-in rules live in Rules &amp; data</span>
          <div className="right">
            <button className="btn sm" onClick={() => save([...list, ...STARTER_DETECTIONS.filter((s) => !list.some((d) => d.name === s.name)).map((s) => ({ ...s, id: newId() }))])}>
              <Icon name="shield" size={12} /> Add starter detections
            </button>
          </div>
        </div>
        <div className="table-wrap">
          <table className="t">
            <thead>
              <tr><th>On</th><th>Detection</th><th>Severity</th><th>Throttle</th><th>Last run</th><th /></tr>
            </thead>
            <tbody>
              {list.map((d) => {
                const r = runs.get(d.id);
                return (
                  <tr key={d.id}>
                    <td><label className="toggle"><input type="checkbox" checked={d.enabled} onChange={(e) => patch(d.id, { enabled: e.target.checked })} aria-label="Enabled" /></label></td>
                    <td style={{ maxWidth: 520 }}>
                      <div className="name">{d.name}</div>
                      <div className="mono muted small" style={{ overflowWrap: "anywhere" }}>{d.query}</div>
                    </td>
                    <td>
                      <select className="select" value={d.severity} onChange={(e) => patch(d.id, { severity: e.target.value as Severity })} aria-label="Severity">
                        {[...SEVERITY_ORDER].reverse().map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </td>
                    <td>
                      <select className="select" value={d.throttleMinutes} onChange={(e) => patch(d.id, { throttleMinutes: Number(e.target.value) })} aria-label="Throttle">
                        {[[15, "15 min"], [60, "1 hour"], [240, "4 hours"], [1440, "1 day"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                      </select>
                    </td>
                    <td className="small">
                      {!r ? <span className="muted">not yet</span>
                        : r.error ? <span style={{ color: "var(--critical)" }} title={r.error}>error</span>
                        : <span className="dim">{ago(new Date(r.ts).toISOString())} · {r.matches} result{r.matches === 1 ? "" : "s"}{r.raised ? ` · ${r.raised} alert${r.raised === 1 ? "" : "s"}` : ""}</span>}
                    </td>
                    <td className="r">
                      <div className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                        <button className="btn sm" disabled={running === d.id} onClick={() => runNow(d)}>{running === d.id ? "Running…" : "Run now"}</button>
                        <button className="btn sm ghost" onClick={() => edit(d)}>Open</button>
                        <button className="btn sm ghost icon" title="Delete" onClick={() => save(list.filter((x) => x.id !== d.id))}><Icon name="trash" size={12} /></button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {list.length === 0 && (
            <div className="empty"><Icon name="shield" size={28} />No custom detections yet — add the starters or save one from Search.</div>
          )}
        </div>
      </div>
    </>
  );
}
