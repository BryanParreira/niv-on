import { useMemo, useState } from "react";
import { api, type Severity } from "../api";
import { AlertList, ruleLabel } from "../components/AlertList";
import { SEVERITY_ORDER } from "../components/Severity";
import { usePoll } from "../store";

export function Alerts() {
  const [alerts, reload] = usePoll(() => api.getAlerts(2000), 2000);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [rule, setRule] = useState<string>("all");
  const [showAcked, setShowAcked] = useState(false);

  const all = alerts ?? [];
  const rules = useMemo(() => [...new Set(all.map((a) => a.rule))].sort(), [all]);
  const shown = all.filter(
    (a) => (showAcked || !a.acknowledged) && (sev === "all" || a.severity === sev) && (rule === "all" || a.rule === rule),
  );
  const countBy = (s: Severity) => all.filter((a) => a.severity === s && (showAcked || !a.acknowledged)).length;

  return (
    <div className="card">
      <div className="card-head" style={{ gap: 12 }}>
        <div className="chips">
          <button className={`chip ${sev === "all" ? "on" : ""}`} onClick={() => setSev("all")}>All severities</button>
          {SEVERITY_ORDER.map((s) => (
            <button key={s} className={`chip ${sev === s ? "on" : ""}`} onClick={() => setSev(s)}>
              {s} <span className="muted num">{countBy(s)}</span>
            </button>
          ))}
        </div>
        <select className="select" value={rule} onChange={(e) => setRule(e.target.value)}>
          <option value="all">All rules</option>
          {rules.map((r) => <option key={r} value={r}>{ruleLabel(r)}</option>)}
        </select>
        <label className="toggle">
          <input type="checkbox" checked={showAcked} onChange={(e) => setShowAcked(e.target.checked)} />
          <span className="dim">Show acknowledged</span>
        </label>
        <div className="right">
          <button className="btn" onClick={() => api.ackAlert().then(reload)}>Acknowledge all</button>
          <button
            className="btn danger"
            onClick={() => confirm("Delete all alerts permanently?") && api.clearAlerts().then(reload)}
          >
            Clear
          </button>
        </div>
      </div>
      <AlertList
        alerts={shown}
        onChange={reload}
        empty={all.length ? "No alerts match these filters." : "No anomalies detected yet."}
      />
    </div>
  );
}
