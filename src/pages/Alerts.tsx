import { useMemo, useState } from "react";
import { api, type AlertStatus, type Severity } from "../api";
import { AlertList, ruleLabel, STATUS_LABEL } from "../components/AlertList";
import { Icon } from "../components/Icon";
import { SEVERITY_ORDER } from "../components/Severity";
import { usePoll } from "../store";

type View = "open" | AlertStatus | "all";
const VIEWS: { id: View; label: string }[] = [
  { id: "open", label: "Open" },
  { id: "new", label: "New" },
  { id: "in-progress", label: "In progress" },
  { id: "resolved", label: "Resolved" },
  { id: "false-positive", label: "False positive" },
  { id: "all", label: "All" },
];

/** Incident review (Splunk ES style): triage queue with urgency, status, owner and notes. */
export function Alerts() {
  const [alerts, reload] = usePoll(() => api.getAlerts(2000), 2000);
  const [view, setView] = useState<View>("open");
  const [urg, setUrg] = useState<Severity | "all">("all");
  const [rule, setRule] = useState<string>("all");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [owner, setOwner] = useState("");

  const all = alerts ?? [];
  const rules = useMemo(() => [...new Set(all.map((a) => a.rule))].sort(), [all]);
  const inView = (s: AlertStatus, v: View) => v === "all" || (v === "open" ? s === "new" || s === "in-progress" : s === v);
  const ql = q.trim().toLowerCase();
  const shown = all.filter(
    (a) =>
      inView(a.status, view) &&
      (urg === "all" || (a.urgency ?? a.severity) === urg) &&
      (rule === "all" || a.rule === rule) &&
      (!ql || `${a.title} ${a.message} ${a.deviceLabel ?? ""} ${a.remote ?? ""} ${a.owner ?? ""} ${a.mitreId ?? ""}`.toLowerCase().includes(ql)),
  );
  const count = (v: View) => all.filter((a) => inView(a.status, v)).length;
  const countUrg = (s: Severity) => all.filter((a) => inView(a.status, view) && (a.urgency ?? a.severity) === s).length;
  const sel = [...selected].filter((id) => shown.some((a) => a.id === id));

  function toggle(id: number, on: boolean) {
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });
  }
  async function bulk(patch: { status?: AlertStatus; owner?: string }) {
    await api.updateAlerts(sel, patch);
    setSelected(new Set());
    reload();
  }

  return (
    <>
      <div className="tabs">
        {VIEWS.map((v) => (
          <button key={v.id} className={view === v.id ? "on" : ""} onClick={() => { setView(v.id); setSelected(new Set()); }}>
            {v.label}
            <span className="badge">{count(v.id)}</span>
          </button>
        ))}
      </div>
      <div className="card">
        <div className="card-head" style={{ gap: 12 }}>
          <div className="chips">
            <button className={`chip ${urg === "all" ? "on" : ""}`} onClick={() => setUrg("all")}>All urgencies</button>
            {SEVERITY_ORDER.map((s) => (
              <button key={s} className={`chip ${urg === s ? "on" : ""}`} onClick={() => setUrg(s)}>
                {s} <span className="muted num">{countUrg(s)}</span>
              </button>
            ))}
          </div>
          <select className="select" value={rule} onChange={(e) => setRule(e.target.value)} aria-label="Rule">
            <option value="all">All rules</option>
            {rules.map((r) => <option key={r} value={r}>{ruleLabel(r)}</option>)}
          </select>
          <div className="right">
            <div className="search">
              <Icon name="search" size={14} />
              <input className="input" style={{ width: 220 }} placeholder="Title, device, owner, T-id…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <button className="btn danger" onClick={() => confirm("Delete all alerts permanently?") && api.clearAlerts().then(reload)}>Clear</button>
          </div>
        </div>

        <div className="bulkbar">
          <label className="toggle small">
            <input type="checkbox" checked={sel.length > 0 && sel.length === shown.length}
              onChange={(e) => setSelected(e.target.checked ? new Set(shown.map((a) => a.id)) : new Set())} aria-label="Select all" />
            {sel.length ? `${sel.length} selected` : "Select all"}
          </label>
          {sel.length > 0 && (
            <>
              {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => (
                <button key={s} className="btn sm" onClick={() => bulk({ status: s })}>{STATUS_LABEL[s]}</button>
              ))}
              <form className="row" style={{ gap: 6 }} onSubmit={(e) => { e.preventDefault(); bulk({ owner }); }}>
                <input className="input" placeholder="Assign to…" value={owner} style={{ width: 140 }} onChange={(e) => setOwner(e.target.value)} />
                <button className="btn sm" type="submit">Assign</button>
              </form>
            </>
          )}
        </div>

        <AlertList
          alerts={shown}
          onChange={reload}
          selected={selected}
          onSelect={toggle}
          empty={all.length ? "Nothing in this queue." : "No anomalies detected yet."}
        />
      </div>
    </>
  );
}
