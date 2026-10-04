import { Fragment, useState } from "react";
import { api } from "../api";
import { Icon } from "../components/Icon";
import { SeverityBadge } from "../components/Severity";
import { useNav } from "../nav";
import { usePoll } from "../store";

/** Security posture: insecure services, cleartext protocols and known-exploited vendors, per check. */
export function Compliance() {
  const nav = useNav();
  const [checks] = usePoll(api.getCompliance, 5000);
  const [open, setOpen] = useState<string | null>(null);
  const [onlyFailing, setOnlyFailing] = useState(false);

  if (!checks) return <div className="card"><div className="empty">Assessing devices…</div></div>;
  const evaluated = checks[0]?.evaluated ?? 0;
  const failing = checks.filter((c) => c.failing.length > 0);
  const devicesWithFindings = new Set(checks.flatMap((c) => c.failing.map((f) => f[0]))).size;
  const score = evaluated ? Math.round(((checks.length - failing.length) / checks.length) * 100) : 100;
  const shown = onlyFailing ? failing : checks;

  return (
    <>
      <div className="kpis">
        <div className="card kpi">
          <div className="label"><Icon name="clipboard" size={14} />Posture score</div>
          <div className="value">{score}<span className="unit"> %</span></div>
          <div className="foot">{checks.length - failing.length} of {checks.length} checks pass everywhere</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="devices" size={14} />Devices assessed</div>
          <div className="value">{evaluated}</div>
          <div className="foot">devices seen on the network</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="alerts" size={14} />Devices with findings</div>
          <div className="value" style={{ color: devicesWithFindings ? "var(--serious)" : undefined }}>{devicesWithFindings}</div>
          <div className="foot">add to risk scores automatically</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="octagon" size={14} />Failing checks</div>
          <div className="value">{failing.length}</div>
          <div className="foot">{failing.filter((c) => c.severity === "critical" || c.severity === "high").length} high or critical</div>
        </div>
      </div>

      <div className="card pad0">
        <div className="card-head">
          <h2>Checks</h2>
          <span className="sub">from passively observed services, protocols, banners and the CISA KEV catalog</span>
          <div className="right">
            <label className="toggle small"><input type="checkbox" checked={onlyFailing} onChange={(e) => setOnlyFailing(e.target.checked)} />Only failing</label>
            <button className="btn sm ghost" onClick={() => nav.go("intel")}>Update KEV catalog <Icon name="chevron" size={12} /></button>
          </div>
        </div>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Result</th><th>Check</th><th>Severity</th><th className="r">Devices failing</th></tr></thead>
            <tbody>
              {shown.map((c) => (
                <Fragment key={c.id}>
                  <tr className={c.failing.length ? "click" : ""} onClick={() => c.failing.length && setOpen(open === c.id ? null : c.id)}>
                    <td>{c.failing.length ? <span className="sev high"><Icon name="x" size={12} /> fail</span> : <span className="chip good"><Icon name="check" size={11} /> pass</span>}</td>
                    <td>
                      <div className="name">{c.name}</div>
                      <div className="muted small">{c.description}</div>
                    </td>
                    <td><SeverityBadge s={c.severity} /></td>
                    <td className="r num">{c.failing.length} / {c.evaluated} {c.failing.length > 0 && <Icon name={open === c.id ? "down" : "chevron"} size={12} />}</td>
                  </tr>
                  {open === c.id && (
                    <tr>
                      <td />
                      <td colSpan={3}>
                        {c.failing.map(([mac, label, detail]) => (
                          <div key={mac} className="row" style={{ gap: 10, padding: "4px 0", flexWrap: "nowrap" }}>
                            <button className="linkish" onClick={() => nav.openDevice(mac, "security")}>{label}</button>
                            <span className="muted small ellipsis">{detail}</span>
                          </div>
                        ))}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
