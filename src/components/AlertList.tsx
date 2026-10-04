import { useState } from "react";
import { ACCEPTABLE_RULES, api, type Alert, type AlertStatus } from "../api";
import { dateTime } from "../format";
import { Icon } from "./Icon";
import { useNav } from "../nav";
import { useLive } from "../store";
import { SeverityBadge } from "./Severity";
import { AlertDetail } from "./AlertDetail";

const RULE_LABEL: Record<string, string> = {
  "new-destination": "New destination",
  "unexpected-port": "Unexpected port",
  "risky-port": "Risky port",
  "volume-spike": "Volume spike",
  "connection-burst": "Connection burst",
  "unusual-time": "Unusual time",
  "deauth-flood": "Deauth flood",
  "new-device": "New device",
  "threat-intel": "Threat intel match",
  "suspicious-domain": "Suspicious domain (DGA)",
  "arp-spoof": "ARP spoofing",
  "ip-conflict": "IP conflict",
  "rogue-router": "Rogue IPv6 router",
  "risk-threshold": "Risk threshold",
  "custom-detection": "Custom detection",
  "ids-signature": "Signature (IDS)",
  "fingerprint-change": "Fingerprint change",
  "identity-change": "Identity change",
  "peer-anomaly": "Peer-group anomaly",
};

export const ruleLabel = (r: string) => RULE_LABEL[r] ?? r;

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: "New",
  "in-progress": "In progress",
  resolved: "Resolved",
  "false-positive": "False positive",
};

interface Props {
  alerts: Alert[];
  onChange: () => void;
  compact?: boolean;
  /** Hide the device link (when already on that device's page). */
  hideDevice?: boolean;
  empty?: string;
  /** Incident review: row checkboxes. */
  selected?: Set<number>;
  onSelect?: (id: number, on: boolean) => void;
}

function Investigation({ a, onChange }: { a: Alert; onChange: () => void }) {
  const [note, setNote] = useState("");
  const [owner, setOwner] = useState(a.owner ?? "");
  async function addNote() {
    if (!note.trim()) return;
    await api.updateAlerts([a.id], { note });
    setNote("");
    onChange();
  }
  return (
    <div className="investigation">
      <div className="row" style={{ gap: 8 }}>
        <span className="small dim">Owner</span>
        <input className="input" value={owner} placeholder="Unassigned" style={{ width: 180 }} onChange={(e) => setOwner(e.target.value)}
          onBlur={() => owner !== (a.owner ?? "") && api.updateAlerts([a.id], { owner }).then(onChange)} />
      </div>
      <div className="notes">
        {a.notes.length === 0 && <div className="muted small">No notes yet.</div>}
        {a.notes.map((n, i) => (
          <div key={i} className="note">
            <span className="mono muted small">{dateTime(n.ts)}</span>
            <span className="small">{n.text}</span>
          </div>
        ))}
      </div>
      <form className="row" style={{ gap: 8 }} onSubmit={(e) => { e.preventDefault(); addNote(); }}>
        <input className="input" value={note} placeholder="Add an investigation note…" style={{ flex: 1 }} onChange={(e) => setNote(e.target.value)} />
        <button className="btn sm" type="submit" disabled={!note.trim()}>Add note</button>
      </form>
    </div>
  );
}

export function AlertList({ alerts, onChange, compact, hideDevice, empty = "No alerts.", selected, onSelect }: Props) {
  const nav = useNav();
  const { status } = useLive();
  const [open, setOpen] = useState<number | null>(null);
  const [detail, setDetail] = useState<number | null>(null);
  const detailAlert = alerts.find((a) => a.id === detail);
  if (alerts.length === 0)
    return (
      <div className="empty">
        <Icon name="shield" size={28} />
        {empty}
      </div>
    );
  const setStatus = (a: Alert, status: AlertStatus) => api.updateAlerts([a.id], { status }).then(onChange);
  return (
    <div>
      {detailAlert && <AlertDetail alert={detailAlert} onClose={() => setDetail(null)} onChange={onChange} />}
      {alerts.map((a) => {
        const urg = a.urgency ?? a.severity;
        return (
          <div key={a.id} className={`alert-row ${urg} ${a.acknowledged ? "acked" : ""} ${compact ? "compact" : ""}`}>
            {!compact && (
              <div className="row" style={{ gap: 8, flexWrap: "nowrap", alignItems: "flex-start" }}>
                {onSelect && (
                  <input type="checkbox" checked={selected?.has(a.id) ?? false} onChange={(e) => onSelect(a.id, e.target.checked)} aria-label="Select alert" />
                )}
                <SeverityBadge s={urg} />
              </div>
            )}
            <div style={{ minWidth: 0 }}>
              {compact && <div style={{ marginBottom: 4 }}><SeverityBadge s={urg} /></div>}
              <button className="alert-title linkish-plain" onClick={() => setDetail(a.id)} title="Open details">{a.title}</button>
              {!compact && <div className="alert-msg">{a.message}</div>}
              <div className="alert-meta">
                <span>{dateTime(a.ts)}</span>
                {!compact && <span className={`chip ${a.status === "new" ? "accent" : ""}`}>{STATUS_LABEL[a.status]}</span>}
                {!compact && a.owner && <span><Icon name="user" size={11} /> {a.owner}</span>}
                {!compact && <span>{ruleLabel(a.rule)}</span>}
                {!compact && urg !== a.severity && <span title="Urgency = severity adjusted by the device's asset priority">severity {a.severity}</span>}
                {!compact && a.mitreId && (
                  <span className="chip mono" title={`MITRE ATT&CK · ${a.tactic ?? ""}: ${a.mitreName ?? ""}`}>
                    {a.mitreId} · {a.mitreName}
                  </span>
                )}
                {a.device && !hideDevice && (
                  <button className="linkish" onClick={() => nav.openDevice(a.device!)}>
                    {a.deviceLabel ?? a.device}
                  </button>
                )}
                {a.remote && !compact && <span className="mono">{a.remote}{a.port != null ? `:${a.port}` : ""}</span>}
                {!compact && a.evidence && (
                  <button className="linkish" title={a.evidence} onClick={() => api.revealPath(a.evidence!).catch((e) => alert(String(e)))}>
                    <Icon name="file" size={11} /> evidence.pcap
                  </button>
                )}
                {!compact && !a.evidence && a.device && status?.evidence && (
                  <button className="linkish" title="Save the device's last two minutes of packets as a pcap"
                    onClick={() => api.saveEvidence(a.id).then(onChange).catch((e) => alert(String(e)))}>
                    Save evidence
                  </button>
                )}
                {!compact && (
                  <button className="linkish" onClick={() => setOpen(open === a.id ? null : a.id)}>
                    {open === a.id ? "Hide investigation" : `Investigate${a.notes.length ? ` (${a.notes.length})` : ""}`}
                  </button>
                )}
              </div>
              {open === a.id && <Investigation a={a} onChange={onChange} />}
            </div>
            <div className="alert-actions">
              {compact ? (
                !a.acknowledged && (
                  <button className="btn sm" onClick={() => setStatus(a, "resolved")} title="Resolve">Resolve</button>
                )
              ) : (
                <>
                  <select className="select" value={a.status} onChange={(e) => setStatus(a, e.target.value as AlertStatus)} aria-label="Status">
                    {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                  </select>
                  {ACCEPTABLE_RULES.has(a.rule) && a.device && !a.acknowledged && (
                    <button
                      className="btn sm ghost"
                      onClick={() => api.acceptAlert(a.id).then(onChange)}
                      title="Close as false positive and add this host/port/volume to the device's baseline so it no longer alerts"
                    >
                      Mark as normal
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
