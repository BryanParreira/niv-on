import { ACCEPTABLE_RULES, api, type Alert } from "../api";
import { dateTime } from "../format";
import { Icon } from "./Icon";
import { useNav } from "../nav";
import { SeverityBadge } from "./Severity";

const RULE_LABEL: Record<string, string> = {
  "new-destination": "New destination",
  "unexpected-port": "Unexpected port",
  "risky-port": "Risky port",
  "volume-spike": "Volume spike",
  "connection-burst": "Connection burst",
  "unusual-time": "Unusual time",
  "deauth-flood": "Deauth flood",
  "new-device": "New device",
};

export const ruleLabel = (r: string) => RULE_LABEL[r] ?? r;

interface Props {
  alerts: Alert[];
  onChange: () => void;
  compact?: boolean;
  /** Hide the device link (when already on that device's page). */
  hideDevice?: boolean;
  empty?: string;
}

export function AlertList({ alerts, onChange, compact, hideDevice, empty = "No alerts." }: Props) {
  const nav = useNav();
  if (alerts.length === 0)
    return (
      <div className="empty">
        <Icon name="shield" size={28} />
        {empty}
      </div>
    );
  return (
    <div>
      {alerts.map((a) => (
        <div key={a.id} className={`alert-row ${a.severity} ${a.acknowledged ? "acked" : ""} ${compact ? "compact" : ""}`}>
          {!compact && <SeverityBadge s={a.severity} />}
          <div style={{ minWidth: 0 }}>
            {compact && <div style={{ marginBottom: 4 }}><SeverityBadge s={a.severity} /></div>}
            <div className="alert-title">{a.title}</div>
            {!compact && <div className="alert-msg">{a.message}</div>}
            <div className="alert-meta">
              <span>{dateTime(a.ts)}</span>
              {!compact && <span>{ruleLabel(a.rule)}</span>}
              {a.device && !hideDevice && (
                <button className="linkish" onClick={() => nav.openDevice(a.device!)}>
                  {a.deviceLabel ?? a.device}
                </button>
              )}
              {a.remote && !compact && <span className="mono">{a.remote}{a.port != null ? `:${a.port}` : ""}</span>}
            </div>
          </div>
          <div className="alert-actions">
            {!a.acknowledged && (
              <button className="btn sm" onClick={() => api.ackAlert(a.id).then(onChange)} title="Acknowledge">
                Ack
              </button>
            )}
            {!compact && ACCEPTABLE_RULES.has(a.rule) && a.device && (
              <button
                className="btn sm ghost"
                onClick={() => api.acceptAlert(a.id).then(onChange)}
                title="Add this host/port/volume to the device's baseline so it no longer alerts"
              >
                Mark as normal
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
