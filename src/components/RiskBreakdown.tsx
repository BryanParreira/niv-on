import type { RiskPart, Severity } from "../api";
import { ruleLabel } from "./AlertList";

const COLOR: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--serious)",
  medium: "var(--warning)",
  low: "var(--good)",
  info: "var(--muted)",
};

/** Stacked bar of what makes up a device's risk score, with a legend. */
export function RiskBreakdown({ parts, score }: { parts: RiskPart[]; score: number }) {
  if (!parts.length) return <div className="muted small">No open alerts or exposures — risk 0.</div>;
  const total = Math.max(100, parts.reduce((s, p) => s + p.points, 0));
  return (
    <div className="risk-breakdown">
      <div className="risk-stack" role="img" aria-label={`Risk ${score} of 100`}>
        {parts.map((p, i) => (
          <span key={i} title={`${p.kind === "alert" ? ruleLabel(p.source) : p.source}: ${p.points.toFixed(1)} pts`}
            style={{ width: `${(p.points / total) * 100}%`, background: COLOR[p.severity], opacity: p.kind === "exposure" ? 0.55 : 1 }} />
        ))}
        <i style={{ left: "100%" }} />
      </div>
      <div className="risk-legend">
        {parts.map((p, i) => (
          <div key={i} className="risk-legend-row">
            <span className="swatch" style={{ background: COLOR[p.severity], opacity: p.kind === "exposure" ? 0.55 : 1 }} />
            <span className="ellipsis">{p.kind === "alert" ? ruleLabel(p.source) : p.source}</span>
            <span className="muted small">{p.kind === "alert" ? `${p.count} open alert${p.count === 1 ? "" : "s"}` : "exposure"}</span>
            <span className="num">{p.points.toFixed(0)}</span>
          </div>
        ))}
        <div className="risk-legend-row total">
          <span />
          <span>Risk score (capped at 100)</span>
          <span />
          <span className="num">{score}</span>
        </div>
      </div>
    </div>
  );
}
