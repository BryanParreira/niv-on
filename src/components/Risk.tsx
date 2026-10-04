/** 0-100 risk score as a short meter + number; tone follows severity bands. */
export function riskTone(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 20) return "medium";
  return "";
}

export function Risk({ score, wide }: { score: number; wide?: boolean }) {
  if (score <= 0) return <span className="muted">—</span>;
  return (
    <span className={`risk ${riskTone(score)}`} title={`Risk ${score}/100 — open alerts, weighted by severity, halving every 24 h`}>
      <span className="risk-track" style={{ width: wide ? 120 : 44 }}>
        <span style={{ width: `${Math.min(100, score)}%` }} />
      </span>
      <span className="num">{score}</span>
    </span>
  );
}
