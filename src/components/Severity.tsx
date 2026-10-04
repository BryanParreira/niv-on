import type { Severity } from "../api";
import { Icon } from "./Icon";

const ICON: Record<Severity, string> = {
  critical: "octagon",
  high: "alerts",
  medium: "alerts",
  low: "info",
  info: "info",
};

/** Severity is always icon + label, never color alone. */
export function SeverityBadge({ s }: { s: Severity }) {
  return (
    <span className={`sev ${s}`}>
      <Icon name={ICON[s]} size={12} />
      {s}
    </span>
  );
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
