export function fmtBytes(b: number, digits = 1): string {
  if (!isFinite(b)) return "–";
  const units = ["B", "kB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1000 && i < units.length - 1) {
    b /= 1000;
    i++;
  }
  return `${i === 0 ? Math.round(b) : b.toFixed(digits)} ${units[i]}`;
}

export const fmtRate = (bps: number) => `${fmtBytes(bps)}/s`;

export function fmtNum(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e4) return `${(n / 1e3).toFixed(1)}k`;
  return n.toLocaleString();
}

/** "12s ago" relative to the engine clock (packet time). */
export function ago(iso: string, clock: string | number = Date.now()): string {
  const now = typeof clock === "number" ? clock : Date.parse(clock);
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 5) return "now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function clockTime(iso: string | number): string {
  const d = typeof iso === "number" ? new Date(iso) : new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export type Presence = "active" | "idle" | "gone";
export function presence(lastSeen: string, clock: string): Presence {
  const s = (Date.parse(clock) - Date.parse(lastSeen)) / 1000;
  if (s < 60) return "active";
  if (s < 600) return "idle";
  return "gone";
}

/** 0-4 bars from dBm. */
export function signalBars(rssi: number | null): number {
  if (rssi == null) return 0;
  if (rssi >= -55) return 4;
  if (rssi >= -65) return 3;
  if (rssi >= -75) return 2;
  return 1;
}
