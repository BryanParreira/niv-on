// User detections: saved searches evaluated every minute; results raise alerts.
import { api, type Detection } from "./api";
import { executeSearch } from "./searchData";

export interface RunResult {
  ts: number;
  matches: number;
  raised: number;
  error?: string;
}

/** Last outcome per detection id (for the Detections page). */
export const lastRuns = new Map<string, RunResult>();

const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

export async function runDetection(d: Detection): Promise<RunResult> {
  let out: RunResult;
  try {
    const r = await executeSearch(d.query);
    const macs = [...new Set(r.rows.map((row) => String(row.mac ?? row.device ?? row.src ?? "")).filter((m) => MAC.test(m)))];
    let raised = 0;
    if (r.rows.length > 0) {
      const sample = r.columns.slice(0, 4).map((c) => `${c}=${String(r.rows[0][c] ?? "")}`).join(" ");
      const message = `Search matched ${r.rows.length} result${r.rows.length === 1 ? "" : "s"} (e.g. ${sample}). Query: ${d.query}`;
      raised = await api.raiseDetection(d.name, d.severity, message, macs, d.throttleMinutes);
    }
    out = { ts: Date.now(), matches: r.rows.length, raised };
  } catch (e) {
    out = { ts: Date.now(), matches: 0, raised: 0, error: e instanceof Error ? e.message : String(e) };
  }
  lastRuns.set(d.id, out);
  return out;
}

export async function runAllDetections(): Promise<void> {
  const s = await api.getSettings();
  for (const d of s.library.detections.filter((x) => x.enabled)) {
    await runDetection(d);
  }
}

export const STARTER_DETECTIONS: Omit<Detection, "id">[] = [
  { name: "Critical asset at risk", query: "index=devices priority=critical risk>=20 | table label mac risk", severity: "high", enabled: true, throttleMinutes: 60 },
  { name: "Telnet on the network", query: "index=feed protocol=Telnet | stats count by src | rename src as mac", severity: "high", enabled: true, throttleMinutes: 60 },
  { name: "Unknown device with many peers", query: "index=devices class=Unknown hosts>20 | table label mac hosts", severity: "medium", enabled: true, throttleMinutes: 240 },
  { name: "Repeat offender", query: "index=devices alerts>=5 | table label mac alerts risk", severity: "medium", enabled: true, throttleMinutes: 240 },
];
