// Fetch only the indexes a query needs, then run it.
import { api } from "./api";
import { alertRow, connRow, deviceRow, dnsRow, feedRow, runSearch, type Index, type Result } from "./search";

export async function executeSearch(query: string): Promise<Result> {
  const needs = (i: Index) => new RegExp(`index=${i}\\b`, "i").test(query) || (i === "alerts" && !/index=/i.test(query));
  // Time-bounded indexes: honour `_time>-Nh/-Nd` to pull the right window from the store.
  const rel = /_time>=?-(\d+)([hd])/i.exec(query);
  const hours = rel ? Number(rel[1]) * (rel[2].toLowerCase() === "d" ? 24 : 1) : 24 * 7;
  const [alerts, devices, feed, conn, dns, settings] = await Promise.all([
    needs("alerts") ? api.getAlerts(2000) : Promise.resolve([]),
    needs("devices") || needs("feed") ? api.getDevices() : Promise.resolve([]),
    needs("feed") ? api.getFeed(0) : Promise.resolve([]),
    needs("conn") ? api.getConnections({ hours, limit: 20000 }) : Promise.resolve([]),
    needs("dns") ? api.getDns({ hours, limit: 20000 }) : Promise.resolve([]),
    /lookup\b/i.test(query) ? api.getSettings() : Promise.resolve(null),
  ]);
  const labels = new Map(devices.map((d) => [d.mac, d.label]));
  return runSearch(query, {
    alerts: alerts.map(alertRow),
    devices: devices.map(deviceRow),
    feed: [...feed].reverse().map((f) => feedRow(f, labels)),
    conn: conn.map(connRow),
    dns: dns.map(dnsRow),
  }, settings?.library.lookups ?? []);
}
