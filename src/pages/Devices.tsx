import { useMemo, useState } from "react";
import { api, type DeviceSummary } from "../api";
import { Avatar, Icon } from "../components/Icon";
import { Mac } from "../components/Mac";
import { Signal } from "../components/Signal";
import { ago, fmtBytes, presence } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

type SortKey = "label" | "class" | "ip" | "rssi" | "traffic" | "dest" | "lastSeen" | "alerts";
type Filter = "all" | "iot" | "active" | "alerts" | "infra" | "wireless";

const COLS: { key: SortKey; label: string; right?: boolean }[] = [
  { key: "label", label: "Device" },
  { key: "class", label: "Type" },
  { key: "ip", label: "Address" },
  { key: "rssi", label: "Signal" },
  { key: "traffic", label: "Traffic", right: true },
  { key: "dest", label: "Hosts", right: true },
  { key: "lastSeen", label: "Last seen", right: true },
  { key: "alerts", label: "Alerts", right: true },
];

const ipKey = (ip?: string) => (ip ? ip.split(".").map((p) => p.padStart(3, "0")).join(".") : "~");

export function Devices({ onMessage }: { onMessage: (m: string) => void }) {
  const { status } = useLive();
  const nav = useNav();
  const [devices] = usePoll(api.getDevices, 1500);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "lastSeen", desc: true });
  const [scanning, setScanning] = useState(false);
  const clock = status?.clock ?? new Date().toISOString();
  const liveManaged = status?.running && status.session?.source === "live" && !status.session.linktype?.includes("802.11");

  const match = (d: DeviceSummary, f: Filter) => {
    switch (f) {
      case "iot":
        return d.isIot;
      case "active":
        return presence(d.lastSeen, clock) === "active";
      case "alerts":
        return d.openAlerts > 0;
      case "infra":
        return d.isAp || d.isGateway;
      case "wireless":
        return d.rssi != null;
      default:
        return true;
    }
  };

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const list = (devices ?? []).filter((d) => {
      if (!match(d, filter)) return false;
      if (!ql) return true;
      return [d.label, d.mac, d.vendor, d.class, d.ssid, d.hostname, ...d.ips].some((s) => s?.toLowerCase().includes(ql));
    });
    const val = (d: DeviceSummary): number | string => {
      switch (sort.key) {
        case "lastSeen":
          return Date.parse(d.lastSeen);
        case "label":
          return d.label.toLowerCase();
        case "class":
          return d.class.toLowerCase();
        case "ip":
          return ipKey(d.ips.find((i) => i.includes(".")));
        case "rssi":
          return d.rssi ?? -200;
        case "traffic":
          return d.txBytes + d.rxBytes;
        case "dest":
          return d.destinations;
        case "alerts":
          return d.openAlerts;
      }
    };
    return [...list].sort((a, b) => {
      const va = val(a), vb = val(b);
      const c = va < vb ? -1 : va > vb ? 1 : 0;
      return sort.desc ? -c : c;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [devices, q, filter, sort, clock]);

  const count = (f: Filter) => (devices ?? []).filter((d) => match(d, f)).length;
  const chip = (f: Filter, label: string) => (
    <button className={`chip ${filter === f ? "on" : ""}`} onClick={() => setFilter(f)}>
      {label} <span className="muted num">{count(f)}</span>
    </button>
  );

  async function scan() {
    setScanning(true);
    try {
      onMessage(await api.scanNetwork());
    } catch (e) {
      onMessage(String(e));
    } finally {
      setScanning(false);
    }
  }

  function exportCsv() {
    const head = ["label", "mac", "vendor", "class", "tag", "hostname", "ips", "ssid", "rssi", "tx_bytes", "rx_bytes", "hosts", "first_seen", "last_seen", "open_alerts"];
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = rows.map((d) =>
      [d.label, d.mac, d.vendor, d.class, d.tag, d.hostname, d.ips.join(" "), d.ssid, d.rssi, d.txBytes, d.rxBytes, d.destinations, d.firstSeen, d.lastSeen, d.openAlerts].map(esc).join(","),
    );
    navigator.clipboard.writeText([head.join(","), ...lines].join("\n"));
    onMessage(`Copied ${rows.length} devices as CSV to the clipboard.`);
  }

  return (
    <div className="card pad0">
      <div className="card-head" style={{ padding: "16px 16px 0" }}>
        <div className="chips">
          {chip("all", "All")}
          {chip("iot", "IoT")}
          {chip("active", "Active")}
          {chip("alerts", "With alerts")}
          {chip("wireless", "Wireless")}
          {chip("infra", "Routers & APs")}
        </div>
        <div className="right">
          <div className="search">
            <Icon name="search" size={14} />
            <input className="input" style={{ width: 260 }} placeholder="Name, MAC, IP, vendor, SSID…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <button className="btn" onClick={scan} disabled={!liveManaged || scanning}
            title={liveManaged ? "Send ARP requests across your subnet to discover every device" : "Available during a live managed-mode capture"}>
            <Icon name="radar" size={14} /> {scanning ? "Scanning…" : "Scan network"}
          </button>
          <button className="btn ghost icon" onClick={exportCsv} title="Copy as CSV"><Icon name="download" size={14} /></button>
        </div>
      </div>
      <div className="table-wrap" style={{ maxHeight: "calc(100vh - 210px)" }}>
        <table className="t">
          <thead>
            <tr>
              {COLS.map((c) => (
                <th key={c.key} className={`sortable ${c.right ? "r" : ""}`}
                  onClick={() => setSort((s) => ({ key: c.key, desc: s.key === c.key ? !s.desc : c.key !== "label" && c.key !== "class" && c.key !== "ip" }))}>
                  {c.label}{sort.key === c.key ? (sort.desc ? " ↓" : " ↑") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => {
              const p = presence(d.lastSeen, clock);
              return (
                <tr key={d.mac} className="click" onClick={() => nav.openDevice(d.mac)}>
                  <td>
                    <div className="dev-cell">
                      <Avatar cls={d.class} iot={d.isIot} net={d.isGateway || d.isAp} self={d.isSelf} />
                      <div style={{ minWidth: 0 }}>
                        <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                          <span className={`dot ${p === "active" ? "live" : p === "idle" ? "idle" : ""}`}
                            title={p === "active" ? "Active" : p === "idle" ? "Idle" : "Not seen recently"} />
                          <span className="name ellipsis" style={{ maxWidth: 260 }}>{d.label}</span>
                          {d.isSelf && <span className="chip">this computer</span>}
                          {d.isGateway && <span className="chip accent">gateway</span>}
                        </div>
                        <div className="muted small ellipsis" style={{ maxWidth: 340 }}>
                          {d.vendor ?? (d.randomized ? "Randomized MAC" : "Unknown vendor")}
                          {d.ssid ? ` · ${d.isAp ? "SSID" : "on"} “${d.ssid}”` : ""}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="chips">
                      <span className={`chip ${d.tag ? "outline" : ""}`} title={d.tag ? "Your tag" : "Auto-classified"}>{d.class}</span>
                      {d.isIot && <span className="chip good">IoT</span>}
                      {d.learning && <span className="chip">learning</span>}
                    </div>
                  </td>
                  <td>
                    <div className="mono small">{d.ips.find((i) => i.includes(".")) ?? d.ips[0] ?? "—"}</div>
                    <div className="small"><Mac mac={d.mac} /></div>
                  </td>
                  <td><Signal rssi={d.rssi} /></td>
                  <td className="r num">
                    <div>{fmtBytes(d.txBytes + d.rxBytes)}</div>
                    <div className="muted small">↑{fmtBytes(d.txBytes)} ↓{fmtBytes(d.rxBytes)}</div>
                  </td>
                  <td className="r num">{d.destinations}</td>
                  <td className="r muted">{ago(d.lastSeen, clock)}</td>
                  <td className="r">
                    {d.openAlerts > 0 ? <span className="sev high"><Icon name="alerts" size={12} />{d.openAlerts}</span> : <span className="muted">—</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div className="empty">
            <Icon name="devices" size={28} />
            {devices?.length ? "No devices match this filter." : "No devices discovered yet — start a capture from the top bar."}
          </div>
        )}
      </div>
    </div>
  );
}
