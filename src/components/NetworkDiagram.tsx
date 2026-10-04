import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api, type Alert, type DeviceSummary, type Threat, type Topology } from "../api";
import { ago, fmtBytes, presence } from "../format";
import { useNav } from "../nav";
import { AlertDetail } from "./AlertDetail";
import { ruleLabel } from "./AlertList";
import { Avatar, classIcon, Icon } from "./Icon";
import { SeverityBadge } from "./Severity";

interface Props {
  devices: DeviceSummary[];
  topo: Topology;
  clock: string;
}

/** Bytes per second in each direction, from the device's point of view. */
interface Rate {
  up: number;
  down: number;
}

interface Line {
  d: string;
  /** "bad" = threat path, "focus" = hovered device's path. */
  tone: "" | "bad" | "focus";
  width: number;
  rate?: Rate;
  /** Downward paths carry downloads; flip for paths drawn bottom-up. */
  over?: boolean;
}

interface Label {
  x: number;
  y: number;
  text: string;
  tone: "" | "bad";
}

const GROUP_ORDER = ["Smart Camera", "Thermostat", "Smart Speaker", "Media / TV", "Smart Lighting", "Smart Home Hub/Plug", "IoT Module", "Printer", "Phone / Tablet", "Phone / Laptop", "Laptop / PC", "Game Console", "Network Device", "Single-board Computer", "Unknown"];
const ZERO: Rate = { up: 0, down: 0 };

const fmtRate = (b: number) => `${fmtBytes(b)}/s`;
const total = (r?: Rate) => (r ? r.up + r.down : 0);
const rateText = (r?: Rate) => (r && total(r) >= 1 ? `↓ ${fmtRate(r.down)} · ↑ ${fmtRate(r.up)}` : "");

/** Stroke width grows with the log of the current rate. */
const widthFor = (bps: number, min = 1.5) => Math.min(7, min + Math.log10(1 + bps) * 0.9);

/** Animation speed tier for the moving-dots overlay. */
function speed(bps: number): string {
  if (bps >= 1e6) return "fast";
  if (bps >= 1e5) return "med";
  if (bps >= 500) return "slow";
  return bps >= 1 ? "idle" : "";
}

function riskTone(d: DeviceSummary): string {
  if (d.risk >= 80) return "critical";
  if (d.risk >= 50) return "high";
  if (d.risk >= 20 || d.openAlerts > 0) return "medium";
  return "";
}

/** Per-key byte-rate tracker across polls (counters may reset → clamp at 0). */
function useRates<T>(items: T[], key: (t: T) => string, tx: (t: T) => number, rx: (t: T) => number): Map<string, Rate> {
  const prev = useRef<{ t: number; v: Map<string, [number, number]> } | null>(null);
  const [rates, setRates] = useState<Map<string, Rate>>(new Map());
  useEffect(() => {
    const now = performance.now();
    const v = new Map(items.map((i) => [key(i), [tx(i), rx(i)] as [number, number]]));
    const p = prev.current;
    prev.current = { t: now, v };
    if (!p) return;
    const dt = (now - p.t) / 1000;
    if (dt < 0.5) return;
    const out = new Map<string, Rate>();
    for (const [k, [t, r]] of v) {
      const o = p.v.get(k);
      if (!o) continue;
      const up = Math.max(0, t - o[0]) / dt;
      const down = Math.max(0, r - o[1]) / dt;
      if (up + down > 0) out.set(k, { up, down });
    }
    setRates(out);
    // Only recompute when the polled data changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);
  return rates;
}

/** Tiered network diagram: threats, internet, router / access points, device groups — with live traffic. */
export function NetworkDiagram({ devices, topo, clock }: Props) {
  const nav = useNav();
  const wrap = useRef<HTMLDivElement>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const [labels, setLabels] = useState<Label[]>([]);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [focus, setFocus] = useState<string | null>(null);
  const [focusThreat, setFocusThreat] = useState<string | null>(null);
  const [openAlert, setOpenAlert] = useState<Alert | null>(null);
  const [showAllThreats, setShowAllThreats] = useState(false);

  const router = useMemo(() => devices.find((d) => d.isGateway), [devices]);
  const aps = useMemo(() => devices.filter((d) => d.isAp && !d.isGateway), [devices]);
  // Devices that are actually on this network (seen with an address), not passers-by.
  const members = useMemo(() => devices.filter((d) => !d.isGateway && !d.isAp && (d.ips.length > 0 || d.isSelf)), [devices]);

  const devRates = useRates(devices, (d) => d.mac, (d) => d.txBytes, (d) => d.rxBytes);
  const inetEdges = useMemo(() => topo.edges.filter((e) => e.kind === "internet"), [topo]);
  const edgeRates = useRates(inetEdges, (e) => `${e.from}>${e.to}`, (e) => e.tx, (e) => e.rx);

  const threats = useMemo(() => topo.threats ?? [], [topo]);
  const threatByDevice = useMemo(() => {
    const m = new Map<string, Threat[]>();
    for (const t of threats) for (const d of t.devices) m.set(d.mac, [...(m.get(d.mac) ?? []), t]);
    return m;
  }, [threats]);
  const threatIps = useMemo(() => new Set(threats.flatMap((t) => [t.address, t.ip ?? ""])), [threats]);

  const groups = useMemo(() => {
    const g = new Map<string, DeviceSummary[]>();
    for (const d of members) g.set(d.class, [...(g.get(d.class) ?? []), d]);
    return [...g.entries()]
      .map(([cls, list]) => ({ cls, list: list.sort((a, b) => b.risk - a.risk || total(devRates.get(b.mac)) - total(devRates.get(a.mac)) || a.label.localeCompare(b.label)) }))
      .sort((a, b) => {
        const ia = GROUP_ORDER.indexOf(a.cls), ib = GROUP_ORDER.indexOf(b.cls);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || b.list.length - a.list.length;
      });
  }, [members, devRates]);

  // Internet hosts with their totals, current rate and the devices talking to them.
  const internet = useMemo(() => {
    const label = new Map(topo.nodes.map((n) => [n.id, n.label]));
    const byHost = new Map<string, { label: string; bytes: number; rate: Rate; devices: Set<string>; bad: boolean; threat: boolean; ports: Set<number>; last: string | null }>();
    for (const e of inetEdges) {
      const h = byHost.get(e.to) ?? { label: label.get(e.to) ?? e.to, bytes: 0, rate: { ...ZERO }, devices: new Set<string>(), bad: false, threat: threatIps.has(e.to), ports: new Set<number>(), last: null };
      const r = edgeRates.get(`${e.from}>${e.to}`);
      if (r) { h.rate.up += r.up; h.rate.down += r.down; }
      h.bytes += e.bytes;
      h.devices.add(e.from);
      h.bad ||= e.suspicious;
      e.ports.forEach((p) => h.ports.add(p));
      if (e.lastSeen && (!h.last || e.lastSeen > h.last)) h.last = e.lastSeen;
      byHost.set(e.to, h);
    }
    return [...byHost.entries()]
      .sort((a, b) => Number(b[1].threat) - Number(a[1].threat) || Number(b[1].bad) - Number(a[1].bad) || total(b[1].rate) - total(a[1].rate) || b[1].bytes - a[1].bytes)
      .slice(0, 18);
  }, [topo, inetEdges, edgeRates, threatIps]);

  const inetRate = useMemo(() => {
    const r = { ...ZERO };
    for (const v of edgeRates.values()) { r.up += v.up; r.down += v.down; }
    return r;
  }, [edgeRates]);
  const lanRate = useMemo(() => {
    const r = { ...ZERO };
    for (const d of members) { const v = devRates.get(d.mac); if (v) { r.up += v.up; r.down += v.down; } }
    return r;
  }, [members, devRates]);

  // What the hovered device (or threat) is connected to.
  const focusDevices = useMemo(() => {
    if (focusThreat) return new Set(threats.find((t) => t.address === focusThreat)?.devices.map((d) => d.mac) ?? []);
    return focus ? new Set([focus]) : null;
  }, [focus, focusThreat, threats]);
  const focusHosts = useMemo(() => {
    if (focusThreat) {
      const t = threats.find((x) => x.address === focusThreat);
      return new Set([t?.address ?? "", t?.ip ?? ""]);
    }
    if (!focus) return null;
    return new Set(inetEdges.filter((e) => e.from === focus).map((e) => e.to));
  }, [focus, focusThreat, threats, inetEdges]);

  const activeThreat = (t: Threat) => !!t.lastSeen && Date.parse(topo.clock) - Date.parse(t.lastSeen) < 120_000;
  const atRisk = members.filter((d) => d.risk >= 20 || d.openAlerts > 0).length;
  const visibleThreats = showAllThreats ? threats : threats.slice(0, 5);

  async function investigate(t: Threat) {
    try {
      const all = await api.getAlerts(1000);
      const a = all.find((x) => x.id === t.reasons[0]?.alertId);
      if (a) setOpenAlert(a);
      else nav.go("alerts");
    } catch {
      nav.go("alerts");
    }
  }

  // Draw connectors, traffic overlays and rate labels between the rendered boxes.
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const draw = () => {
      const base = el.getBoundingClientRect();
      const rect = (n: Element | null) => {
        if (!n) return null;
        const r = n.getBoundingClientRect();
        return { x: r.left - base.left + r.width / 2, top: r.top - base.top, bottom: r.bottom - base.top, left: r.left - base.left, right: r.right - base.left, midY: r.top - base.top + r.height / 2 };
      };
      const box = (sel: string) => rect(el.querySelector(sel));
      const curve = (a: { x: number; y: number }, b: { x: number; y: number }) => {
        const my = (a.y + b.y) / 2;
        return `M${a.x},${a.y} C${a.x},${my} ${b.x},${my} ${b.x},${b.y}`;
      };
      const out: Line[] = [];
      const lbl: Label[] = [];
      const inet = box("[data-node=internet]");
      const hub = box("[data-node=router]");
      const threat = box("[data-node=threats]");
      if (inet && hub) {
        out.push({ d: curve({ x: inet.x, y: inet.bottom }, { x: hub.x, y: hub.top }), tone: "", width: widthFor(total(inetRate), 2.5), rate: inetRate });
        const t = rateText(inetRate);
        if (t) lbl.push({ x: (inet.x + hub.x) / 2, y: (inet.bottom + hub.top) / 2, text: t, tone: "" });
      }
      if (threat && hub) {
        out.push({ d: curve({ x: threat.x, y: threat.bottom }, { x: hub.x + 30, y: hub.top }), tone: "bad", width: 2, rate: threats.some(activeThreat) ? { up: 1000, down: 1000 } : undefined });
      }
      el.querySelectorAll<HTMLElement>("[data-node^=ap-]").forEach((n) => {
        const r = rect(n)!;
        if (hub) out.push({ d: curve({ x: hub.x, y: hub.bottom }, { x: r.x, y: r.top }), tone: "", width: 1.5 });
      });
      const lan = box("[data-node=lan]");
      if (lan && hub) {
        out.push({ d: curve({ x: hub.x, y: hub.bottom }, { x: hub.x, y: lan.top }), tone: "", width: widthFor(total(lanRate), 3), rate: lanRate });
        const t = rateText(lanRate);
        if (t) lbl.push({ x: hub.x, y: (hub.bottom + lan.top) / 2, text: t, tone: "" });
      }
      // Threat paths: router → each device involved in an open threat.
      if (hub) {
        for (const mac of threatByDevice.keys()) {
          const d = box(`[data-dev="${mac}"]`);
          if (!d) continue;
          const dim = focusDevices && !focusDevices.has(mac);
          if (dim) continue;
          out.push({ d: curve({ x: hub.x + 30, y: hub.bottom }, { x: d.left + 22, y: d.top + 2 }), tone: "bad", width: 1.5, rate: { up: 1000, down: 1000 } });
        }
      }
      // Focused device: device → router → each internet host it talks to.
      if (focus && !focusThreat && hub) {
        const d = box(`[data-dev="${focus}"]`);
        const r = devRates.get(focus);
        if (d) out.push({ d: curve({ x: hub.x - 30, y: hub.bottom }, { x: d.right - 22, y: d.top + 2 }), tone: "focus", width: widthFor(total(r), 2), rate: r });
        el.querySelectorAll<HTMLElement>("[data-host]").forEach((n) => {
          const host = n.dataset.host!;
          if (!focusHosts?.has(host)) return;
          const h = rect(n)!;
          const er = edgeRates.get(`${focus}>${host}`);
          out.push({ d: curve({ x: hub.x - 30, y: hub.top }, { x: h.x, y: h.bottom }), tone: "focus", width: widthFor(total(er), 1.5), rate: er, over: true });
        });
      }
      // Only update when geometry actually changed (avoids render loops).
      setLines((prev) => (JSON.stringify(prev) === JSON.stringify(out) ? prev : out));
      setLabels((prev) => (JSON.stringify(prev) === JSON.stringify(lbl) ? prev : lbl));
      setSize((prev) => (prev.w === el.scrollWidth && prev.h === el.scrollHeight ? prev : { w: el.scrollWidth, h: el.scrollHeight }));
    };
    draw();
    const ro = new ResizeObserver(draw);
    ro.observe(el);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, internet, aps, threats, inetRate, lanRate, focus, focusThreat, focusDevices, focusHosts, devRates, edgeRates, threatByDevice]);

  return (
    <div className="diagram" ref={wrap}>
      {openAlert && <AlertDetail alert={openAlert} onClose={() => setOpenAlert(null)} onChange={() => api.getAlerts(1000).then((all) => setOpenAlert(all.find((x) => x.id === openAlert.id) ?? null))} />}
      <svg className="diagram-lines" width={size.w} height={size.h} aria-hidden="true">
        {lines.map((l, i) => {
          const stroke = l.tone === "bad" ? "var(--critical)" : l.tone === "focus" ? "var(--accent)" : "var(--rule-strong)";
          const r = l.rate;
          // Downloads travel along the path (top → bottom); uploads against it.
          const down = r ? (l.over ? r.up : r.down) : 0;
          const up = r ? (l.over ? r.down : r.up) : 0;
          return (
            <g key={i}>
              <path d={l.d} fill="none" stroke={stroke} strokeWidth={l.width} strokeOpacity={l.tone ? 0.55 : 1} strokeDasharray={l.tone === "bad" ? "6 4" : undefined} />
              {speed(down) && <path d={l.d} fill="none" className={`flow fwd ${speed(down)} ${l.tone}`} strokeWidth={Math.max(2, l.width - 0.5)} />}
              {speed(up) && <path d={l.d} fill="none" className={`flow rev ${speed(up)} ${l.tone}`} strokeWidth={Math.max(1.5, l.width - 1.5)} />}
            </g>
          );
        })}
      </svg>
      {labels.map((l, i) => (
        <span key={i} className={`flow-label ${l.tone}`} style={{ left: l.x, top: l.y }}>{l.text}</span>
      ))}

      <div className="tier">
        <div className="dnode internet" data-node="internet">
          <div className="dnode-head">
            <Icon name="globe" size={16} /> Internet <span className="muted small">· top destinations, live rate</span>
          </div>
          {internet.length === 0 ? (
            <div className="muted small">No internet traffic attributed yet.</div>
          ) : (
            <div className="hosts">
              {internet.map(([ip, h]) => {
                const live = !!h.last && Date.parse(topo.clock) - Date.parse(h.last) < 60_000;
                const dim = focusHosts && !focusHosts.has(ip);
                const r = total(h.rate) >= 1 ? fmtRate(total(h.rate)) : "";
                return (
                  <span key={ip} data-host={ip} className={`host ${h.threat ? "threat" : h.bad ? "bad" : ""} ${dim ? "dim" : ""} ${focusHosts?.has(ip) ? "lit" : ""}`}
                    title={`${h.label}${h.label !== ip ? ` (${ip})` : ""}\n${fmtBytes(h.bytes)} total · ${h.devices.size} device(s)${h.ports.size ? ` · ports ${[...h.ports].join(", ")}` : ""}${h.last ? `\nlast seen ${ago(h.last, topo.clock)}` : ""}${h.threat ? "\nTHREAT — open alert on this address" : h.bad ? "\nnot in baseline / alerted" : ""}`}>
                    {live && <span className={`dot live ${h.threat ? "bad" : ""}`} />}
                    {(h.threat || h.bad) && <Icon name="alerts" size={11} />}
                    <span className="ellipsis">{h.label}</span>
                    {r && <span className="host-rate">{r}</span>}
                  </span>
                );
              })}
            </div>
          )}
        </div>

        {threats.length > 0 && (
          <div className="dnode threats" data-node="threats">
            <div className="dnode-head">
              <Icon name="alerts" size={16} /> Threat addresses
              <span className="muted small">· {threats.length} with open alerts</span>
              <button className="linkish small" style={{ marginLeft: "auto" }} onClick={() => nav.go("alerts")}>All alerts →</button>
            </div>
            <div className="threat-list">
              {visibleThreats.map((t) => {
                const live = activeThreat(t);
                const top = t.reasons[0];
                return (
                  <div key={t.address} className={`threat ${t.severity} ${focusThreat === t.address ? "lit" : ""}`}
                    onMouseEnter={() => setFocusThreat(t.address)} onMouseLeave={() => setFocusThreat(null)}>
                    <div className="threat-head">
                      <SeverityBadge s={t.severity} />
                      <span className="mono threat-addr ellipsis" title={t.address}>{t.address}</span>
                      {t.domain && t.domain !== t.address && <span className="muted small ellipsis" title={t.domain}>{t.domain}</span>}
                      {live && <span className="chip bad-live"><span className="dot live bad" /> active now</span>}
                    </div>
                    <div className="small threat-why">
                      {t.intel ? <><b>Listed on {t.intel}</b>{top ? ` · ${ruleLabel(top.rule)}` : ""}</> : top ? <><b>{ruleLabel(top.rule)}</b> · {top.title}</> : null}
                      {t.reasons.length > 1 && <span className="muted"> · +{t.reasons.length - 1} more alert{t.reasons.length > 2 ? "s" : ""}</span>}
                      {t.internal && <span className="chip" style={{ marginLeft: 6 }}>inside your network</span>}
                    </div>
                    <div className="small muted threat-meta">
                      {t.devices.map((d) => (
                        <button key={d.mac} className="linkish" onClick={() => nav.openDevice(d.mac)}><Icon name="devices" size={11} /> {d.label}</button>
                      ))}
                      {t.tx + t.rx > 0 && <span className="mono">↑ {fmtBytes(t.tx)} ↓ {fmtBytes(t.rx)}</span>}
                      {t.ports.length > 0 && <span className="mono">port{t.ports.length > 1 ? "s" : ""} {t.ports.join(", ")}</span>}
                      {t.lastSeen && <span>last seen {ago(t.lastSeen, topo.clock)}</span>}
                      <button className="linkish" onClick={() => investigate(t)}>Investigate →</button>
                    </div>
                  </div>
                );
              })}
              {threats.length > 5 && (
                <button className="linkish small" onClick={() => setShowAllThreats(!showAllThreats)}>
                  {showAllThreats ? "Show fewer" : `Show all ${threats.length}`}
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="tier">
        <button className="dnode hub" data-node="router" onClick={() => router && nav.openDevice(router.mac)} disabled={!router}>
          <div className="dnode-head"><Icon name="router" size={18} /> {router ? router.label : "Router not identified yet"}</div>
          {!router && <div className="muted small">Start a live capture on the interface that carries your internet connection.</div>}
          {router && <div className="muted small mono">{router.ips.find((i) => i.includes(".")) ?? router.mac} · {router.vendor ?? "unknown vendor"}</div>}
          {total(inetRate) >= 1 && <div className="small mono">internet ↓ {fmtRate(inetRate.down)} · ↑ {fmtRate(inetRate.up)}</div>}
          {router && router.openAlerts > 0 && <span className="sev high">{router.openAlerts} alert{router.openAlerts === 1 ? "" : "s"}</span>}
        </button>
        {aps.slice(0, 4).map((ap) => (
          <button key={ap.mac} className="dnode ap" data-node={`ap-${ap.mac}`} onClick={() => nav.openDevice(ap.mac)}>
            <div className="dnode-head"><Icon name="ap" size={16} /> {ap.label}</div>
            <div className="muted small">{ap.ssid ? `“${ap.ssid}”` : "access point"}{ap.channel ? ` · ch ${ap.channel}` : ""}</div>
          </button>
        ))}
      </div>

      <div className="lan" data-node="lan">
        <div className="lan-head">
          <Icon name="devices" size={16} />
          <b>Local network</b>
          <span className="muted small">· {members.length} device{members.length === 1 ? "" : "s"} in {groups.length} group{groups.length === 1 ? "" : "s"}</span>
          {atRisk > 0 && <span className="sev high" style={{ marginLeft: "auto" }}>{atRisk} need attention</span>}
        </div>
        <div className="groups">
          {groups.map((g) => {
            const alerts = g.list.reduce((s, d) => s + d.openAlerts, 0);
            const bad = g.list.some((d) => threatByDevice.has(d.mac) || d.risk >= 50);
            return (
              <div key={g.cls} className={`dnode group ${bad ? "bad" : ""}`} data-node={`group-${g.cls}`}>
                <div className="dnode-head">
                  <Icon name={classIcon(g.cls)} size={16} /> {g.cls}
                  <span className="muted small">· {g.list.length}</span>
                  {g.list[0]?.isIot && <span className="chip good">IoT</span>}
                  {alerts > 0 && <span className="sev high" style={{ marginLeft: "auto" }}>{alerts}</span>}
                </div>
                <div className="group-list">
                  {g.list.slice(0, 12).map((d) => {
                    const p = presence(d.lastSeen, clock);
                    const th = threatByDevice.get(d.mac);
                    const r = devRates.get(d.mac);
                    const dim = focusDevices && !focusDevices.has(d.mac);
                    return (
                      <button key={d.mac} data-dev={d.mac} className={`gdev ${riskTone(d)} ${th ? "threatened" : ""} ${dim ? "dim" : ""} ${focus === d.mac ? "lit" : ""}`}
                        onClick={() => nav.openDevice(d.mac)} onMouseEnter={() => setFocus(d.mac)} onMouseLeave={() => setFocus(null)}
                        onFocus={() => setFocus(d.mac)} onBlur={() => setFocus(null)}
                        title={`${d.label}\n${d.ips[0] ?? d.mac}${d.vendor ? ` · ${d.vendor}` : ""}${th ? `\nThreat contact: ${th.map((t) => t.address).join(", ")}` : ""}\nHover to trace its traffic`}>
                        <span className={`dot ${p === "active" ? "live" : p === "idle" ? "idle" : ""}`} />
                        <Avatar cls={d.class} iot={d.isIot} self={d.isSelf} />
                        <span className="gdev-text">
                          <span className="ellipsis">{th && <Icon name="alerts" size={11} />} {d.label}</span>
                          <span className="muted small mono ellipsis">
                            {total(r) >= 1 ? `↓ ${fmtRate(r!.down)} ↑ ${fmtRate(r!.up)}` : d.ips.find((i) => i.includes(".")) ?? d.ips[0] ?? d.mac}
                          </span>
                        </span>
                        {d.risk > 0 && <span className={`gdev-risk ${riskTone(d)}`}>{d.risk}</span>}
                      </button>
                    );
                  })}
                  {g.list.length > 12 && <div className="muted small">+{g.list.length - 12} more</div>}
                </div>
              </div>
            );
          })}
          {groups.length === 0 && <div className="empty">No devices with an address yet — start a capture or run Scan network.</div>}
        </div>
      </div>

      <div className="diagram-legend small muted">
        <span><i className="lg-line flowing" /> live traffic (moving dots = data flowing; faster = more)</span>
        <span><i className="lg-line bad" /> threat path: threat address → router → device involved</span>
        <span><i className="lg-line focus" /> hover a device to trace where its traffic goes</span>
        <span><span className="dot live" /> active <span className="dot idle" style={{ marginLeft: 8 }} /> idle</span>
        <span>numbers = risk score · rates refresh every 3 s</span>
      </div>
    </div>
  );
}
