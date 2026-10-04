import { useLayoutEffect, useMemo, useRef, useState } from "react";
import type { DeviceSummary, TopoEdge, TopoNode } from "../api";
import { fmtBytes, presence } from "../format";
import { useNav } from "../nav";
import { Avatar, classIcon, Icon } from "./Icon";

interface Props {
  devices: DeviceSummary[];
  topo: { nodes: TopoNode[]; edges: TopoEdge[] };
  clock: string;
}

interface Line {
  d: string;
  bad: boolean;
  width: number;
}

const GROUP_ORDER = ["Smart Camera", "Thermostat", "Smart Speaker", "Media / TV", "Smart Lighting", "Smart Home Hub/Plug", "IoT Module", "Printer", "Phone / Tablet", "Phone / Laptop", "Laptop / PC", "Game Console", "Network Device", "Single-board Computer", "Unknown"];

function riskTone(d: DeviceSummary): string {
  if (d.risk >= 80) return "critical";
  if (d.risk >= 50) return "high";
  if (d.risk >= 20 || d.openAlerts > 0) return "medium";
  return "";
}

/** Tiered network diagram: internet, router / access points, device groups. */
export function NetworkDiagram({ devices, topo, clock }: Props) {
  const nav = useNav();
  const wrap = useRef<HTMLDivElement>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [focus, setFocus] = useState<string | null>(null);

  const router = useMemo(() => devices.find((d) => d.isGateway), [devices]);
  const aps = useMemo(() => devices.filter((d) => d.isAp && !d.isGateway), [devices]);
  // Devices that are actually on this network (seen with an address), not passers-by.
  const members = useMemo(() => devices.filter((d) => !d.isGateway && !d.isAp && (d.ips.length > 0 || d.isSelf)), [devices]);

  const suspiciousBy = useMemo(() => {
    const m = new Map<string, string[]>();
    const label = new Map(topo.nodes.map((n) => [n.id, n.label]));
    for (const e of topo.edges.filter((e) => e.kind === "internet" && e.suspicious)) {
      m.set(e.from, [...(m.get(e.from) ?? []), label.get(e.to) ?? e.to]);
    }
    return m;
  }, [topo]);

  const groups = useMemo(() => {
    const g = new Map<string, DeviceSummary[]>();
    for (const d of members) g.set(d.class, [...(g.get(d.class) ?? []), d]);
    return [...g.entries()]
      .map(([cls, list]) => ({ cls, list: list.sort((a, b) => b.risk - a.risk || a.label.localeCompare(b.label)) }))
      .sort((a, b) => {
        const ia = GROUP_ORDER.indexOf(a.cls), ib = GROUP_ORDER.indexOf(b.cls);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || b.list.length - a.list.length;
      });
  }, [members]);

  const internet = useMemo(() => {
    const byHost = new Map<string, { label: string; bytes: number; devices: Set<string>; bad: boolean }>();
    const label = new Map(topo.nodes.map((n) => [n.id, n.label]));
    for (const e of topo.edges.filter((e) => e.kind === "internet")) {
      const h = byHost.get(e.to) ?? { label: label.get(e.to) ?? e.to, bytes: 0, devices: new Set<string>(), bad: false };
      h.bytes += e.bytes;
      h.devices.add(e.from);
      h.bad ||= e.suspicious;
      byHost.set(e.to, h);
    }
    return [...byHost.entries()].sort((a, b) => Number(b[1].bad) - Number(a[1].bad) || b[1].bytes - a[1].bytes).slice(0, 14);
  }, [topo]);

  const atRisk = members.filter((d) => d.risk >= 20 || d.openAlerts > 0).length;

  // Draw connectors between the rendered boxes.
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const draw = () => {
      const base = el.getBoundingClientRect();
      const box = (sel: string) => {
        const n = el.querySelector(sel);
        if (!n) return null;
        const r = n.getBoundingClientRect();
        return { x: r.left - base.left + r.width / 2, top: r.top - base.top, bottom: r.bottom - base.top };
      };
      const curve = (a: { x: number; y: number }, b: { x: number; y: number }) => {
        const my = (a.y + b.y) / 2;
        return `M${a.x},${a.y} C${a.x},${my} ${b.x},${my} ${b.x},${b.y}`;
      };
      const out: Line[] = [];
      const inet = box("[data-node=internet]");
      const hub = box("[data-node=router]");
      if (inet && hub) out.push({ d: curve({ x: inet.x, y: inet.bottom }, { x: hub.x, y: hub.top }), bad: internet.some(([, h]) => h.bad), width: 2.5 });
      el.querySelectorAll<HTMLElement>("[data-node^=ap-]").forEach((n) => {
        const r = n.getBoundingClientRect();
        if (hub) out.push({ d: curve({ x: hub.x, y: hub.bottom }, { x: r.left - base.left + r.width / 2, y: r.top - base.top }), bad: false, width: 1.5 });
      });
      const lan = box("[data-node=lan]");
      if (lan && hub) {
        const bad = groups.some((g) => g.list.some((d) => suspiciousBy.has(d.mac) || d.risk >= 50));
        out.push({ d: curve({ x: hub.x, y: hub.bottom }, { x: hub.x, y: lan.top }), bad, width: 3 });
      }
      // Only update when geometry actually changed (avoids render loops).
      setLines((prev) => (JSON.stringify(prev) === JSON.stringify(out) ? prev : out));
      setSize((prev) => (prev.w === el.scrollWidth && prev.h === el.scrollHeight ? prev : { w: el.scrollWidth, h: el.scrollHeight }));
    };
    draw();
    const ro = new ResizeObserver(draw);
    ro.observe(el);
    return () => ro.disconnect();
  }, [groups, internet, suspiciousBy, aps]);

  const focusSet = focus ? new Set([focus]) : null;

  return (
    <div className="diagram" ref={wrap}>
      <svg className="diagram-lines" width={size.w} height={size.h} aria-hidden="true">
        {lines.map((l, i) => (
          <path key={i} d={l.d} fill="none" stroke={l.bad ? "var(--critical)" : "var(--rule-strong)"} strokeWidth={l.width} strokeDasharray={l.bad ? "6 4" : undefined} />
        ))}
      </svg>

      <div className="tier">
        <div className="dnode internet" data-node="internet">
          <div className="dnode-head"><Icon name="globe" size={16} /> Internet <span className="muted small">· top destinations</span></div>
          {internet.length === 0 ? (
            <div className="muted small">No internet traffic attributed yet.</div>
          ) : (
            <div className="hosts">
              {internet.map(([ip, h]) => (
                <span key={ip} className={`host ${h.bad ? "bad" : ""}`} title={`${ip} · ${fmtBytes(h.bytes)} · ${h.devices.size} device(s)${h.bad ? " · not in baseline / alerted" : ""}`}>
                  {h.bad && <Icon name="alerts" size={11} />} {h.label}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="tier">
        <button className="dnode hub" data-node="router" onClick={() => router && nav.openDevice(router.mac)} disabled={!router}>
          <div className="dnode-head"><Icon name="router" size={18} /> {router ? router.label : "Router not identified yet"}</div>
          {!router && <div className="muted small">Start a live capture on the interface that carries your internet connection.</div>}
          {router && <div className="muted small mono">{router.ips.find((i) => i.includes(".")) ?? router.mac} · {router.vendor ?? "unknown vendor"}</div>}
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
          const bad = g.list.some((d) => suspiciousBy.has(d.mac) || d.risk >= 50);
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
                  const bad = suspiciousBy.get(d.mac);
                  return (
                    <button key={d.mac} className={`gdev ${riskTone(d)} ${focusSet && !focusSet.has(d.mac) ? "dim" : ""}`}
                      onClick={() => nav.openDevice(d.mac)} onMouseEnter={() => setFocus(d.mac)} onMouseLeave={() => setFocus(null)}
                      title={`${d.label}\n${d.ips[0] ?? d.mac}${d.vendor ? ` · ${d.vendor}` : ""}${bad ? `\nSuspicious destinations: ${bad.join(", ")}` : ""}`}>
                      <span className={`dot ${p === "active" ? "live" : p === "idle" ? "idle" : ""}`} />
                      <Avatar cls={d.class} iot={d.isIot} self={d.isSelf} />
                      <span className="gdev-text">
                        <span className="ellipsis">{d.label}</span>
                        <span className="muted small mono ellipsis">{d.ips.find((i) => i.includes(".")) ?? d.ips[0] ?? d.mac}</span>
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
        <span><i className="lg-line" /> network path (thicker = more traffic)</span>
        <span><i className="lg-line bad" /> path carrying a device with risk ≥ 50 or a suspicious destination (red-framed group)</span>
        <span><span className="dot live" /> active <span className="dot idle" style={{ marginLeft: 8 }} /> idle</span>
        <span>numbers = risk score</span>
      </div>
    </div>
  );
}
