import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, inTauri, type TopoEdge, type TopoNode, type Topology } from "../api";
import { classIcon, Icon, ICON_PATHS } from "../components/Icon";
import { NetworkDiagram } from "../components/NetworkDiagram";
import { fmtBytes } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

interface P {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fixed?: boolean;
}

const W = 1200;
const H = 800;

/** Force-directed layout; keeps earlier positions so refreshes don't jump. */
function layout(nodes: TopoNode[], edges: TopoEdge[], prev: Map<string, P>, iterations: number): Map<string, P> {
  const pos = new Map<string, P>();
  nodes.forEach((n, i) => {
    const old = prev.get(n.id);
    if (old) pos.set(n.id, { ...old, vx: 0, vy: 0 });
    else {
      const a = (i / Math.max(1, nodes.length)) * Math.PI * 2;
      const r = n.kind === "internet" ? 360 : n.kind === "router" ? 0 : 200;
      pos.set(n.id, { x: W / 2 + Math.cos(a) * r + Math.random() * 20, y: H / 2 + Math.sin(a) * r + Math.random() * 20, vx: 0, vy: 0 });
    }
  });
  const router = nodes.find((n) => n.kind === "router");
  if (router) Object.assign(pos.get(router.id)!, { x: W / 2, y: H / 2, fixed: true });
  const list = nodes.map((n) => [n, pos.get(n.id)!] as const);
  const springLen = (e: TopoEdge) => (e.kind === "lan" ? 170 : e.kind === "internet" ? 90 : 120);
  for (let it = 0; it < iterations; it++) {
    const cool = 1 - it / iterations;
    for (let i = 0; i < list.length; i++) {
      const [, a] = list[i];
      for (let j = i + 1; j < list.length; j++) {
        const [, b] = list[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          dx = Math.random() - 0.5;
          dy = Math.random() - 0.5;
          d2 = 1;
        }
        if (d2 > 250_000) continue;
        const f = 1800 / d2;
        const d = Math.sqrt(d2);
        a.vx += (dx / d) * f;
        a.vy += (dy / d) * f;
        b.vx -= (dx / d) * f;
        b.vy -= (dy / d) * f;
      }
    }
    for (const e of edges) {
      const a = pos.get(e.from), b = pos.get(e.to);
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      const f = (d - springLen(e)) * 0.02;
      a.vx += (dx / d) * f;
      a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f;
      b.vy -= (dy / d) * f;
    }
    for (const [, p] of list) {
      p.vx += (W / 2 - p.x) * 0.002;
      p.vy += (H / 2 - p.y) * 0.002;
      if (!p.fixed) {
        p.x += Math.max(-20, Math.min(20, p.vx)) * cool;
        p.y += Math.max(-20, Math.min(20, p.vy)) * cool;
      }
      p.vx *= 0.5;
      p.vy *= 0.5;
    }
  }
  return pos;
}

function tone(n: TopoNode): string {
  if (n.kind === "internet") return n.flagged ? "var(--critical)" : "var(--muted)";
  if (n.risk >= 80) return "var(--critical)";
  if (n.risk >= 50) return "var(--serious)";
  if (n.risk >= 20 || n.alerts > 0) return "var(--warning)";
  return "var(--text-2)";
}

/** Network map: who talks to whom, the router, and where traffic leaves the network. */
export function NetworkMap() {
  const nav = useNav();
  const { status } = useLive();
  const [mode, setMode] = useState<"diagram" | "graph">(() => {
    try {
      return (localStorage.getItem("niv.mapMode") as "diagram" | "graph") ?? "diagram";
    } catch {
      return "diagram";
    }
  });
  const [devices] = usePoll(api.getDevices, 3000);
  const [data, setData] = useState<Topology | null>(null);
  const [showInternet, setShowInternet] = useState(true);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hover, setHover] = useState<string | null>(null);
  const [, force] = useState(0);
  const pos = useRef(new Map<string, P>());
  const drag = useRef<{ id?: string; sx: number; sy: number; vx: number; vy: number } | null>(null);
  const svg = useRef<SVGSVGElement>(null);

  const load = useCallback(() => {
    if (inTauri) api.getTopology().then(setData).catch(console.error);
  }, []);
  useEffect(() => {
    load();
    const id = setInterval(load, mode === "diagram" ? 3_000 : 10_000);
    return () => clearInterval(id);
  }, [load, mode]);

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as TopoNode[], edges: [] as TopoEdge[] };
    let edges = data.edges.filter((e) => showInternet || e.kind !== "internet");
    if (onlySuspicious) edges = edges.filter((e) => e.suspicious || e.kind === "lan");
    const used = new Set(edges.flatMap((e) => [e.from, e.to]));
    const nodes = data.nodes.filter((n) => (n.kind === "internet" ? showInternet && used.has(n.id) : true));
    return { nodes, edges };
  }, [data, showInternet, onlySuspicious]);

  // Re-layout when the graph changes (warm start from previous positions).
  useEffect(() => {
    if (!nodes.length || mode !== "graph") return;
    const fresh = nodes.some((n) => !pos.current.has(n.id));
    pos.current = layout(nodes, edges, pos.current, fresh ? 260 : 40);
    force((x) => x + 1);
  }, [nodes, edges, mode]);

  const toSvg = (e: { clientX: number; clientY: number }) => {
    const r = svg.current!.getBoundingClientRect();
    return { x: ((e.clientX - r.left) / r.width) * W, y: ((e.clientY - r.top) / r.height) * H };
  };

  const maxBytes = Math.max(1, ...edges.map((e) => e.bytes));
  const counts = data ? { devices: data.nodes.filter((n) => n.kind !== "internet").length, internet: data.nodes.filter((n) => n.kind === "internet").length, bad: data.edges.filter((e) => e.suspicious).length } : null;
  const hovered = nodes.find((n) => n.id === hover);
  const linked = useMemo(() => new Set(hover ? edges.filter((e) => e.from === hover || e.to === hover).flatMap((e) => [e.from, e.to]) : []), [hover, edges]);

  return (
    <div className="card pad0">
      <div className="card-head" style={{ padding: "16px 16px 0" }}>
        <div className="seg">
          {(["diagram", "graph"] as const).map((m) => (
            <button key={m} className={mode === m ? "on" : ""} onClick={() => { setMode(m); try { localStorage.setItem("niv.mapMode", m); } catch { /* ignore */ } }}>
              {m === "diagram" ? "Diagram" : "Graph"}
            </button>
          ))}
        </div>
        {counts && <span className="sub">{counts.devices} devices · {counts.internet} internet hosts · {counts.bad} suspicious links</span>}
        {mode === "graph" && <div className="right">
          <label className="toggle small"><input type="checkbox" checked={showInternet} onChange={(e) => setShowInternet(e.target.checked)} />Internet hosts</label>
          <label className="toggle small"><input type="checkbox" checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} />Only suspicious links</label>
          <button className="btn sm ghost" onClick={() => setView({ x: 0, y: 0, k: 1 })}>Reset view</button>
          <button className="btn sm ghost" onClick={() => { pos.current = new Map(); load(); }}><Icon name="refresh" size={12} /> Re-layout</button>
        </div>}
      </div>
      {mode === "diagram" ? (
        data && devices ? <NetworkDiagram devices={devices} topo={data} clock={status?.clock ?? new Date().toISOString()} /> : <div className="empty">Loading…</div>
      ) : (
      <div className="map-wrap">
        {!data || !nodes.length ? (
          <div className="empty"><Icon name="globe" size={28} />No devices yet — start a capture to draw the map.</div>
        ) : (
          <svg ref={svg} viewBox={`0 0 ${W} ${H}`} className="map"
            onWheel={(e) => {
              const p = toSvg(e);
              const k = Math.min(4, Math.max(0.3, view.k * (e.deltaY < 0 ? 1.1 : 0.9)));
              setView((v) => ({ k, x: p.x - ((p.x - v.x) * k) / v.k, y: p.y - ((p.y - v.y) * k) / v.k }));
            }}
            onMouseDown={(e) => { const p = toSvg(e); drag.current = { sx: p.x, sy: p.y, vx: view.x, vy: view.y }; }}
            onMouseMove={(e) => {
              const d = drag.current;
              if (!d) return;
              const p = toSvg(e);
              if (d.id) {
                const n = pos.current.get(d.id);
                if (n) {
                  n.x = (p.x - view.x) / view.k;
                  n.y = (p.y - view.y) / view.k;
                  n.fixed = true;
                  force((x) => x + 1);
                }
              } else setView((v) => ({ ...v, x: d.vx + p.x - d.sx, y: d.vy + p.y - d.sy }));
            }}
            onMouseUp={() => (drag.current = null)}
            onMouseLeave={() => (drag.current = null)}>
            <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
              {edges.map((e, i) => {
                const a = pos.current.get(e.from), b = pos.current.get(e.to);
                if (!a || !b) return null;
                const dim = hover && !(e.from === hover || e.to === hover);
                return (
                  <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    stroke={e.suspicious ? "var(--critical)" : e.kind === "lan" ? "var(--rule-strong)" : "var(--axis)"}
                    strokeWidth={e.kind === "lan" ? 1 : 0.8 + (Math.log10(1 + e.bytes) / Math.log10(1 + maxBytes)) * 3}
                    strokeDasharray={e.kind === "peer" ? "4 3" : e.suspicious ? "6 3" : undefined}
                    opacity={dim ? 0.12 : 0.9} />
                );
              })}
              {nodes.map((n) => {
                const p = pos.current.get(n.id);
                if (!p) return null;
                const r = n.kind === "router" ? 22 : n.kind === "internet" ? 6 : 15;
                const dim = hover && hover !== n.id && !linked.has(n.id);
                return (
                  <g key={n.id} transform={`translate(${p.x} ${p.y})`} opacity={dim ? 0.25 : 1} style={{ cursor: "pointer" }}
                    onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}
                    onMouseDown={(e) => { e.stopPropagation(); const q = toSvg(e); drag.current = { id: n.id, sx: q.x, sy: q.y, vx: 0, vy: 0 }; }}
                    onDoubleClick={() => {
                      if (n.kind === "internet") {
                        try { localStorage.setItem("niv.lastSearch", `index=conn remote_ip=${n.id} | table _time device_label direction remote_port domain bytes_out bytes_in`); } catch { /* default */ }
                        nav.go("search");
                      } else nav.openDevice(n.id);
                    }}>
                    <circle r={r} fill="var(--panel)" stroke={tone(n)} strokeWidth={n.kind === "internet" ? 1.5 : n.risk > 0 || n.alerts > 0 ? 2.5 : 1.2} />
                    {n.kind !== "internet" && (
                      <g transform={`translate(${-r * 0.55} ${-r * 0.55}) scale(${(r * 1.1) / 24})`} color={tone(n)}>
                        <path d={ICON_PATHS[n.kind === "router" ? "router" : n.kind === "self" ? "user" : n.kind === "ap" ? "ap" : classIcon(n.class)] ?? ""}
                          fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                      </g>
                    )}
                    {(n.kind !== "internet" || hover === n.id || n.flagged) && (
                      <text y={r + 13} textAnchor="middle" className="map-label">{n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label}</text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>
        )}
        {hovered && (
          <div className="map-tip">
            <div style={{ fontWeight: 600 }}>{hovered.label}</div>
            <div className="muted small">{hovered.kind === "internet" ? `Internet host · ${hovered.id}` : `${hovered.class} · ${hovered.id}`}</div>
            {hovered.kind !== "internet" && <div className="small">Risk {hovered.risk} · {hovered.alerts} open alert{hovered.alerts === 1 ? "" : "s"}</div>}
            <div className="small dim">
              {edges.filter((e) => e.from === hovered.id || e.to === hovered.id).reduce((s, e) => s + e.bytes, 0) > 0 &&
                `${fmtBytes(edges.filter((e) => e.from === hovered.id || e.to === hovered.id).reduce((s, e) => s + e.bytes, 0))} exchanged`}
            </div>
            <div className="muted small">Double-click to {hovered.kind === "internet" ? "search its connections" : "open the device"} · drag to move</div>
          </div>
        )}
        <div className="map-legend small">
          <span><i style={{ background: "var(--critical)" }} /> suspicious link / risk ≥ 80</span>
          <span><i style={{ background: "var(--serious)" }} /> risk ≥ 50</span>
          <span><i style={{ background: "var(--warning)" }} /> risk ≥ 20 / open alerts</span>
          <span><i style={{ background: "var(--rule-strong)" }} /> LAN · dashed = device to device</span>
        </div>
      </div>
      )}
    </div>
  );
}
