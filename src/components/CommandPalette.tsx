import { useEffect, useMemo, useRef, useState } from "react";
import { api, type DeviceSummary } from "../api";
import { useNav, type Page } from "../nav";
import { useLive } from "../store";
import { Avatar, Icon } from "./Icon";

interface Item {
  id: string;
  icon: React.ReactNode;
  title: string;
  sub?: string;
  group: string;
  run: () => void | Promise<unknown>;
}

const PAGES: { page: Page; title: string; icon: string }[] = [
  { page: "overview", title: "Overview", icon: "home" },
  { page: "dashboards", title: "Dashboards", icon: "dashboard" },
  { page: "map", title: "Network map", icon: "map" },
  { page: "compliance", title: "Compliance & vulnerabilities", icon: "clipboard" },
  { page: "intel", title: "Threat intel & signatures", icon: "crosshair" },
  { page: "automation", title: "Automation playbooks", icon: "bolt" },
  { page: "devices", title: "Devices", icon: "devices" },
  { page: "feed", title: "Live feed", icon: "activity" },
  { page: "search", title: "Search (SPL)", icon: "search" },
  { page: "alerts", title: "Incident review (alerts)", icon: "alerts" },
  { page: "networks", title: "Networks", icon: "globe" },
  { page: "capture", title: "Capture setup", icon: "settings" },
  { page: "rules", title: "Detection rules & data", icon: "sliders" },
  { page: "detections", title: "Custom detections", icon: "shield" },
];

/** Global quick-jump: pages, actions and every known device. */
export function CommandPalette({ onClose, onMessage }: { onClose: () => void; onMessage: (m: string) => void }) {
  const nav = useNav();
  const { status, refresh } = useLive();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    input.current?.focus();
    api.getDevices().then(setDevices).catch(() => {});
  }, []);

  const items = useMemo<Item[]>(() => {
    const done = (p: Promise<unknown>, ok: string) =>
      p.then((r) => onMessage(typeof r === "string" ? r : ok)).catch((e) => onMessage(String(e))).finally(refresh);
    const all: Item[] = [
      ...PAGES.map((p) => ({
        id: `p-${p.page}`,
        icon: <span className="ic"><Icon name={p.icon} /></span>,
        title: p.title,
        group: "Go to",
        run: () => nav.go(p.page),
      })),
      {
        id: "a-capture",
        icon: <span className="ic"><Icon name={status?.running ? "stop" : "play"} /></span>,
        title: status?.running ? "Stop capture" : "Start capture",
        group: "Actions",
        run: () => done(status?.running ? api.stopCapture() : api.startCapture(), status?.running ? "Capture stopped." : "Capture started."),
      },
      {
        id: "a-sim",
        icon: <span className="ic"><Icon name="beaker" /></span>,
        title: "Run simulator (demo)",
        group: "Actions",
        run: () => done(api.switchSource("simulator"), "Simulator started."),
      },
      {
        id: "a-scan",
        icon: <span className="ic"><Icon name="radar" /></span>,
        title: "Scan network for devices (ARP)",
        sub: "Needs a live managed-mode capture",
        group: "Actions",
        run: () => done(api.scanNetwork(), "Scan started."),
      },
      {
        id: "a-cleardemo",
        icon: <span className="ic"><Icon name="beaker" /></span>,
        title: "Clear demo data",
        sub: "Remove all simulated devices and alerts",
        group: "Actions",
        run: () => done(api.clearDemo(), "Demo data cleared."),
      },
      {
        id: "a-vendors",
        icon: <span className="ic"><Icon name="database" /></span>,
        title: "Download / update MAC vendor database",
        sub: "IEEE registry, ~38,000 manufacturers",
        group: "Actions",
        run: () => done(api.updateVendorDb(), "Vendor database updated."),
      },
      {
        id: "a-ack",
        icon: <span className="ic"><Icon name="check" /></span>,
        title: "Resolve all open alerts",
        group: "Actions",
        run: () => done(api.ackAlert(), "All alerts acknowledged."),
      },
      {
        id: "a-export",
        icon: <span className="ic"><Icon name="download" /></span>,
        title: "Export JSON report",
        group: "Actions",
        run: () => done(api.exportReport().then((p) => `Report saved to ${p}`), ""),
      },
      ...devices.map((d) => ({
        id: `d-${d.mac}`,
        icon: <Avatar cls={d.class} iot={d.isIot} net={d.isGateway || d.isAp} self={d.isSelf} />,
        title: d.label,
        sub: [d.mac, d.vendor, d.ips[0], d.class].filter(Boolean).join(" · "),
        group: "Devices",
        run: () => nav.openDevice(d.mac),
      })),
    ];
    const ql = q.trim().toLowerCase();
    if (!ql) return all.filter((i) => i.group !== "Devices").concat(all.filter((i) => i.group === "Devices").slice(0, 6));
    return all.filter((i) => `${i.title} ${i.sub ?? ""}`.toLowerCase().includes(ql)).slice(0, 40);
  }, [q, devices, status?.running, nav, onMessage, refresh]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector(".sel")?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  function key(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(items.length - 1, s + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(0, s - 1));
    } else if (e.key === "Enter" && items[sel]) {
      items[sel].run();
      onClose();
    } else if (e.key === "Escape") {
      onClose();
    }
  }

  let lastGroup = "";
  return (
    <div className="overlay" onMouseDown={onClose}>
      <div className="palette" onMouseDown={(e) => e.stopPropagation()}>
        <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={key}
          placeholder="Search devices (name, MAC, IP, vendor), pages and actions…" />
        <div className="list" ref={listRef}>
          {items.length === 0 && <div className="empty">No matches.</div>}
          {items.map((it, i) => {
            const header = it.group !== lastGroup ? <div className="menu-label">{it.group}</div> : null;
            lastGroup = it.group;
            return (
              <div key={it.id}>
                {header}
                <button className={`menu-item ${i === sel ? "sel" : ""}`} onMouseEnter={() => setSel(i)}
                  onClick={() => { it.run(); onClose(); }}>
                  {it.icon}
                  <span style={{ minWidth: 0 }}>
                    <div className="t ellipsis">{it.title}</div>
                    {it.sub && <div className="s ellipsis">{it.sub}</div>}
                  </span>
                  {i === sel ? <kbd>↵</kbd> : <span />}
                </button>
              </div>
            );
          })}
        </div>
        <div className="foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
