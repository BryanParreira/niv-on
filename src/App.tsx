import { useCallback, useEffect, useState } from "react";
import { api, inTauri, onAlerts, type Alert } from "./api";
import { CommandPalette } from "./components/CommandPalette";
import { Icon } from "./components/Icon";
import { LogoMark, Wordmark } from "./components/Logo";
import { UpdateNotice } from "./components/UpdateNotice";
import { UpdaterProvider } from "./updater";
import { SeverityBadge } from "./components/Severity";
import { SourceSwitcher } from "./components/SourceSwitcher";
import { NavProvider, useNav, type Page } from "./nav";
import { Alerts } from "./pages/Alerts";
import { Capture } from "./pages/Capture";
import { Dashboard } from "./pages/Dashboard";
import { DeviceDetail } from "./pages/DeviceDetail";
import { Devices } from "./pages/Devices";
import { LiveFeed } from "./pages/LiveFeed";
import { Networks } from "./pages/Networks";
import { Rules } from "./pages/Rules";
import { LiveProvider, useLive } from "./store";

const NAV: { section: string; items: { id: Page; label: string; icon: string }[] }[] = [
  {
    section: "Monitor",
    items: [
      { id: "overview", label: "Overview", icon: "dashboard" },
      { id: "devices", label: "Devices", icon: "devices" },
      { id: "feed", label: "Live feed", icon: "activity" },
      { id: "alerts", label: "Alerts", icon: "alerts" },
    ],
  },
  {
    section: "Manage",
    items: [{ id: "networks", label: "Networks", icon: "globe" }],
  },
  {
    section: "Configure",
    items: [
      { id: "capture", label: "Capture setup", icon: "settings" },
      { id: "rules", label: "Rules & data", icon: "sliders" },
    ],
  },
];
const ALL_PAGES = NAV.flatMap((s) => s.items);
const isMac = navigator.userAgent.includes("Mac");

function Shell() {
  const { status, refresh } = useLive();
  const nav = useNav();
  const { route } = nav;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Alert[]>([]);
  const [palette, setPalette] = useState(false);
  const [deviceName, setDeviceName] = useState<string | null>(null);

  // Pop high/critical alerts as toasts.
  useEffect(() => {
    if (!inTauri) return;
    const un = onAlerts((list) => {
      const loud = list.filter((a) => a.severity === "high" || a.severity === "critical");
      if (!loud.length) return;
      setToasts((t) => [...loud.slice(-3), ...t].slice(0, 4));
      for (const a of loud) setTimeout(() => setToasts((t) => t.filter((x) => x.id !== a.id)), 7000);
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  // Keyboard: ⌘/Ctrl+K palette, ⌘/Ctrl+1..6 pages, Esc back from device.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      } else if (mod && /^[1-7]$/.test(e.key)) {
        e.preventDefault();
        nav.go(ALL_PAGES[Number(e.key) - 1].id);
      } else if (e.key === "Escape" && route.device && !palette && !(e.target instanceof HTMLInputElement)) {
        nav.back();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [nav, route.device, palette]);

  useEffect(() => {
    if (!route.device) setDeviceName(null);
  }, [route.device]);

  const flash = useCallback((m: string) => {
    setNote(m);
    setTimeout(() => setNote((n) => (n === m ? null : n)), 6000);
  }, []);

  async function toggleCapture() {
    setBusy(true);
    setErr(null);
    try {
      if (status?.running) await api.stopCapture();
      else await api.startCapture();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      refresh();
    }
  }

  const running = !!status?.running;
  const current = ALL_PAGES.find((p) => p.id === route.page)!;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <LogoMark size={30} />
          <div>
            <div className="brand-name"><Wordmark /></div>
            <div className="brand-sub">Network &amp; IoT monitor</div>
          </div>
        </div>
        <button className="btn ghost" style={{ justifyContent: "flex-start", border: "1px solid var(--border)", marginBottom: 6 }}
          onClick={() => setPalette(true)}>
          <Icon name="search" size={14} />
          <span className="muted">Search…</span>
          <kbd style={{ marginLeft: "auto" }}>{isMac ? "⌘" : "Ctrl"} K</kbd>
        </button>
        {NAV.map((sec) => (
          <div key={sec.section}>
            <div className="nav-section">{sec.section}</div>
            {sec.items.map((n) => (
              <button key={n.id} className={`nav-item ${route.page === n.id ? "active" : ""}`} onClick={() => nav.go(n.id)}>
                <Icon name={n.icon} />
                {n.label}
                {n.id === "alerts" && (status?.alerts.open ?? 0) > 0 && <span className="count">{status!.alerts.open}</span>}
                {n.id === "devices" && status && <span className="meta">{status.devices}</span>}
                {n.id === "feed" && running && <span className="dot live" style={{ marginLeft: "auto" }} />}
              </button>
            ))}
          </div>
        ))}
        <UpdateNotice />
        <div className="sidebar-foot">
          Only monitor networks you own or are explicitly authorized to test.
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="crumbs">
            {route.device ? (
              <>
                <button onClick={() => nav.go("devices")}>Devices</button>
                <span className="sep">/</span>
                <h1 className="ellipsis" style={{ maxWidth: 360 }}>{deviceName ?? route.device}</h1>
              </>
            ) : (
              <h1>{current.label}</h1>
            )}
          </div>
          {status?.network && !route.device && (
            <button className="net-chip" onClick={() => nav.go("networks")} title="Devices, baselines and alerts are kept per network">
              <Icon name={status.network.kind === "demo" ? "beaker" : "globe"} size={13} />
              <span className="ellipsis">{status.network.name}</span>
            </button>
          )}
          <div className="spacer" />
          <SourceSwitcher onError={setErr} />
          <button className={`btn ${running ? "stop" : "primary"}`} onClick={toggleCapture} disabled={busy || !inTauri}>
            <Icon name={running ? "stop" : "play"} size={14} />
            {running ? "Stop" : "Start capture"}
          </button>
        </header>

        <div className="content">
          <div className="page">
            {!inTauri && (
              <div className="banner error">
                <Icon name="octagon" />
                <div>The backend isn't connected. Launch the desktop app with <span className="mono">npm run tauri dev</span>.</div>
              </div>
            )}
            {err && (
              <div className="banner error">
                <Icon name="octagon" />
                <div className="grow">{err}</div>
                <button className="btn sm" onClick={() => nav.go("capture")}>Capture setup</button>
                <button className="btn sm ghost" onClick={() => setErr(null)}><Icon name="x" size={12} /></button>
              </div>
            )}
            {note && (
              <div className="banner ok">
                <Icon name="check" />
                <div className="grow">{note}</div>
                <button className="btn sm ghost" onClick={() => setNote(null)}><Icon name="x" size={12} /></button>
              </div>
            )}
            {route.device ? (
              <DeviceDetail key={route.device} mac={route.device} onName={setDeviceName} />
            ) : route.page === "overview" ? (
              <Dashboard onError={setErr} />
            ) : route.page === "devices" ? (
              <Devices onMessage={flash} />
            ) : route.page === "feed" ? (
              <LiveFeed />
            ) : route.page === "alerts" ? (
              <Alerts />
            ) : route.page === "networks" ? (
              <Networks onMessage={flash} />
            ) : route.page === "capture" ? (
              <Capture onMessage={flash} />
            ) : (
              <Rules onMessage={flash} />
            )}
          </div>
        </div>
      </main>

      {palette && <CommandPalette onClose={() => setPalette(false)} onMessage={flash} />}

      <div className="toasts">
        {toasts.map((a) => (
          <div
            key={a.id}
            className="toast"
            onClick={() => {
              setToasts((t) => t.filter((x) => x.id !== a.id));
              if (a.device) nav.openDevice(a.device, "alerts");
              else nav.go("alerts");
            }}
          >
            <div className="row" style={{ marginBottom: 4 }}>
              <SeverityBadge s={a.severity} />
              <span className="muted small">new alert · click to investigate</span>
            </div>
            <div style={{ fontWeight: 600 }}>{a.title}</div>
            <div className="dim small" style={{ marginTop: 2 }}>{a.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <LiveProvider>
      <UpdaterProvider>
        <NavProvider>
          <Shell />
        </NavProvider>
      </UpdaterProvider>
    </LiveProvider>
  );
}
