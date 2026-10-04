import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useRef, useState } from "react";
import { api, type InterfaceInfo } from "../api";
import { fmtNum, fmtRate } from "../format";
import { useNav } from "../nav";
import { useLive } from "../store";
import { Icon } from "./Icon";

export function ifIcon(i: InterfaceInfo) {
  return i.kind === "wifi" ? "wifi" : i.kind === "ethernet" ? "ethernet" : i.kind === "vpn" ? "lock" : "globe";
}

export function ifSubtitle(i: InterfaceInfo) {
  const parts = [i.name];
  if (i.ipv4.length) parts.push(i.ipv4[0]);
  else parts.push(i.up ? "not connected" : "down");
  if (i.network) parts.push(i.network);
  return parts.join(" · ");
}

/** Top-bar pill: shows what we're capturing and switches source in one click. */
export function SourceSwitcher({ onError }: { onError: (e: string | null) => void }) {
  const { status, refresh, access, recheckAccess } = useLive();
  const nav = useNav();
  const [openPop, setOpen] = useState(false);
  const [ifaces, setIfaces] = useState<InterfaceInfo[] | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!openPop) return;
    api.listInterfaces().then(setIfaces).catch((e) => onError(String(e)));
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [openPop, onError]);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    onError(null);
    try {
      await fn();
      setOpen(false);
    } catch (e) {
      onError(String(e));
      recheckAccess();
    } finally {
      setBusy(false);
      refresh();
    }
  }

  async function openFile() {
    const f = await open({ multiple: false, filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }] });
    if (typeof f !== "string") return;
    await run(async () => {
      const s = await api.getSettings();
      s.capture.filePath = f;
      await api.saveSettings(s);
      await api.switchSource("file");
    });
  }

  const s = status?.session;
  const running = !!status?.running;
  const finished = status?.stats.finished;
  const visible = (ifaces ?? []).filter((i) => showAll || !i.hidden);
  const hiddenCount = (ifaces ?? []).filter((i) => i.hidden).length;
  const isCurrent = (name: string, monitor: boolean) =>
    running && s?.source === "live" && s.interface === name && s.monitorMode === monitor;

  let label = "Not capturing";
  if (running && s?.source === "simulator") label = "Simulator";
  if (running && s?.source === "live") label = `${s.interface}${s.monitorMode ? " · monitor" : ""}`;
  if (running && s?.source === "file") label = finished ? "File replay finished" : "Replaying file";
  if (running && s?.source === "remote") label = `${s.interface ?? "sensor"}${s.monitorMode ? " · monitor" : ""}`;

  return (
    <div className="popover-wrap" ref={ref}>
      <button className="pill" onClick={() => setOpen((o) => !o)} title="Switch capture source / interface">
        <span className={`dot ${running && !finished ? "live" : ""}`} />
        <span className="mono" style={{ fontSize: 12 }}>{label}</span>
        {running && status?.channel ? <span>· ch {status.channel}{s?.hopping ? "↻" : ""}</span> : null}
        {running && <span className="num">· {fmtNum(status?.packetsPerSec ?? 0)} fps · {fmtRate(status?.bytesPerSec ?? 0)}</span>}
        <Icon name="down" size={14} />
      </button>
      {openPop && (
        <div className="popover">
          {access && !access.ok && (
            <div className="banner warn" style={{ margin: 4 }}>
              <Icon name="lock" />
              <div className="grow small">
                Live capture needs permission on this computer.
                {access.canFix && (
                  <div style={{ marginTop: 8 }}>
                    <button className="btn sm primary" disabled={busy}
                      onClick={() => run(async () => { await api.fixAccess(); await recheckAccess(); })}>
                      Grant capture access…
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="menu-label">Network interfaces</div>
          {ifaces === null && <div className="empty small">Detecting interfaces…</div>}
          {visible.map((i) => (
            <div key={i.name}>
              <button
                className={`menu-item ${isCurrent(i.name, false) ? "current" : ""}`}
                disabled={busy}
                onClick={() => run(() => api.switchSource("live", i.name, false))}
              >
                <span className="ic"><Icon name={ifIcon(i)} /></span>
                <span style={{ minWidth: 0 }}>
                  <div className="t ellipsis">
                    {i.friendly}{" "}
                    {i.isDefault && <span className="chip accent" style={{ marginLeft: 4 }}>recommended</span>}
                  </div>
                  <div className="s ellipsis mono">{ifSubtitle(i)}</div>
                </span>
                {isCurrent(i.name, false) ? <Icon name="check" /> : <span className="s">capture</span>}
              </button>
              {i.kind === "wifi" && (
                <button
                  className={`menu-item ${isCurrent(i.name, true) ? "current" : ""}`}
                  style={{ paddingLeft: 50 }}
                  disabled={busy}
                  onClick={() => run(() => api.switchSource("live", i.name, true))}
                  title="Raw 802.11: sees all nearby devices, RSSI, probes, deauths. May disconnect this Wi-Fi."
                >
                  <span className="ic"><Icon name="radar" size={14} /></span>
                  <span>
                    <div className="t small">Monitor mode on {i.name}</div>
                    <div className="s">All nearby Wi-Fi devices · RSSI · may disconnect Wi-Fi</div>
                  </span>
                  {isCurrent(i.name, true) ? <Icon name="check" /> : null}
                </button>
              )}
            </div>
          ))}
          {hiddenCount > 0 && (
            <button className="btn sm ghost" style={{ margin: "4px 6px" }} onClick={() => setShowAll((v) => !v)}>
              {showAll ? "Hide virtual / inactive" : `Show ${hiddenCount} virtual / inactive interfaces`}
            </button>
          )}

          <div className="menu-sep" />
          <div className="menu-label">Other sources</div>
          <button className={`menu-item ${running && s?.source === "simulator" ? "current" : ""}`} disabled={busy}
            onClick={() => run(() => api.switchSource("simulator"))}>
            <span className="ic"><Icon name="beaker" /></span>
            <span>
              <div className="t">Simulator</div>
              <div className="s">Demo smart home with scripted attacks</div>
            </span>
            {running && s?.source === "simulator" ? <Icon name="check" /> : null}
          </button>
          <button className={`menu-item ${running && s?.source === "file" ? "current" : ""}`} disabled={busy} onClick={openFile}>
            <span className="ic"><Icon name="file" /></span>
            <span>
              <div className="t">Open capture file…</div>
              <div className="s ellipsis">{s?.file ?? ".pcap / .pcapng from Wireshark, tcpdump, airodump-ng"}</div>
            </span>
          </button>
          <button className={`menu-item ${running && s?.source === "remote" ? "current" : ""}`} disabled={busy}
            onClick={async () => {
              const st = await api.getSettings();
              if (!st.capture.remote.host) {
                setOpen(false);
                nav.go("capture");
                return;
              }
              run(() => api.switchSource("remote"));
            }}>
            <span className="ic"><Icon name="radar" /></span>
            <span>
              <div className="t">Remote sensor</div>
              <div className="s">ALFA / monitor adapter on a Raspberry Pi or Linux box, over SSH</div>
            </span>
            {running && s?.source === "remote" ? <Icon name="check" /> : null}
          </button>
          <div className="menu-sep" />
          <button className="menu-item" onClick={() => { setOpen(false); nav.go("capture"); }}>
            <span className="ic"><Icon name="settings" /></span>
            <span>
              <div className="t">Capture setup</div>
              <div className="s">Channels, hopping, filters, interface test</div>
            </span>
            <Icon name="chevron" />
          </button>
        </div>
      )}
    </div>
  );
}
