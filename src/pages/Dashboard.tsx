import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useMemo, useState } from "react";
import { api, type InterfaceInfo } from "../api";
import { AlertList } from "../components/AlertList";
import { Avatar, Icon } from "../components/Icon";
import { Mac } from "../components/Mac";
import { Risk } from "../components/Risk";
import { Signal } from "../components/Signal";
import { ifIcon, ifSubtitle } from "../components/SourceSwitcher";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { ago, fmtBytes, fmtNum, fmtRate, presence } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

/** First-run / stopped state: pick how to start in one click. */
function Welcome({ onError }: { onError: (e: string | null) => void }) {
  const { refresh, access, recheckAccess } = useLive();
  const [ifaces, setIfaces] = useState<InterfaceInfo[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.listInterfaces().then(setIfaces).catch(() => {});
  }, []);
  const best = ifaces.find((i) => i.isDefault) ?? ifaces.find((i) => !i.hidden && i.ipv4.length);
  const wifi = ifaces.find((i) => i.kind === "wifi" && !i.hidden);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    onError(null);
    try {
      await fn();
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
    run(async () => {
      const s = await api.getSettings();
      s.capture.filePath = f;
      await api.saveSettings(s);
      await api.switchSource("file");
    });
  }

  return (
    <div className="card hero">
      <h2>Start monitoring</h2>
      <p>
        Niv.ON discovers every device it can see, learns each one's normal behavior, and flags anomalies — an IoT camera
        calling an unknown server, a smart plug scanning the internet, traffic at 3 a.m., or a Wi-Fi deauth attack.
      </p>
      {access && !access.ok && (
        <div className="banner warn" style={{ marginTop: 16 }}>
          <Icon name="lock" />
          <div className="grow">
            <b>Live capture needs permission.</b> {access.message}
          </div>
          {access.canFix && (
            <button className="btn primary sm" disabled={busy}
              onClick={() => run(async () => { await api.fixAccess(); await recheckAccess(); })}>
              Grant access…
            </button>
          )}
        </div>
      )}
      <div className="choices">
        {best && (
          <button className="choice" disabled={busy} onClick={() => run(() => api.switchSource("live", best.name, false))}>
            <span className="t"><Icon name={ifIcon(best)} /> Monitor my network <span className="chip accent">recommended</span></span>
            <span className="s">{best.friendly} · <span className="mono">{ifSubtitle(best)}</span>. Sees this computer's traffic plus LAN broadcasts (ARP, DHCP, mDNS, SSDP). Use “Scan network” to discover every device.</span>
          </button>
        )}
        {wifi && (
          <button className="choice" disabled={busy} onClick={() => run(() => api.switchSource("live", wifi.name, true))}>
            <span className="t"><Icon name="radar" /> Wi-Fi monitor mode</span>
            <span className="s">Raw 802.11 on <span className="mono">{wifi.name}</span>: every nearby device, signal strength, probes, deauth attacks. Needs a monitor-capable adapter; may disconnect Wi-Fi.</span>
          </button>
        )}
        <button className="choice" disabled={busy} onClick={() => run(() => api.switchSource("simulator"))}>
          <span className="t"><Icon name="beaker" /> Demo simulator</span>
          <span className="s">A simulated smart home that turns hostile after the learning period. Perfect for presentations.</span>
        </button>
        <button className="choice" disabled={busy} onClick={openFile}>
          <span className="t"><Icon name="file" /> Analyze a capture file</span>
          <span className="s">Replay a .pcap/.pcapng from Wireshark, tcpdump or airodump-ng.</span>
        </button>
      </div>
    </div>
  );
}

export function Dashboard({ onError }: { onError: (e: string | null) => void }) {
  const { status, traffic, refresh } = useLive();
  const nav = useNav();
  const [range, setRange] = useState<60 | 300>(60);
  const [devices] = usePoll(api.getDevices, 2000);
  const [alerts, reloadAlerts] = usePoll(() => api.getAlerts(500), 2000);
  const [showNotes, setShowNotes] = useState(false);

  const pts = traffic.slice(-range);
  const times = pts.map((p) => p.t);
  const ethernetSeen = pts.some((p) => p.ethernet > 0);
  const wifiSeen = pts.some((p) => p.management + p.control + p.data > 0);
  const all = devices ?? [];
  const clock = status?.clock ?? new Date().toISOString();

  const talkers = useMemo(
    () => all.filter((d) => d.recentBytes > 0 && !d.isAp && !d.isGateway).sort((a, b) => b.recentBytes - a.recentBytes).slice(0, 6),
    [all],
  );
  const maxTalk = Math.max(1, ...talkers.map((t) => t.recentBytes));
  const mix = useMemo(() => {
    const m = new Map<string, number>();
    for (const d of all) m.set(d.class, (m.get(d.class) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [all]);
  const maxMix = Math.max(1, ...mix.map((m) => m[1]));
  const open = useMemo(() => (alerts ?? []).filter((a) => !a.acknowledged), [alerts]);
  const openAlerts = open.slice(0, 7);
  const risky = useMemo(() => all.filter((d) => d.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 6), [all]);
  // Open detections grouped by MITRE ATT&CK technique, ordered by tactic.
  const techniques = useMemo(() => {
    const m = new Map<string, { id: string; name: string; tactic: string; n: number; devices: Set<string> }>();
    for (const a of open) {
      if (!a.mitreId) continue;
      const t = m.get(a.mitreId) ?? { id: a.mitreId, name: a.mitreName ?? "", tactic: a.tactic ?? "", n: 0, devices: new Set<string>() };
      t.n++;
      if (a.device) t.devices.add(a.device);
      m.set(a.mitreId, t);
    }
    return [...m.values()].sort((a, b) => b.n - a.n).slice(0, 8);
  }, [open]);
  const maxTech = Math.max(1, ...techniques.map((t) => t.n));
  const sev = status?.alerts;
  const iot = all.filter((d) => d.isIot).length;
  const gateway = all.find((d) => d.isGateway);
  const self = all.find((d) => d.isSelf);
  const notes = status?.session?.notes ?? [];
  const showWelcome = status && !status.running && status.devices === 0;

  return (
    <>
      {showWelcome && <Welcome onError={onError} />}
      {status?.network?.kind === "demo" && (
        <div className="banner warn">
          <Icon name="beaker" />
          <div className="grow">
            <b>You're viewing demo data.</b> Simulated devices are never saved and won't appear on your real networks.
          </div>
          {!status.running && (
            <button className="btn sm" onClick={() => api.clearDemo().then(refresh).catch((e) => onError(String(e)))}>Clear demo data</button>
          )}
        </div>
      )}
      {status && !status.running && status.devices > 0 && status.network?.kind !== "demo" && (
        <div className="banner">
          <Icon name="info" />
          <div className="grow">Capture is stopped — showing saved device profiles and baselines. Pick a source from the pill in the top bar to resume.</div>
        </div>
      )}
      {status?.stats.error && (
        <div className="banner error"><Icon name="octagon" /><div>{status.stats.error}</div></div>
      )}
      {notes.length > 0 && (
        <div className="banner">
          <Icon name="info" />
          <div className="grow">
            {showNotes ? notes.map((n, i) => <div key={i} style={{ marginBottom: 4 }}>{n}</div>) : notes[0]}
          </div>
          {notes.length > 1 && (
            <button className="btn sm ghost" onClick={() => setShowNotes((v) => !v)}>{showNotes ? "Less" : `+${notes.length - 1} more`}</button>
          )}
        </div>
      )}

      <div className="kpis">
        <div className="card kpi clickable" onClick={() => nav.go("devices")}>
          <div className="label"><Icon name="devices" size={14} />Devices</div>
          <div className="value">{status?.activeDevices ?? 0}<span className="unit"> / {status?.devices ?? 0}</span></div>
          <div className="foot">active in the last minute / known</div>
        </div>
        <div className="card kpi clickable" onClick={() => nav.go("devices")}>
          <div className="label"><Icon name="chip" size={14} />IoT devices</div>
          <div className="value">{iot}</div>
          <div className="foot">held to strict behavioral baselines</div>
        </div>
        <div className="card kpi clickable" onClick={() => nav.go("feed")}>
          <div className="label"><Icon name="activity" size={14} />Throughput</div>
          <div className="value">{fmtRate(status?.bytesPerSec ?? 0)}</div>
          <div className="foot">{fmtNum(status?.packetsPerSec ?? 0)} frames/s · {fmtNum(status?.totals.packets ?? 0)} total</div>
        </div>
        <div className="card kpi clickable" onClick={() => nav.go("alerts")}>
          <div className="label"><Icon name="alerts" size={14} />Open alerts</div>
          <div className="value" style={{ color: sev && sev.critical + sev.high > 0 ? "var(--serious)" : undefined }}>{sev?.open ?? 0}</div>
          <div className="foot">{sev ? `${sev.critical} critical · ${sev.high} high · ${sev.medium} medium` : "—"}</div>
        </div>
      </div>

      <div className="split">
        <div className="grid">
          <div className="card">
            <div className="card-head">
              <h2>Traffic flow</h2>
              <span className="sub">bytes per second</span>
              <div className="right">
                <div className="seg">
                  <button className={range === 60 ? "on" : ""} onClick={() => setRange(60)}>1 min</button>
                  <button className={range === 300 ? "on" : ""} onClick={() => setRange(300)}>5 min</button>
                </div>
              </div>
            </div>
            <TimeSeriesChart
              times={times}
              series={[{ key: "bytes", label: "Throughput", color: "var(--mono-series)", values: pts.map((p) => p.bytes) }]}
              format={fmtRate}
              minMax={1000}
              area
              height={220}
            />
          </div>
          <div className="card">
            <div className="card-head">
              <h2>Frames by type</h2>
              <span className="sub">frames per second</span>
            </div>
            <TimeSeriesChart
              times={times}
              series={[
                ...(wifiSeen || !ethernetSeen
                  ? [
                      { key: "data", label: "Data", color: "var(--s1)", values: pts.map((p) => p.data) },
                      { key: "mgmt", label: "Management", color: "var(--s2)", values: pts.map((p) => p.management) },
                      { key: "ctrl", label: "Control", color: "var(--s3)", values: pts.map((p) => p.control) },
                    ]
                  : []),
                ...(ethernetSeen ? [{ key: "eth", label: "Ethernet", color: "var(--s4)", values: pts.map((p) => p.ethernet) }] : []),
              ]}
              format={(v) => fmtNum(Math.round(v))}
              height={170}
            />
          </div>
        </div>

        <div className="card" style={{ alignSelf: "start" }}>
          <div className="card-head">
            <h2>Alert panel</h2>
            <span className="sub">latest unacknowledged</span>
            <div className="right">
              <button className="btn sm ghost" onClick={() => nav.go("alerts")}>View all <Icon name="chevron" size={12} /></button>
            </div>
          </div>
          <AlertList alerts={openAlerts} onChange={reloadAlerts} compact empty="No open alerts — behavior matches baselines." />
        </div>
      </div>

      <div className="three">
        <div className="card">
          <div className="card-head"><h2>Top talkers</h2><span className="sub">last 10 s</span></div>
          {talkers.length === 0 && <div className="empty">No traffic yet.</div>}
          {talkers.map((t) => (
            <div key={t.mac} className="talker" onClick={() => nav.openDevice(t.mac)}>
              <span className="name ellipsis">{t.label}</span>
              <span className="num dim">{fmtRate(t.recentBytes / 10)}</span>
              <div className="track"><div style={{ width: `${(t.recentBytes / maxTalk) * 100}%` }} /></div>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-head"><h2>Device mix</h2><span className="sub">by type</span></div>
          {mix.length === 0 && <div className="empty">No devices yet.</div>}
          <div className="bars">
            {mix.map(([cls, n]) => (
              <div key={cls} className="bar-row">
                <span className="row" style={{ gap: 8, flexWrap: "nowrap" }}>{cls}</span>
                <span className="num dim">{n}</span>
                <div className="track"><div style={{ width: `${(n / maxMix) * 100}%` }} /></div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><h2>Network</h2></div>
          <dl className="kv">
            <dt>Network</dt>
            <dd>{status?.network ? <button className="linkish" onClick={() => nav.go("networks")}>{status.network.name}</button> : "—"}</dd>
            <dt>Source</dt>
            <dd>{status?.session ? (status.session.source === "live" ? `${status.session.interface} (${status.session.linktype})` : status.session.linktype) : "—"}</dd>
            <dt>Gateway</dt>
            <dd>{gateway ? <button className="linkish" onClick={() => nav.openDevice(gateway.mac)}>{gateway.label} · {gateway.ips[0] ?? gateway.mac}</button> : "—"}</dd>
            <dt>This computer</dt>
            <dd>{self ? <button className="linkish" onClick={() => nav.openDevice(self.mac)}>{self.ips[0] ?? self.mac}</button> : "—"}</dd>
            <dt>Frames w/ IP</dt>
            <dd>{status && status.totals.packets ? `${Math.round((status.totals.withIp / status.totals.packets) * 100)}%` : "—"}</dd>
            <dt>Encrypted</dt>
            <dd>{status && status.totals.packets ? `${Math.round((status.totals.protected / status.totals.packets) * 100)}% of frames` : "—"}</dd>
            <dt>Dropped</dt>
            <dd>{status ? fmtNum(status.stats.dropped + status.stats.queueDropped) : "—"}</dd>
          </dl>
        </div>
      </div>

      <div className="two">
        <div className="card">
          <div className="card-head"><h2>Highest risk</h2><span className="sub">open alerts weighted by severity · 24 h half-life</span></div>
          {risky.length === 0 && <div className="empty">No device carries risk right now.</div>}
          <table className="t compact">
            <tbody>
              {risky.map((d) => (
                <tr key={d.mac} className="click" onClick={() => nav.openDevice(d.mac, "alerts")}>
                  <td>
                    <div className="dev-cell">
                      <Avatar cls={d.class} iot={d.isIot} net={d.isGateway || d.isAp} self={d.isSelf} />
                      <div style={{ minWidth: 0 }}>
                        <div className="name ellipsis">{d.label}</div>
                        <div className="muted small">{d.class} · {d.openAlerts} open alert{d.openAlerts === 1 ? "" : "s"}</div>
                      </div>
                    </div>
                  </td>
                  <td className="r"><Risk score={d.risk} wide /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-head"><h2>MITRE ATT&amp;CK</h2><span className="sub">techniques behind open alerts</span></div>
          {techniques.length === 0 && <div className="empty">No open detections.</div>}
          <div className="bars">
            {techniques.map((t) => (
              <div key={t.id} className="bar-row" title={`${t.tactic} — seen on ${t.devices.size} device(s)`}>
                <span className="ellipsis"><span className="mono dim">{t.id}</span> {t.name} <span className="muted small">· {t.tactic}</span></span>
                <span className="num dim">{t.n}</span>
                <div className="track"><div style={{ width: `${(t.n / maxTech) * 100}%` }} /></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Recently seen</h2>
          <div className="right"><button className="btn sm ghost" onClick={() => nav.go("devices")}>All devices <Icon name="chevron" size={12} /></button></div>
        </div>
        <div className="table-wrap">
          <table className="t">
            <tbody>
              {all.filter((d) => !d.isAp).slice(0, 8).map((d) => {
                const p = presence(d.lastSeen, clock);
                return (
                  <tr key={d.mac} className="click" onClick={() => nav.openDevice(d.mac)}>
                    <td>
                      <div className="dev-cell">
                        <Avatar cls={d.class} iot={d.isIot} net={d.isGateway || d.isAp} self={d.isSelf} />
                        <div style={{ minWidth: 0 }}>
                          <div className="name ellipsis">{d.label}</div>
                          <div className="muted small">{d.class}{d.vendor ? ` · ${d.vendor}` : ""}</div>
                        </div>
                      </div>
                    </td>
                    <td className="small dim">{d.ips[0] ? <span className="mono">{d.ips[0]}</span> : <Mac mac={d.mac} />}</td>
                    <td><Signal rssi={d.rssi} /></td>
                    <td className="r num">{fmtBytes(d.txBytes + d.rxBytes)}</td>
                    <td className="r muted">
                      <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap", gap: 6 }}>
                        <span className={`dot ${p === "active" ? "live" : p === "idle" ? "idle" : ""}`} />
                        {ago(d.lastSeen, clock)}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {all.length === 0 && <div className="empty">No devices discovered yet.</div>}
        </div>
      </div>
    </>
  );
}
