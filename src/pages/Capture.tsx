import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useState, type ReactNode } from "react";
import { api, inTauri, type InterfaceInfo, type Settings, type Source, type TestResult } from "../api";
import { Icon } from "../components/Icon";
import { ifIcon } from "../components/SourceSwitcher";
import { useLive } from "../store";

const CH_24 = Array.from({ length: 14 }, (_, i) => i + 1);
const CH_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];

export function Toggle({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}

export function Capture({ onMessage }: { onMessage: (m: string) => void }) {
  const { status, refresh, access, recheckAccess } = useLive();
  const [s, setS] = useState<Settings | null>(null);
  const [ifaces, setIfaces] = useState<InterfaceInfo[] | null>(null);
  const [ifErr, setIfErr] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<TestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [fixing, setFixing] = useState(false);

  const loadIfaces = () => {
    setIfaces(null);
    api.listInterfaces().then((l) => { setIfaces(l); setIfErr(null); }).catch((e) => { setIfaces([]); setIfErr(String(e)); });
  };

  useEffect(() => {
    if (!inTauri) return;
    api.getSettings().then(setS);
    loadIfaces();
    recheckAccess();
  }, [recheckAccess]);

  if (!s) return <div className="card"><div className="empty">Loading…</div></div>;
  const cap = s.capture;
  const setCap = (p: Partial<Settings["capture"]>) => {
    setS({ ...s, capture: { ...cap, ...p } });
    setDirty(true);
    if ("interface" in p || "monitorMode" in p) setTest(null);
  };
  const list = (ifaces ?? []).filter((i) => showAll || !i.hidden || i.name === cap.interface);
  const hidden = (ifaces ?? []).filter((i) => i.hidden).length;
  const selected = ifaces?.find((i) => i.name === cap.interface);

  async function save(start: boolean) {
    setErr(null);
    try {
      await api.saveSettings(s!);
      setDirty(false);
      if (start) {
        await api.startCapture();
        onMessage(status?.running ? "Capture restarted with the new settings." : "Capture started.");
      } else onMessage("Capture settings saved.");
      refresh();
    } catch (e) {
      setErr(String(e));
      recheckAccess();
    }
  }

  async function runTest() {
    if (!cap.interface) return;
    setTesting(true);
    setTest(null);
    try {
      setTest(await api.testInterface(cap.interface, cap.monitorMode, cap.promiscuous));
    } catch (e) {
      setTest({ ok: false, linktype: null, packets: 0, decoded: 0, withRssi: 0, seconds: 0, message: String(e) });
    } finally {
      setTesting(false);
    }
  }

  async function fix() {
    setFixing(true);
    try {
      onMessage(await api.fixAccess());
    } catch (e) {
      setErr(String(e));
    } finally {
      setFixing(false);
      recheckAccess();
    }
  }

  async function browse() {
    const f = await open({ multiple: false, filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }] });
    if (typeof f === "string") setCap({ filePath: f });
  }

  return (
    <>
      {err && <div className="banner error"><Icon name="octagon" /><div className="grow">{err}</div></div>}

      {/* Permission status */}
      <div className={`banner ${access == null ? "" : access.ok ? "ok" : "warn"}`}>
        <Icon name={access?.ok ? "shield" : "lock"} />
        <div className="grow">
          <b>{access == null ? "Checking capture permission…" : access.ok ? "Live capture allowed" : "Live capture not permitted yet"}</b>
          {access && <div className="small dim" style={{ marginTop: 2 }}>{access.message}</div>}
        </div>
        {access && !access.ok && access.canFix && (
          <button className="btn primary sm" onClick={fix} disabled={fixing}>{fixing ? "Waiting for approval…" : "Grant access…"}</button>
        )}
        <button className="btn sm ghost" onClick={() => recheckAccess()}><Icon name="refresh" size={12} /> Re-check</button>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Capture source</h2>
          <div className="right">
            <div className="seg">
              {(["live", "simulator", "file"] as Source[]).map((src) => (
                <button key={src} className={cap.source === src ? "on" : ""} onClick={() => setCap({ source: src })}>
                  <Icon name={src === "live" ? "wifi" : src === "simulator" ? "beaker" : "file"} size={14} />
                  {src === "simulator" ? "Simulator" : src === "live" ? "Network interface" : "Capture file"}
                </button>
              ))}
            </div>
          </div>
        </div>

        {cap.source === "simulator" && (
          <p className="dim" style={{ margin: 0 }}>
            Simulates a monitor-mode capture of a smart home — camera, thermostat, smart plug, speaker, TV, laptop, phone,
            neighbors' APs and passers-by, with DHCP/mDNS/SSDP identity traffic. After the learning period it replays attacks:
            a camera beaconing to a Tor relay, a Mirai-style telnet scan, thermostat data exfiltration, a deauth flood and a
            rogue device joining.
          </p>
        )}

        {cap.source === "file" && (
          <div className="field">
            <label>Capture file</label>
            <div className="row" style={{ flexWrap: "nowrap" }}>
              <input className="input mono" style={{ flex: 1 }} value={cap.filePath ?? ""} placeholder="/path/to/capture.pcapng"
                onChange={(e) => setCap({ filePath: e.target.value })} />
              <button className="btn" onClick={browse}><Icon name="folder" size={14} /> Browse…</button>
            </div>
            <span className="hint">802.11 + radiotap, raw 802.11, Ethernet or Linux cooked captures. Timestamps come from the file.</span>
          </div>
        )}

        {cap.source === "live" && (
          <div className="stack" style={{ gap: 18 }}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="dim small">Pick the adapter to listen on. The recommended one carries your internet connection.</span>
              <div className="row">
                {hidden > 0 && (
                  <button className="btn sm ghost" onClick={() => setShowAll((v) => !v)}>
                    {showAll ? "Hide virtual / inactive" : `Show all (${hidden} hidden)`}
                  </button>
                )}
                <button className="btn sm" onClick={loadIfaces}><Icon name="refresh" size={12} /> Refresh</button>
              </div>
            </div>
            {ifErr && <div className="banner error"><Icon name="octagon" /><div>{ifErr}</div></div>}
            {ifaces === null && <div className="empty">Detecting interfaces…</div>}
            <div className="ifaces">
              {list.map((i) => (
                <button key={i.name} className={`iface ${cap.interface === i.name ? "sel" : ""} ${!i.ipv4.length && !i.isDefault ? "off" : ""}`}
                  onClick={() => setCap({ interface: i.name, monitorMode: i.kind === "wifi" ? cap.monitorMode : false })}>
                  <div className="top">
                    <span className={`avatar ${i.isDefault ? "net" : ""}`}><Icon name={ifIcon(i)} /></span>
                    <div style={{ minWidth: 0 }}>
                      <div className="name ellipsis">{i.friendly}</div>
                      <div className="mono small muted ellipsis">{i.name}</div>
                    </div>
                    {cap.interface === i.name && <span style={{ marginLeft: "auto", color: "var(--accent)" }}><Icon name="check" /></span>}
                  </div>
                  <div className="chips">
                    {i.isDefault && <span className="chip accent">recommended</span>}
                    <span className="chip">{i.kind === "wifi" ? "Wi-Fi" : i.kind}</span>
                    {i.ipv4.length ? <span className="chip mono">{i.ipv4[0]}</span> : <span className="chip">{i.up ? "not connected" : "down"}</span>}
                    {i.network && <span className="chip mono">{i.network}</span>}
                  </div>
                  {(i.mac || i.gateway) && (
                    <div className="muted small mono">{i.mac}{i.gateway ? ` · gw ${i.gateway}` : ""}</div>
                  )}
                </button>
              ))}
            </div>

            {selected && (
              <div className="card flat" style={{ background: "var(--surface-2)" }}>
                <div className="card-head">
                  <h3>Mode for {selected.friendly}</h3>
                  <div className="right">
                    <button className="btn sm" onClick={runTest} disabled={testing}>
                      <Icon name="zap" size={12} /> {testing ? "Testing (3 s)…" : "Test interface"}
                    </button>
                  </div>
                </div>
                <div className="seg" style={{ marginBottom: 12 }}>
                  <button className={!cap.monitorMode ? "on" : ""} onClick={() => setCap({ monitorMode: false })}>
                    <Icon name="globe" size={14} /> Managed (network traffic)
                  </button>
                  <button className={cap.monitorMode ? "on" : ""} onClick={() => setCap({ monitorMode: true })} disabled={selected.kind !== "wifi"}
                    title={selected.kind !== "wifi" ? "Monitor mode needs a Wi-Fi adapter" : ""}>
                    <Icon name="radar" size={14} /> Monitor (raw 802.11)
                  </button>
                </div>
                <div className="dim small" style={{ marginBottom: 14 }}>
                  {cap.monitorMode
                    ? "Hears every nearby Wi-Fi device: MACs, signal strength, SSIDs, probes, deauth attacks. Data on WPA2/WPA3 networks stays encrypted, and this adapter leaves its network while monitoring."
                    : "Sees this computer's traffic plus LAN broadcasts (ARP, DHCP, mDNS, SSDP) — names and identifies devices, and builds destination baselines. Use Devices → Scan network to find everything on the subnet. On a router/mirror port it sees all traffic."}
                </div>
                {test && (
                  <div className={`banner ${test.ok ? "ok" : "error"}`} style={{ marginBottom: 14 }}>
                    <Icon name={test.ok ? "check" : "octagon"} />
                    <div className="grow">
                      {test.message}
                      {test.linktype && <div className="small dim">Link type: {test.linktype} · decoded {test.decoded}/{test.packets}{test.withRssi ? ` · ${test.withRssi} with RSSI` : ""}</div>}
                    </div>
                  </div>
                )}
                <div className="form-grid">
                  <Toggle checked={cap.promiscuous} onChange={(v) => setCap({ promiscuous: v })}>Promiscuous mode</Toggle>
                </div>
                {cap.monitorMode && (
                  <div className="form-grid" style={{ marginTop: 14 }}>
                    <div className="field">
                      <label>Channel</label>
                      <select className="select" value={cap.channel ?? ""} disabled={cap.hop}
                        onChange={(e) => setCap({ channel: e.target.value ? Number(e.target.value) : null })}>
                        <option value="">Leave unchanged</option>
                        <optgroup label="2.4 GHz">{CH_24.map((c) => <option key={c} value={c}>{c}</option>)}</optgroup>
                        <optgroup label="5 GHz">{CH_5.map((c) => <option key={c} value={c}>{c}</option>)}</optgroup>
                      </select>
                    </div>
                    <div className="field">
                      <span className="label">Channel hopping</span>
                      <Toggle checked={cap.hop} onChange={(v) => setCap({ hop: v })}>Cycle through channels</Toggle>
                      <input className="input mono" disabled={!cap.hop} value={cap.hopChannels.join(", ")}
                        onChange={(e) => setCap({ hopChannels: e.target.value.split(/[\s,]+/).map(Number).filter((n) => n > 0) })} />
                    </div>
                    <div className="field">
                      <label>Dwell per channel</label>
                      <div className="row" style={{ flexWrap: "nowrap" }}>
                        <input className="input num" type="number" min={100} step={100} value={cap.hopDwellMs} style={{ width: 110 }}
                          onChange={(e) => setCap({ hopDwellMs: Number(e.target.value) })} />
                        <span className="muted">ms</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="field">
              <label>BPF capture filter (optional)</label>
              <input className="input mono" value={cap.bpfFilter} placeholder={cap.monitorMode ? "e.g. not subtype beacon" : "e.g. not port 22"}
                onChange={(e) => setCap({ bpfFilter: e.target.value })} />
              <span className="hint">Standard tcpdump syntax, applied in the kernel.</span>
            </div>
          </div>
        )}
      </div>

      <PlatformGuide platform={access?.platform} />

      <div className="savebar">
        <button className="btn primary" onClick={() => save(true)}>
          <Icon name="play" size={14} /> Save &amp; {status?.running ? "restart" : "start"} capture
        </button>
        <button className="btn" onClick={() => save(false)} disabled={!dirty}>Save only</button>
        {dirty && <span className="muted small">Unsaved changes</span>}
      </div>
    </>
  );
}

function PlatformGuide({ platform }: { platform?: string }) {
  const [tab, setTab] = useState<string>(platform ?? "macos");
  useEffect(() => {
    if (platform) setTab(platform);
  }, [platform]);
  return (
    <div className="card">
      <div className="card-head">
        <h2>Setup guide</h2>
        <span className="sub">what each OS needs for live and monitor-mode capture</span>
        <div className="right">
          <div className="seg">
            {[["macos", "macOS"], ["linux", "Linux"], ["windows", "Windows"]].map(([k, l]) => (
              <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}{platform === k ? " ·  this PC" : ""}</button>
            ))}
          </div>
        </div>
      </div>
      {tab === "macos" && (
        <ol className="dim" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
          <li><b>Permission:</b> click <i>Grant access</i> above (admin password, lasts until reboot) or install Wireshark's <span className="mono">ChmodBPF</span> for a permanent fix.</li>
          <li><b>Managed mode</b> works on any interface (Ethernet / Wi-Fi) — recommended for device discovery and destination baselines.</li>
          <li><b>Monitor mode</b> works on many Macs' built-in Wi-Fi; the Mac leaves its Wi-Fi network while monitoring. Newer macOS can't switch channel programmatically — use the channel the Mac was on, or Wireless Diagnostics → Window → Sniffer and open the file here.</li>
        </ol>
      )}
      {tab === "linux" && (
        <ol className="dim" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
          <li><b>Permission:</b> click <i>Grant access</i> (uses <span className="mono">pkexec setcap cap_net_raw,cap_net_admin=eip</span>) and restart Niv.ON.</li>
          <li><b>Monitor mode</b> needs a capable adapter (e.g. Atheros AR9271, MediaTek MT7612U/MT7921AU, Realtek RTL8812AU with proper driver). Stop NetworkManager managing it: <span className="mono">nmcli dev set wlan1 managed no</span>.</li>
          <li>Channel switching and hopping use <span className="mono">iw</span> — fully supported.</li>
        </ol>
      )}
      {tab === "windows" && (
        <ol className="dim" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
          <li><b>Install Npcap</b> from npcap.com — tick <i>“Support raw 802.11 traffic (and monitor mode) for wireless adapters”</i>.</li>
          <li>Managed-mode capture works as a normal user. For <b>monitor mode</b> run Niv.ON as Administrator; channels are set with Npcap's <span className="mono">WlanHelper.exe</span>.</li>
          <li>Many built-in Intel/Realtek adapters don't support monitor mode on Windows — use the Test button to check.</li>
        </ol>
      )}
      <div className="banner" style={{ marginTop: 14 }}>
        <Icon name="info" />
        <div className="small">
          On WPA2/WPA3 networks, monitor mode sees frame headers, MACs, RSSI and SSIDs — not IPs or DNS (encrypted). For
          per-device destination baselines, capture in managed mode on the gateway, a mirrored switch port, a Raspberry Pi
          access point, or an open lab network.
        </div>
      </div>
    </div>
  );
}
