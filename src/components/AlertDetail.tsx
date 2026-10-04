import { useEffect, useState } from "react";
import { api, type Alert, type AlertStatus, type DeviceDetail } from "../api";
import { dateTime } from "../format";
import { useNav } from "../nav";
import { useLive } from "../store";
import { ruleLabel, STATUS_LABEL } from "./AlertList";
import { Avatar, Icon } from "./Icon";
import { Mac } from "./Mac";
import { RiskBreakdown } from "./RiskBreakdown";
import { SeverityBadge } from "./Severity";

/** How to respond, per detection. Practical first steps, not speculation. */
const RESPONSE: Record<string, string[]> = {
  "threat-intel": [
    "The device reached infrastructure listed by a threat feed. Treat it as compromised until shown otherwise.",
    "Isolate it: move it to a guest/IoT network or block its MAC on the router.",
    "Check the Connections tab for what was sent, then factory-reset and update the device; scan laptops/phones with antivirus.",
  ],
  "ids-signature": [
    "Inbound (from the internet): someone is attacking this device. Remove port forwards / disable UPnP so it isn't reachable, and update its firmware.",
    "Outbound or LAN-to-LAN: the device itself is likely infected. Isolate it, reset it, update firmware, change its password.",
    "Open the packet evidence in Wireshark to confirm what was sent.",
  ],
  "arp-spoof": [
    "Another device is answering for your router — a man-in-the-middle. Find it by MAC in the router/AP client list and disconnect it.",
    "Enable client isolation / Dynamic ARP Inspection on the access point or switch if available.",
    "Treat traffic since the alert as intercepted: change passwords entered in that window.",
  ],
  "ip-conflict": [
    "Two devices claimed the same address. If one has a static IP, move it outside the DHCP range.",
    "If neither should, it may be ARP poisoning — check which MAC is unfamiliar and disconnect it.",
  ],
  "rogue-router": [
    "A device is advertising itself as an IPv6 router (mitm6-style attack). Identify it by MAC and disconnect it.",
    "Enable RA Guard / client isolation on the switch or AP; disable IPv6 if you don't use it.",
  ],
  "risky-port": [
    "Telnet, SMB, RDP, ADB or a known exploit port from an IoT device is a classic botnet sign.",
    "Isolate the device, factory-reset it, update firmware and set a unique password. Disable Telnet if the device allows it.",
  ],
  "unexpected-port": [
    "The device used a service port it never used while learning. Check the destination below.",
    "If it's an expected new feature (app update), use Mark as normal; otherwise block the destination and watch for repeats.",
  ],
  "new-destination": [
    "Look up who owns the destination (name, IP owner). IoT devices normally talk to a fixed set of vendor servers.",
    "If it's a legitimate new cloud endpoint, Mark as normal. If not, block it on the firewall and check for firmware updates.",
  ],
  "suspicious-domain": [
    "Random-looking lookups are how malware finds its command server (domain generation algorithms).",
    "Check the DNS log for more lookups like this; if they keep coming, isolate and reset the device.",
  ],
  "volume-spike": [
    "Far more traffic than this device ever sent while learning — possible data exfiltration or DDoS participation.",
    "Check the destinations in the Connections tab. Block unknown ones; Mark as normal for expected bulk transfers (backups, updates).",
  ],
  "connection-burst": [
    "Many connection attempts in seconds means scanning — typical of worm infections (Mirai scans for Telnet).",
    "Isolate the device right away, then reset and update it.",
  ],
  "unusual-time": [
    "Heavy activity outside the device's normal hours. Confirm whether someone used it or an update ran.",
    "Unexplained night-time uploads from cameras or speakers deserve investigation of the destinations.",
  ],
  "deauth-flood": [
    "Someone nearby is forcing clients off Wi-Fi (often to capture WPA handshakes or push an evil twin).",
    "Enable WPA3 or Protected Management Frames (802.11w) on the access point; use strong Wi-Fi passwords.",
  ],
  "new-device": [
    "Confirm you recognise the device. If not, block its MAC on the router and review who has the Wi-Fi password.",
    "Give unknown or guest devices their own network.",
  ],
  "fingerprint-change": [
    "The device's TLS client changed — new firmware, a new app, or malware. Check whether the vendor shipped an update.",
    "If there was no update, look at the new destinations it contacted and isolate it if they're unfamiliar.",
  ],
  "identity-change": [
    "The DHCP fingerprint on this MAC changed: another device may be spoofing it, or it was reset/replaced.",
    "Physically check the device; if it wasn't changed, block the MAC and investigate.",
  ],
  "peer-anomaly": [
    "This device behaves very differently from others of its type — likely misconfigured or compromised.",
    "Compare its destinations with a peer's; isolate it if the extra hosts are unknown.",
  ],
  "risk-threshold": [
    "Several independent detections on one device — the strongest sign of compromise Niv.ON produces.",
    "Isolate the device now, then work through its timeline to see how it started.",
  ],
  "custom-detection": ["Your own detection matched. Open it under Detections to see the search and why it fired."],
};

function Endpoint({ title, mac, ip, port, label }: { title: string; mac: string | null; ip: string | null; port: number | null; label?: string | null }) {
  return (
    <div className="endpoint">
      <div className="label-caps">{title}</div>
      {label && <div className="name ellipsis">{label}</div>}
      <div className="mono small">{ip ?? "—"}{port != null ? `:${port}` : ""}</div>
      {mac && <div className="small"><Mac mac={mac} /></div>}
    </div>
  );
}

/** Everything needed to understand and act on one alert. */
export function AlertDetail({ alert: a, onClose, onChange }: { alert: Alert; onClose: () => void; onChange: () => void }) {
  const nav = useNav();
  const { status } = useLive();
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [labels, setLabels] = useState<Map<string, string>>(new Map());
  const [busy, setBusy] = useState(false);
  const c = a.context;

  useEffect(() => {
    setDevice(null);
    if (a.device) api.getDevice(a.device).then(setDevice).catch(() => {});
    api.getDevices().then((l) => setLabels(new Map(l.map((d) => [d.mac, d.label])))).catch(() => {});
  }, [a.device, a.id]);

  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose]);

  async function evidence() {
    setBusy(true);
    try {
      const p = a.evidence ?? (await api.saveEvidence(a.id));
      await api.revealPath(p);
      onChange();
    } catch (e) {
      window.alert(String(e));
    } finally {
      setBusy(false);
    }
  }

  const steps = RESPONSE[a.rule] ?? ["Review the device's timeline and connections to decide whether this activity is expected."];
  const arrow = c?.direction === "inbound" ? "from the internet" : c?.direction === "outbound" ? "to the internet" : "inside the network";

  return (
    <div className="drawer-overlay" onMouseDown={onClose}>
      <aside className="drawer" onMouseDown={(e) => e.stopPropagation()} aria-label="Alert details">
        <div className="drawer-head">
          <div className="row" style={{ gap: 8 }}>
            <SeverityBadge s={a.urgency ?? a.severity} />
            <span className="muted small">{ruleLabel(a.rule)} · #{a.id} · {dateTime(a.ts)}</span>
          </div>
          <button className="btn sm ghost icon" onClick={onClose} title="Close (Esc)"><Icon name="x" size={14} /></button>
        </div>
        <h2 className="drawer-title">{a.title}</h2>
        <p className="dim" style={{ marginTop: 4 }}>{a.message}</p>

        <div className="row" style={{ gap: 8, margin: "12px 0 4px" }}>
          <select className="select" value={a.status} aria-label="Status"
            onChange={(e) => api.updateAlerts([a.id], { status: e.target.value as AlertStatus }).then(onChange)}>
            {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
          {a.device && <button className="btn sm" onClick={() => nav.openDevice(a.device!, "timeline")}><Icon name="clock" size={12} /> Device timeline</button>}
          {a.device && (a.evidence || status?.evidence) && (
            <button className="btn sm" disabled={busy} onClick={evidence} title="The device's packets from the two minutes before the alert, as a Wireshark file">
              <Icon name="file" size={12} /> {a.evidence ? "Show evidence" : busy ? "Saving…" : "Save evidence"}
            </button>
          )}
        </div>
        {a.urgency && a.urgency !== a.severity && (
          <div className="muted small">Urgency {a.urgency} = severity {a.severity} adjusted for the device's {device?.priority ?? ""} asset priority.</div>
        )}

        <section className="drawer-section">
          <h3>What was seen</h3>
          {!c ? (
            <div className="muted small">This alert was raised from aggregated behaviour or saved before request details were recorded.</div>
          ) : (
            <>
              <div className="flow-diagram">
                <Endpoint title="Source" mac={c.srcMac} ip={c.srcIp} port={c.srcPort} label={c.srcMac ? labels.get(c.srcMac) : null} />
                <div className="flow-arrow">
                  <span className="chip mono">{c.service ?? c.protocol}</span>
                  <svg viewBox="0 0 120 12" preserveAspectRatio="none" aria-hidden="true"><path d="M0 6h112M106 1l7 5-7 5" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
                  <span className="muted small">{c.transport ?? ""} · {arrow}</span>
                </div>
                <Endpoint title="Destination" mac={c.dstMac} ip={c.dstIp} port={c.dstPort} label={c.dstMac ? labels.get(c.dstMac) ?? c.domain : c.domain} />
              </div>
              <dl className="kv" style={{ marginTop: 12 }}>
                <dt>Request</dt><dd className="mono small" style={{ overflowWrap: "anywhere" }}>{c.summary}</dd>
                <dt>Protocol</dt><dd>{c.protocol}{c.transport ? ` over ${c.transport}` : ""}</dd>
                {c.domain && (<><dt>Name</dt><dd className="mono small">{c.domain}</dd></>)}
                <dt>Frame size</dt><dd>{c.frameLen} bytes</dd>
              </dl>
              {c.aggregate && (
                <div className="banner" style={{ marginTop: 10 }}>
                  <Icon name="info" />
                  <div className="grow small">This rule measures a pattern over time; the request above is the one that crossed the threshold, not the only one involved.</div>
                </div>
              )}
              {c.payload && (
                <>
                  <div className="label-caps" style={{ marginTop: 12 }}>Payload (first bytes)</div>
                  <pre className="payload">{c.payload}</pre>
                </>
              )}
              {!c.payload && c.payloadHex && (
                <>
                  <div className="label-caps" style={{ marginTop: 12 }}>Payload (hex — encrypted or binary)</div>
                  <pre className="payload">{c.payloadHex}</pre>
                </>
              )}
            </>
          )}
        </section>

        <section className="drawer-section">
          <h3>Recommended response</h3>
          <ol className="steps">{steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
          {a.mitreId && (
            <div className="muted small" style={{ marginTop: 8 }}>
              MITRE ATT&amp;CK <span className="mono">{a.mitreId}</span> {a.mitreName} · tactic: {a.tactic}
            </div>
          )}
        </section>

        {a.device && (
          <section className="drawer-section">
            <h3>Affected device</h3>
            {!device ? <div className="muted small">Loading…</div> : (
              <>
                <div className="dev-cell" style={{ marginBottom: 10 }}>
                  <Avatar cls={device.class} iot={device.isIot} net={device.isGateway || device.isAp} self={device.isSelf} />
                  <div style={{ minWidth: 0 }}>
                    <button className="linkish name" onClick={() => nav.openDevice(device.mac)}>{device.label}</button>
                    <div className="muted small">{device.class} · {device.ips[0] ?? device.mac} · {device.vendor ?? (device.randomized ? "randomized MAC" : "unknown vendor")} · {device.priority} priority</div>
                  </div>
                </div>
                <RiskBreakdown parts={device.riskParts} score={device.risk} />
              </>
            )}
          </section>
        )}

        {a.notes.length > 0 && (
          <section className="drawer-section">
            <h3>Activity</h3>
            {a.notes.map((n, i) => (
              <div key={i} className="note"><span className="mono muted small">{dateTime(n.ts)}</span><span className="small">{n.text}</span></div>
            ))}
          </section>
        )}
      </aside>
    </div>
  );
}
