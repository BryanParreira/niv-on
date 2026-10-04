import { useEffect, useMemo, useState } from "react";
import { api, TAG_PRESETS, type DeviceDetail as Detail } from "../api";
import { AlertList } from "../components/AlertList";
import { Avatar, Icon } from "../components/Icon";
import { Mac } from "../components/Mac";
import { Signal } from "../components/Signal";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { ago, dateTime, fmtBytes, fmtNum, fmtRate } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

type Tab = "overview" | "comms" | "baseline" | "wireless" | "alerts";

export function DeviceDetail({ mac, onName }: { mac: string; onName: (n: string) => void }) {
  const { status } = useLive();
  const nav = useNav();
  const [d, reload] = usePoll(() => api.getDevice(mac), 2000, [mac]);
  const [tab, setTab] = useState<Tab>((nav.route.tab as Tab) ?? "overview");
  const clock = status?.clock ?? new Date().toISOString();

  useEffect(() => {
    if (d) onName(d.label);
  }, [d, onName]);

  if (!d) {
    return (
      <div className="card">
        <div className="empty">Loading device… (if this persists, the device was removed)</div>
      </div>
    );
  }

  const openAlerts = d.alerts.filter((a) => !a.acknowledged).length;
  const dests = Object.keys(d.destinations).length;
  const newDests = Object.values(d.destinations).filter((x) => !x.inBaseline).length;

  async function relearn() {
    if (!confirm("Discard this device's baseline and start learning again from now?")) return;
    await api.relearnDevice(mac);
    reload();
  }
  async function forget() {
    if (!confirm("Remove this device and its history? It will be re-discovered if seen again.")) return;
    await api.forgetDevice(mac);
    nav.go("devices");
  }

  const tabs: { id: Tab; label: string; badge?: number | string }[] = [
    { id: "overview", label: "Overview" },
    { id: "comms", label: "Communications", badge: newDests ? `${newDests} new` : dests || undefined },
    { id: "baseline", label: "Baseline & schedule" },
    { id: "wireless", label: "Wireless" },
    { id: "alerts", label: "Alerts", badge: openAlerts || undefined },
  ];

  return (
    <>
      <div className="card">
        <div className="row" style={{ alignItems: "flex-start", justifyContent: "space-between", flexWrap: "nowrap", gap: 16 }}>
          <div className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap", gap: 14, minWidth: 0 }}>
            <Avatar cls={d.class} iot={d.isIot} net={d.isGateway || d.isAp} self={d.isSelf} large />
            <div style={{ minWidth: 0 }}>
              <h2 style={{ margin: 0, fontSize: 22, fontFamily: "var(--display)", fontWeight: 600 }}>{d.label}</h2>
              <div className="muted" style={{ marginTop: 3 }}>
                <Mac mac={d.mac} /> · {d.vendor ?? (d.randomized ? "randomized (private) MAC" : "unknown vendor")}
                {d.ips.length > 0 && <> · <span className="mono">{d.ips.slice(0, 3).join(", ")}</span></>}
              </div>
              <div className="chips" style={{ marginTop: 10 }}>
                <span className="chip outline">{d.class}</span>
                {d.tag && d.tag !== d.autoClass && <span className="chip">auto: {d.autoClass}</span>}
                {d.isIot && <span className="chip good">IoT</span>}
                {d.isSelf && <span className="chip">this computer</span>}
                {d.isGateway && <span className="chip accent">gateway / router</span>}
                {d.isAp && <span className="chip accent">access point</span>}
                {d.randomized && <span className="chip">randomized MAC</span>}
                {d.learning ? <span className="chip">learning baseline</span> : <span className="chip"><Icon name="lock" size={11} /> baseline locked</span>}
              </div>
            </div>
          </div>
          <div className="row" style={{ flexWrap: "nowrap" }}>
            <button className="btn" onClick={relearn}><Icon name="refresh" size={14} /> Re-learn</button>
            <button className="btn danger icon" onClick={forget} title="Forget device"><Icon name="trash" size={14} /></button>
          </div>
        </div>
      </div>

      <div className="tabs">
        {tabs.map((t) => (
          <button key={t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
            {t.label}
            {t.badge != null && <span className="badge">{t.badge}</span>}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview d={d} clock={clock} reload={reload} mac={mac} />}
      {tab === "comms" && <Comms d={d} />}
      {tab === "baseline" && <BaselineTab d={d} />}
      {tab === "wireless" && <Wireless d={d} clock={clock} />}
      {tab === "alerts" && (
        <div className="card">
          <AlertList alerts={d.alerts} onChange={reload} hideDevice empty="No alerts raised for this device." />
        </div>
      )}
    </>
  );
}

function Overview({ d, clock, reload, mac }: { d: Detail; clock: string; reload: () => void; mac: string }) {
  const history = useMemo(() => {
    const now = Math.floor(Date.parse(clock) / 1000);
    const map = new Map(d.history);
    const times: number[] = [];
    const values: number[] = [];
    for (let t = now - 299; t <= now; t++) {
      times.push(t);
      values.push(map.get(t) ?? 0);
    }
    return { times, values };
  }, [d, clock]);

  return (
    <>
      <div className="kpis">
        <div className="card kpi">
          <div className="label"><Icon name="wifi" size={14} />Signal</div>
          <div className="value" style={{ fontSize: 20 }}><Signal rssi={d.rssi} /></div>
          <div className="foot">avg {d.rssiAvg != null ? `${d.rssiAvg.toFixed(0)} dBm` : "—"}{d.channel ? ` · channel ${d.channel}` : ""}</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="activity" size={14} />Sent / received</div>
          <div className="value" style={{ fontSize: 20 }}>{fmtBytes(d.txBytes)} / {fmtBytes(d.rxBytes)}</div>
          <div className="foot">{fmtNum(d.txPackets)} / {fmtNum(d.rxPackets)} frames</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="globe" size={14} />Hosts contacted</div>
          <div className="value" style={{ fontSize: 20 }}>{Object.keys(d.destinations).length}</div>
          <div className="foot">{Object.keys(d.ports).length} service ports</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="refresh" size={14} />Last seen</div>
          <div className="value" style={{ fontSize: 20 }}>{ago(d.lastSeen, clock)}</div>
          <div className="foot">first {dateTime(d.firstSeen)}</div>
        </div>
      </div>

      <div className="split">
        <div className="grid">
          <div className="card">
            <div className="card-head"><h3>Throughput</h3><span className="sub">last 5 minutes, sent + received</span></div>
            <TimeSeriesChart times={history.times}
              series={[{ key: "b", label: "Throughput", color: "var(--mono-series)", values: history.values }]}
              format={fmtRate} minMax={1000} area height={180} />
          </div>
          <div className="card">
            <div className="card-head"><h3>Identity clues</h3><span className="sub">how Niv.ON recognized this device</span></div>
            <dl className="kv">
              <dt>Vendor (OUI)</dt><dd>{d.vendor ?? (d.randomized ? "Hidden — randomized MAC" : "Unknown")}</dd>
              <dt>Hostnames</dt><dd>{d.hostnames.length ? d.hostnames.join(", ") : <span className="muted">none seen (DHCP / mDNS)</span>}</dd>
              <dt>OS / firmware hint</dt><dd>{d.vendorClass ?? <span className="muted">—</span>}</dd>
              <dt>Advertised services</dt>
              <dd>{d.services.length ? <div className="chips">{d.services.map((s) => <span key={s} className="chip mono">{s}</span>)}</div> : <span className="muted">—</span>}</dd>
              <dt>Banners</dt>
              <dd>{d.banners.length ? d.banners.map((b) => <div key={b} className="mono small">{b}</div>) : <span className="muted">— (UPnP server / HTTP user-agent)</span>}</dd>
              <dt>Frames</dt>
              <dd>mgmt {fmtNum(d.frames.management)} · ctrl {fmtNum(d.frames.control)} · data {fmtNum(d.frames.data)} · ethernet {fmtNum(d.frames.ethernet)}</dd>
            </dl>
          </div>
        </div>
        <TagEditor d={d} mac={mac} reload={reload} />
      </div>
    </>
  );
}

function TagEditor({ d, mac, reload }: { d: Detail; mac: string; reload: () => void }) {
  const [name, setName] = useState(d.name ?? "");
  const [tag, setTag] = useState(d.tag ?? "");
  const [notes, setNotes] = useState(d.notes);
  const [editing, setEditing] = useState(false);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (!editing) {
      setName(d.name ?? "");
      setTag(d.tag ?? "");
      setNotes(d.notes);
    }
  }, [d, editing]);
  const edit = <T,>(fn: (v: T) => void) => (v: T) => {
    setEditing(true);
    fn(v);
  };
  async function save() {
    await api.updateDevice(mac, { name, tag, notes });
    setEditing(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
    reload();
  }
  return (
    <div className="card" style={{ alignSelf: "start" }}>
      <div className="card-head"><h3>Identify &amp; tag</h3>{saved && <span className="chip good"><Icon name="check" size={11} /> saved</span>}</div>
      <div className="stack">
        <div className="field">
          <label htmlFor="dname">Friendly name</label>
          <input id="dname" className="input" placeholder={d.hostname ?? "e.g. Front door camera"} value={name}
            onChange={(e) => edit(setName)(e.target.value)} />
        </div>
        <div className="field">
          <span className="label">Device type</span>
          <div className="chips">
            {TAG_PRESETS.map((t) => (
              <button key={t} className={`chip ${tag === t ? "on" : ""}`} onClick={() => edit(setTag)(tag === t ? "" : t)}>{t}</button>
            ))}
          </div>
          <input className="input" placeholder="…or a custom tag" value={TAG_PRESETS.includes(tag) ? "" : tag}
            onChange={(e) => edit(setTag)(e.target.value)} />
          <span className="hint">Auto-classified as “{d.autoClass}”. IoT types get stricter anomaly rules.</span>
        </div>
        <div className="field">
          <label htmlFor="dnotes">Notes</label>
          <textarea id="dnotes" className="input" rows={3} value={notes} placeholder="Location, owner, purchase date…"
            onChange={(e) => edit(setNotes)(e.target.value)} />
        </div>
        <div className="row">
          <button className="btn primary" onClick={save} disabled={!editing}>Save</button>
          {editing && <button className="btn ghost" onClick={() => setEditing(false)}>Cancel</button>}
        </div>
      </div>
    </div>
  );
}

function Comms({ d }: { d: Detail }) {
  const [q, setQ] = useState("");
  const [onlyNew, setOnlyNew] = useState(false);
  const dests = Object.values(d.destinations)
    .filter((x) => !onlyNew || !x.inBaseline)
    .filter((x) => !q || `${x.ip} ${x.domain ?? ""} ${x.ports.join(" ")}`.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => b.txBytes + b.rxBytes - (a.txBytes + a.rxBytes));
  const ports = Object.entries(d.ports).sort((a, b) => b[1] - a[1]);
  return (
    <div className="split">
      <div className="card pad0">
        <div className="card-head" style={{ padding: "16px 16px 0" }}>
          <h3>Communication destinations</h3>
          <span className="sub">names from DNS answers and TLS SNI</span>
          <div className="right">
            <label className="toggle small"><input type="checkbox" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)} />Only new</label>
            <div className="search"><Icon name="search" size={14} /><input className="input" style={{ width: 200 }} placeholder="Filter hosts…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          </div>
        </div>
        <div className="table-wrap" style={{ maxHeight: 560 }}>
          <table className="t">
            <thead>
              <tr><th>Host</th><th>Ports</th><th className="r">Sent</th><th className="r">Received</th><th className="r">First seen</th><th>Baseline</th></tr>
            </thead>
            <tbody>
              {dests.map((x) => (
                <tr key={x.ip}>
                  <td>
                    <div>{x.domain ?? <span className="muted">no name</span>}</div>
                    <div className="muted mono small">{x.ip}{x.external ? "" : " · LAN"}</div>
                  </td>
                  <td className="mono small">{x.ports.join(", ") || "—"}</td>
                  <td className="r num">{fmtBytes(x.txBytes)}</td>
                  <td className="r num">{fmtBytes(x.rxBytes)}</td>
                  <td className="r muted small">{dateTime(x.firstSeen)}</td>
                  <td>
                    {x.inBaseline ? <span className="chip"><Icon name="check" size={12} /> normal</span>
                      : <span className="sev medium"><Icon name="alerts" size={12} /> new</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {dests.length === 0 && (
            <div className="empty">
              {Object.keys(d.destinations).length
                ? "No hosts match."
                : "No IP-layer traffic seen. In monitor mode WPA2/WPA3 data is encrypted — destinations need an open network or a managed-mode / gateway capture."}
            </div>
          )}
        </div>
      </div>
      <div className="card" style={{ alignSelf: "start" }}>
        <div className="card-head"><h3>Service ports</h3><span className="sub">as a client · outlined = not in baseline</span></div>
        {ports.length === 0 ? <div className="muted">None observed.</div> : (
          <table className="t compact">
            <tbody>
              {ports.map(([p, n]) => (
                <tr key={p}>
                  <td><span className={`chip mono ${d.baseline.ports.includes(Number(p)) ? "" : "outline"}`}>{p}</span></td>
                  <td className="r num dim">{fmtNum(n)} pkts</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function BaselineTab({ d }: { d: Detail }) {
  const maxHour = Math.max(1, ...d.hourly);
  return (
    <div className="two">
      <div className="card">
        <div className="card-head"><h3>Behavioral baseline</h3><span className="sub">{d.learning ? "learning" : "locked"}</span></div>
        {d.learning ? (
          <div className="stack" style={{ marginBottom: 14 }}>
            <div className="progress"><div style={{ width: `${d.learningProgress * 100}%` }} /></div>
            <div className="muted small">
              Recording normal behavior until {dateTime(d.baseline.learningUntil)}. Rules (except risky ports and scans) start afterwards.
            </div>
          </div>
        ) : (
          <div className="muted small" style={{ marginBottom: 14 }}>
            Learned {dateTime(d.baseline.learningStarted)} → {dateTime(d.baseline.learningUntil)}. Use “Mark as normal” on alerts to extend it.
          </div>
        )}
        <dl className="kv">
          <dt>Known hosts</dt><dd>{d.baseline.destinations.length}</dd>
          <dt>Known domains</dt>
          <dd>{d.baseline.domains.length ? <div className="chips">{d.baseline.domains.map((x) => <span key={x} className="chip">{x}</span>)}</div> : "—"}</dd>
          <dt>Service ports</dt><dd className="mono">{d.baseline.ports.join(", ") || "—"}</dd>
          <dt>Peak per 10 s</dt><dd>{fmtBytes(d.baseline.peakWindowBytes)}</dd>
          <dt>Average per 10 s</dt><dd>{fmtBytes(d.baseline.avgWindowBytes)}</dd>
        </dl>
      </div>
      <div className="card">
        <div className="card-head">
          <h3>Activity by hour</h3>
          <span className="sub">local time · <span style={{ color: "var(--s3)" }}>▬</span> hours active while learning</span>
        </div>
        <div className="hours">
          {d.hourly.map((v, h) => (
            <div key={h} className={`col ${d.baseline.hours[h] ? "base" : ""}`} title={`${String(h).padStart(2, "0")}:00 — ${fmtNum(v)} frames`}>
              <div className="bar" style={{ height: `${(v / maxHour) * 100}%` }} />
            </div>
          ))}
        </div>
        <div className="hours-axis">{d.hourly.map((_, h) => <span key={h}>{h % 6 === 0 ? `${h}h` : ""}</span>)}</div>
      </div>
    </div>
  );
}

function Wireless({ d, clock }: { d: Detail; clock: string }) {
  const none = d.connections.length === 0 && d.ssids.length === 0 && d.probedSsids.length === 0 && d.rssi == null;
  return (
    <div className="two">
      <div className="card">
        <div className="card-head"><h3>Connection history</h3><span className="sub">access points this device used</span></div>
        {none && <div className="empty">No 802.11 data — capture in monitor mode to see radio details.</div>}
        {d.connections.length > 0 && (
          <table className="t">
            <thead><tr><th>Network</th><th className="r">First</th><th className="r">Last</th><th className="r">Frames</th></tr></thead>
            <tbody>
              {[...d.connections].sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen)).map((c) => (
                <tr key={c.bssid}>
                  <td><div>{c.ssid ?? <span className="muted">unknown SSID</span>}</div><div className="muted small">BSSID <Mac mac={c.bssid} /></div></td>
                  <td className="r muted small">{dateTime(c.firstSeen)}</td>
                  <td className="r muted">{ago(c.lastSeen, clock)}</td>
                  <td className="r num">{fmtNum(c.frames)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="card">
        <div className="card-head"><h3>Radio</h3></div>
        <dl className="kv">
          <dt>Signal</dt><dd><Signal rssi={d.rssi} /></dd>
          <dt>Average</dt><dd>{d.rssiAvg != null ? `${d.rssiAvg.toFixed(1)} dBm` : "—"}</dd>
          <dt>Channel</dt><dd>{d.channel ?? "—"}</dd>
          <dt>Advertised SSIDs</dt>
          <dd>{d.ssids.length ? <div className="chips">{d.ssids.map((s) => <span key={s} className="chip">{s}</span>)}</div> : "—"}</dd>
          <dt>Probed SSIDs</dt>
          <dd>
            {d.probedSsids.length ? <div className="chips">{d.probedSsids.map((s) => <span key={s} className="chip">{s}</span>)}</div> : "—"}
            {d.probedSsids.length > 0 && <div className="muted small" style={{ marginTop: 6 }}>Networks this device remembers — a privacy leak attackers use for evil-twin APs.</div>}
          </dd>
        </dl>
      </div>
    </div>
  );
}
