import { useEffect, useState, type ReactNode } from "react";
import { api, inTauri, type RuleSettings, type Settings } from "../api";
import { Icon } from "../components/Icon";
import { AboutCard } from "../components/UpdateNotice";
import { useLive } from "../store";
import { Toggle } from "./Capture";

function NumField({ label, value, onChange, min, max, step, hint, suffix }: {
  label: string; value: number; onChange: (v: number) => void; min?: number; max?: number; step?: number; hint?: string; suffix?: string;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      <div className="row" style={{ flexWrap: "nowrap" }}>
        <input className="input num" type="number" value={value} min={min} max={max} step={step}
          onChange={(e) => onChange(Number(e.target.value))} style={{ width: 120 }} />
        {suffix && <span className="muted small">{suffix}</span>}
      </div>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

function Rule({ title, desc, on, set, children }: { title: string; desc: string; on: boolean; set: (v: boolean) => void; children?: ReactNode }) {
  return (
    <div className="rule">
      <div className="rule-head">
        <div>
          <div className="rule-title">{title}</div>
          <div className="muted small">{desc}</div>
        </div>
        <Toggle checked={on} onChange={set}>{""}</Toggle>
      </div>
      {on && children && <div className="rule-body">{children}</div>}
    </div>
  );
}

export function Rules({ onMessage }: { onMessage: (m: string) => void }) {
  const { status, refresh } = useLive();
  const [s, setS] = useState<Settings | null>(null);
  const [dirty, setDirty] = useState(false);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    if (inTauri) api.getSettings().then(setS);
  }, []);
  if (!s) return <div className="card"><div className="empty">Loading…</div></div>;
  const r = s.rules;
  const set = (p: Partial<RuleSettings>) => {
    setS({ ...s, rules: { ...r, ...p } });
    setDirty(true);
  };

  async function save() {
    try {
      // Re-read capture settings so we never clobber changes made elsewhere.
      const latest = await api.getSettings();
      await api.saveSettings({ ...latest, rules: s!.rules });
      setDirty(false);
      onMessage("Detection rules saved — active immediately.");
    } catch (e) {
      onMessage(String(e));
    }
  }

  async function exportReport() {
    try {
      onMessage(`Report written to ${await api.exportReport()}`);
    } catch (e) {
      onMessage(String(e));
    }
  }

  async function updateVendors() {
    setUpdating(true);
    try {
      onMessage(await api.updateVendorDb());
      refresh();
    } catch (e) {
      onMessage(String(e));
    } finally {
      setUpdating(false);
    }
  }

  async function reset() {
    if (!confirm("Delete all device profiles, baselines and alerts? This cannot be undone.")) return;
    await api.resetData();
    onMessage("All captured data was deleted.");
    refresh();
  }

  return (
    <>
      <div className="card">
        <div className="card-head">
          <h2>Baseline learning</h2>
          <span className="sub">how long a new device is observed before its behavior counts as “normal”</span>
        </div>
        <div className="form-grid">
          <NumField label="Learning period" value={r.learningMinutes} min={1} suffix="minutes"
            hint="Demo: 2–5 min. Real deployments: 1440+ (24 h) — also enables learned active-hours detection."
            onChange={(v) => set({ learningMinutes: Math.max(1, v) })} />
          <div className="field">
            <span className="label">Presets</span>
            <div className="chips">
              {[["Demo", 2], ["1 hour", 60], ["1 day", 1440], ["1 week", 10080]].map(([l, v]) => (
                <button key={l} className={`chip ${r.learningMinutes === v ? "on" : ""}`} onClick={() => set({ learningMinutes: v as number })}>{l}</button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head"><h2>Detection rules</h2><span className="sub">changes apply immediately after saving</span></div>
        <div className="rules">
          <Rule title="Unknown external destination" on={r.newDestination} set={(v) => set({ newDestination: v })}
            desc="A device contacts an internet host (IP or domain) that is not in its baseline.">
            <Toggle checked={r.newDestinationIotOnly} onChange={(v) => set({ newDestinationIotOnly: v })}>
              Only for IoT devices — laptops and phones reach new hosts constantly
            </Toggle>
          </Rule>
          <Rule title="Unexpected or risky service port" on={r.unexpectedPort} set={(v) => set({ unexpectedPort: v })}
            desc="Outbound connection to a port the device never used while learning. Risky ports alert immediately, even while learning.">
            <div className="field">
              <label>Risky ports</label>
              <input className="input mono" value={r.riskyPorts.join(", ")}
                onChange={(e) => set({ riskyPorts: e.target.value.split(/[\s,]+/).map(Number).filter((n) => n > 0 && n < 65536) })} />
              <span className="hint">Telnet, SSH, SMB, RDP, ADB, TR-069, IRC and known IoT exploit ports by default.</span>
            </div>
          </Rule>
          <Rule title="Traffic volume spike" on={r.volumeSpike} set={(v) => set({ volumeSpike: v })}
            desc="Bytes in a 10-second window exceed the device's learned peak by a factor.">
            <div className="form-grid">
              <NumField label="Factor over learned peak" value={r.spikeFactor} min={1} step={0.5} suffix="×" onChange={(v) => set({ spikeFactor: v })} />
              <NumField label="Minimum volume" value={Math.round(r.spikeMinBytes / 1000)} min={1} suffix="kB per 10 s"
                onChange={(v) => set({ spikeMinBytes: v * 1000 })} />
            </div>
          </Rule>
          <Rule title="Connection burst / scanning" on={r.connectionBurst} set={(v) => set({ connectionBurst: v })}
            desc="Many TCP connection attempts or distinct destinations within 10 seconds — worm propagation, port scans.">
            <NumField label="Threshold" value={r.synThreshold} min={5} suffix="per 10 s" onChange={(v) => set({ synThreshold: v })} />
          </Rule>
          <Rule title="Activity at unusual times" on={r.unusualTime} set={(v) => set({ unusualTime: v })}
            desc="Heavy traffic or connection bursts during quiet hours, or outside learned active hours (needs ≥ 24 h of learning).">
            <div className="form-grid">
              <Toggle checked={r.quietHoursEnabled} onChange={(v) => set({ quietHoursEnabled: v })}>Enforce quiet hours</Toggle>
              <NumField label="From" value={r.quietStartHour} min={0} max={23} suffix=":00" onChange={(v) => set({ quietStartHour: Math.min(23, Math.max(0, v)) })} />
              <NumField label="Until" value={r.quietEndHour} min={0} max={23} suffix=":00" onChange={(v) => set({ quietEndHour: Math.min(23, Math.max(0, v)) })} />
            </div>
          </Rule>
          <Rule title="Wi-Fi deauthentication flood" on={r.deauthFlood} set={(v) => set({ deauthFlood: v })}
            desc="Burst of deauth/disassoc frames — Wi-Fi denial of service or handshake capture. Requires monitor mode.">
            <NumField label="Threshold" value={r.deauthThreshold} min={5} suffix="frames per 10 s" onChange={(v) => set({ deauthThreshold: v })} />
          </Rule>
          <Rule title="New device on the network" on={r.newDevice} set={(v) => set({ newDevice: v })}
            desc="A previously unseen device starts sending data after the initial discovery period." />
        </div>
      </div>

      <div className="card">
        <div className="card-head"><h2>Data</h2></div>
        <dl className="kv">
          <dt>Storage</dt><dd className="mono small">{status?.dataDir}</dd>
          <dt>Vendor database</dt>
          <dd>
            {status?.ouiEntries
              ? `${status.ouiEntries.toLocaleString()} manufacturers (IEEE registry)`
              : "Built-in starter table (~120 vendors). Download the official IEEE registry for full coverage."}
          </dd>
        </dl>
        <div className="row" style={{ marginTop: 16 }}>
          <button className="btn" onClick={updateVendors} disabled={updating}>
            <Icon name="database" size={14} /> {updating ? "Downloading…" : status?.ouiEntries ? "Update vendor database" : "Download vendor database"}
          </button>
          <button className="btn" onClick={exportReport}><Icon name="download" size={14} /> Export JSON report</button>
          <button className="btn danger" onClick={reset}><Icon name="trash" size={14} /> Delete all captured data</button>
        </div>
      </div>

      <AboutCard />

      <div className="savebar">
        <button className="btn primary" onClick={save} disabled={!dirty}>Save rules</button>
        {dirty && <span className="muted small">Unsaved changes</span>}
      </div>
    </>
  );
}
