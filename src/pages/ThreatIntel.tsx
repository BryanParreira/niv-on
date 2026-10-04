import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState } from "react";
import { api, inTauri, type IntelStatus, type RulesStatus, type Settings } from "../api";
import { Icon } from "../components/Icon";
import { SeverityBadge } from "../components/Severity";
import { ago, fmtNum } from "../format";
import { Toggle } from "./Capture";

/** Threat feeds, CISA KEV, your watchlist, and Suricata / Snort signatures. */
export function ThreatIntel({ onMessage }: { onMessage: (m: string) => void }) {
  const [intel, setIntel] = useState<IntelStatus | null>(null);
  const [rules, setRules] = useState<RulesStatus | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [watch, setWatch] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [cats, setCats] = useState<Set<string>>(new Set(["emerging-exploit", "emerging-scan", "emerging-attack_response", "emerging-coinminer"]));

  const load = useCallback(() => {
    if (!inTauri) return;
    api.intelStatus().then(setIntel).catch(console.error);
    api.rulesStatus().then(setRules).catch(console.error);
    api.getSettings().then((s) => {
      setSettings(s);
      setWatch(s.rules.watchlist.join("\n"));
    });
  }, []);
  useEffect(load, [load]);

  async function saveData(patch: Partial<Settings["data"]>, rulesPatch?: Partial<Settings["rules"]>) {
    const s = await api.getSettings();
    const next = { ...s, data: { ...s.data, ...patch }, rules: { ...s.rules, ...rulesPatch } };
    await api.saveSettings(next);
    setSettings(next);
    api.intelStatus().then(setIntel);
  }

  async function run(label: string, fn: () => Promise<string | void>) {
    setBusy(label);
    try {
      const m = await fn();
      if (m) onMessage(m);
    } catch (e) {
      onMessage(String(e));
    } finally {
      setBusy(null);
      load();
    }
  }

  if (!intel || !rules || !settings) return <div className="card"><div className="empty">Loading…</div></div>;
  const watchCount = watch.split("\n").filter((l) => l.split("#")[0].trim()).length;

  return (
    <>
      <div className="kpis">
        <div className="card kpi">
          <div className="label"><Icon name="crosshair" size={14} />Threat indicators</div>
          <div className="value">{fmtNum(intel.indicators)}</div>
          <div className="foot">IPs, ranges and domains matched against every connection and lookup</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="shield" size={14} />Signatures</div>
          <div className="value">{fmtNum(rules.total)}</div>
          <div className="foot">{rules.enabled ? "Suricata / Snort rules, inspected on every packet" : "signature matching is turned off"}</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="alerts" size={14} />Known exploited CVEs</div>
          <div className="value">{fmtNum(intel.kev.count)}</div>
          <div className="foot">CISA KEV catalog · {intel.kev.updated ? `updated ${ago(intel.kev.updated)}` : "not downloaded"}</div>
        </div>
        <div className="card kpi">
          <div className="label"><Icon name="clock" size={14} />Auto-update</div>
          <div className="value" style={{ fontSize: 20 }}>{settings.data.autoUpdateIntel ? "Daily" : "Off"}</div>
          <div className="foot">feeds and KEV refresh in the background</div>
        </div>
      </div>

      <div className="card pad0">
        <div className="card-head">
          <h2>Threat feeds</h2>
          <span className="sub">free, community-maintained indicator lists</span>
          <div className="right">
            <Toggle checked={settings.data.autoUpdateIntel} onChange={(v) => saveData({ autoUpdateIntel: v })}>Update daily</Toggle>
            <button className="btn primary sm" disabled={busy !== null} onClick={() => run("update", async () => {
              const s = await api.updateIntel();
              setIntel(s);
              const failed = s.feeds.filter((f) => f.enabled && f.error);
              return failed.length ? `Updated with errors: ${failed.map((f) => `${f.name}: ${f.error}`).join("; ")}` : `Threat intel updated — ${fmtNum(s.indicators)} indicators, ${fmtNum(s.kev.count)} KEV entries.`;
            })}>
              <Icon name="refresh" size={12} /> {busy === "update" ? "Updating…" : "Update now"}
            </button>
          </div>
        </div>
        <table className="t">
          <thead><tr><th>On</th><th>Feed</th><th>Severity</th><th className="r">Indicators</th><th className="r">Updated</th></tr></thead>
          <tbody>
            {intel.feeds.map((f) => (
              <tr key={f.id}>
                <td>
                  <label className="toggle"><input type="checkbox" checked={f.enabled} aria-label={`Enable ${f.name}`}
                    onChange={(e) => saveData({ feeds: e.target.checked ? [...settings.data.feeds, f.id] : settings.data.feeds.filter((x) => x !== f.id) })} /></label>
                </td>
                <td>
                  <div className="name">{f.name}</div>
                  <div className="muted small">{f.description}</div>
                  {f.error && <div className="small" style={{ color: "var(--critical)" }}>{f.error}</div>}
                </td>
                <td><SeverityBadge s={f.severity} /></td>
                <td className="r num">{f.updated ? fmtNum(f.count) : "—"}</td>
                <td className="r muted small">{f.updated ? ago(f.updated) : "never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Your watchlist</h2>
          <span className="sub">critical alert on any contact — {watchCount} indicators</span>
          <div className="right">
            <button className="btn sm primary" onClick={() => run("watch", async () => {
              await saveData({}, { watchlist: watch.split("\n").map((l) => l.trim()).filter(Boolean) });
              return "Watchlist saved.";
            })}>Save watchlist</button>
          </div>
        </div>
        <textarea className="input mono" rows={6} spellCheck={false} value={watch} onChange={(e) => setWatch(e.target.value)}
          placeholder={"203.0.113.50\n198.51.100.0/24\nevil.example        # also matches sub.evil.example"} style={{ width: "100%" }} />
        <span className="hint">IPv4/IPv6 addresses, CIDR ranges or domains, one per line. Paste exports from MISP, OpenCTI, CISA alerts or your SOC.</span>
      </div>

      <div className="card pad0">
        <div className="card-head">
          <h2>Signatures</h2>
          <span className="sub">Suricata / Snort rule subset — content, ports, $HOME_NET; stateful and regex rules are skipped</span>
          <div className="right">
            <Toggle checked={settings.rules.ids} onChange={(v) => saveData({}, { ids: v }).then(load)}>Enabled</Toggle>
            <button className="btn sm" disabled={busy !== null} onClick={async () => {
              const f = await open({ multiple: false, filters: [{ name: "Suricata / Snort rules", extensions: ["rules", "txt"] }] });
              if (typeof f === "string") run("import", () => api.importRules(f));
            }}><Icon name="file" size={12} /> Import .rules</button>
          </div>
        </div>
        <table className="t">
          <thead><tr><th>Source</th><th className="r">Loaded</th><th className="r">Skipped</th><th /></tr></thead>
          <tbody>
            {rules.sources.map((s) => (
              <tr key={s.name}>
                <td><div className="name">{s.builtin ? "Built-in IoT rules" : s.name}</div>{s.builtin && <div className="muted small">Mirai loaders, Log4Shell, router/camera RCEs, miners, cleartext credentials, scanners</div>}</td>
                <td className="r num">{fmtNum(s.loaded)}</td>
                <td className="r num dim">{fmtNum(s.skipped)}</td>
                <td className="r">
                  {!s.builtin && <button className="btn sm ghost icon" title="Remove" onClick={() => run("rm", () => api.removeRules(s.name))}><Icon name="trash" size={12} /></button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: 16 }}>
          <div className="label-caps" style={{ marginBottom: 8 }}>Emerging Threats Open (Proofpoint, free)</div>
          <div className="chips">
            {rules.etCategories.map((c) => (
              <button key={c.id} className={`chip ${cats.has(c.id) ? "on" : ""}`} title={c.description}
                onClick={() => setCats((s) => { const n = new Set(s); if (n.has(c.id)) n.delete(c.id); else n.add(c.id); return n; })}>
                {c.installed && <Icon name="check" size={11} />} {c.id.replace("emerging-", "")}
              </button>
            ))}
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <button className="btn sm" disabled={busy !== null || cats.size === 0} onClick={() => run("et", () => api.downloadEt([...cats]))}>
              <Icon name="download" size={12} /> {busy === "et" ? "Downloading…" : `Download ${cats.size} categor${cats.size === 1 ? "y" : "ies"}`}
            </button>
            <span className="hint">Downloading again updates them. Signatures inspect the first 1 KB of each packet (no stream reassembly).</span>
          </div>
        </div>
      </div>
    </>
  );
}
