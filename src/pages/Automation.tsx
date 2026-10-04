import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { api, inTauri, newId, PRIORITIES, type Playbook, type PlaybookAction, type Priority, type RunLog, type Severity } from "../api";
import { ruleLabel } from "../components/AlertList";
import { Icon } from "../components/Icon";
import { SEVERITY_ORDER } from "../components/Severity";
import { ago } from "../format";
import { usePoll } from "../store";

const RULES = [
  "threat-intel", "ids-signature", "arp-spoof", "rogue-router", "risky-port", "connection-burst", "new-destination",
  "suspicious-domain", "volume-spike", "fingerprint-change", "identity-change", "peer-anomaly", "risk-threshold", "custom-detection", "new-device",
];

const ACTION_LABEL: Record<PlaybookAction["type"], string> = {
  notify: "Desktop notification",
  evidence: "Save packet evidence (.pcap)",
  investigate: "Open an investigation",
  tag: "Tag the device",
  priority: "Set asset priority",
  script: "Run a script",
};

const STARTERS: Omit<Playbook, "id">[] = [
  {
    name: "Critical alert response",
    enabled: true,
    minSeverity: "critical",
    rules: [],
    iotOnly: false,
    actions: [{ type: "notify" }, { type: "evidence" }, { type: "investigate", owner: "" }],
  },
  {
    name: "Compromised IoT device",
    enabled: true,
    minSeverity: "high",
    rules: ["threat-intel", "ids-signature", "risky-port", "connection-burst"],
    iotOnly: true,
    actions: [{ type: "priority", priority: "critical" }, { type: "tag", tag: "Quarantine candidate" }, { type: "notify" }],
  },
  {
    name: "Man-in-the-middle on the network",
    enabled: true,
    minSeverity: "medium",
    rules: ["arp-spoof", "rogue-router", "ip-conflict"],
    iotOnly: false,
    actions: [{ type: "notify" }, { type: "evidence" }],
  },
];

function defaultAction(t: PlaybookAction["type"]): PlaybookAction {
  switch (t) {
    case "investigate":
      return { type: t, owner: "" };
    case "tag":
      return { type: t, tag: "Quarantine candidate" };
    case "priority":
      return { type: t, priority: "high" };
    case "script":
      return { type: t, path: "" };
    default:
      return { type: t };
  }
}

function Editor({ pb, onChange, onDelete }: { pb: Playbook; onChange: (p: Playbook) => void; onDelete: () => void }) {
  const set = (p: Partial<Playbook>) => onChange({ ...pb, ...p });
  const setAction = (i: number, a: PlaybookAction) => set({ actions: pb.actions.map((x, j) => (j === i ? a : x)) });
  return (
    <div className="card">
      <div className="card-head">
        <label className="toggle"><input type="checkbox" checked={pb.enabled} onChange={(e) => set({ enabled: e.target.checked })} aria-label="Enabled" /></label>
        <input className="input" value={pb.name} onChange={(e) => set({ name: e.target.value })} style={{ width: 320, fontWeight: 600 }} aria-label="Playbook name" />
        <div className="right"><button className="btn sm ghost icon" onClick={onDelete} title="Delete playbook"><Icon name="trash" size={12} /></button></div>
      </div>
      <div className="two">
        <div className="stack">
          <div className="label-caps">When</div>
          <div className="row">
            <span className="small dim">an alert of at least</span>
            <select className="select" value={pb.minSeverity} onChange={(e) => set({ minSeverity: e.target.value as Severity })} aria-label="Minimum severity">
              {[...SEVERITY_ORDER].reverse().map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <label className="toggle small"><input type="checkbox" checked={pb.iotOnly} onChange={(e) => set({ iotOnly: e.target.checked })} />on IoT devices only</label>
          </div>
          <div className="small dim">from {pb.rules.length ? "these rules" : "any rule"}:</div>
          <div className="chips">
            {RULES.map((r) => (
              <button key={r} className={`chip ${pb.rules.includes(r) ? "on" : ""}`}
                onClick={() => set({ rules: pb.rules.includes(r) ? pb.rules.filter((x) => x !== r) : [...pb.rules, r] })}>{ruleLabel(r)}</button>
            ))}
          </div>
        </div>
        <div className="stack">
          <div className="label-caps">Then</div>
          {pb.actions.map((a, i) => (
            <div key={i} className="row" style={{ flexWrap: "nowrap" }}>
              <span className="small" style={{ minWidth: 190 }}>{i + 1}. {ACTION_LABEL[a.type]}</span>
              {a.type === "investigate" && (
                <input className="input" placeholder="Owner (default: automation)" value={a.owner} onChange={(e) => setAction(i, { ...a, owner: e.target.value })} />
              )}
              {a.type === "tag" && <input className="input" value={a.tag} onChange={(e) => setAction(i, { ...a, tag: e.target.value })} />}
              {a.type === "priority" && (
                <select className="select" value={a.priority} onChange={(e) => setAction(i, { ...a, priority: e.target.value as Priority })}>
                  {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              )}
              {a.type === "script" && (
                <>
                  <input className="input mono" placeholder="/path/to/block-device.sh" value={a.path} style={{ flex: 1 }}
                    onChange={(e) => setAction(i, { ...a, path: e.target.value })} />
                  <button className="btn sm ghost" onClick={async () => { const f = await open({ multiple: false }); if (typeof f === "string") setAction(i, { ...a, path: f }); }}>Browse</button>
                </>
              )}
              <button className="btn sm ghost icon" title="Remove action" onClick={() => set({ actions: pb.actions.filter((_, j) => j !== i) })}><Icon name="x" size={12} /></button>
            </div>
          ))}
          <select className="select" value="" onChange={(e) => e.target.value && set({ actions: [...pb.actions, defaultAction(e.target.value as PlaybookAction["type"])] })} aria-label="Add action">
            <option value="">+ Add action…</option>
            {(Object.keys(ACTION_LABEL) as PlaybookAction["type"][]).map((t) => <option key={t} value={t}>{ACTION_LABEL[t]}</option>)}
          </select>
          {pb.actions.some((a) => a.type === "script") && (
            <span className="hint">
              Scripts get <span className="mono">NIV_ALERT_ID NIV_RULE NIV_SEVERITY NIV_TITLE NIV_MESSAGE NIV_DEVICE_MAC NIV_DEVICE_IP NIV_DEVICE_LABEL NIV_REMOTE</span> and
              30 s to finish — e.g. ssh to your OpenWrt/pfSense router and block NIV_DEVICE_MAC.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/** Response playbooks (SOAR): what happens automatically when an alert fires. */
export function Automation({ onMessage }: { onMessage: (m: string) => void }) {
  const [list, setList] = useState<Playbook[] | null>(null);
  const [dirty, setDirty] = useState(false);
  const [log] = usePoll(api.playbookLog, 3000);

  useEffect(() => {
    if (inTauri) api.getSettings().then((s) => setList(s.playbooks)).catch((e) => onMessage(String(e)));
  }, [onMessage]);

  async function save() {
    try {
      const s = await api.getSettings();
      await api.saveSettings({ ...s, playbooks: list! });
      setDirty(false);
      onMessage("Playbooks saved — they run on the next matching alert.");
    } catch (e) {
      onMessage(String(e));
    }
  }
  const update = (next: Playbook[]) => {
    setList(next);
    setDirty(true);
  };

  if (!list) return <div className="card"><div className="empty">Loading…</div></div>;

  return (
    <>
      <div className="banner">
        <Icon name="bolt" />
        <div className="grow">
          Playbooks respond the moment an alert fires: notify you, save packet evidence, open an investigation, raise the device's priority,
          tag it, or run your own script — for example to block the device on your router.
        </div>
        <button className="btn sm" onClick={() => update([...list, ...STARTERS.filter((s) => !list.some((p) => p.name === s.name)).map((s) => ({ ...s, id: newId() }))])}>
          Add starter playbooks
        </button>
        <button className="btn sm" onClick={() => update([...list, { id: newId(), name: "New playbook", enabled: true, minSeverity: "high", rules: [], iotOnly: false, actions: [{ type: "notify" }] }])}>
          <Icon name="bolt" size={12} /> New playbook
        </button>
      </div>

      {list.length === 0 && <div className="card"><div className="empty"><Icon name="bolt" size={28} />No playbooks yet.</div></div>}
      {list.map((pb) => (
        <Editor key={pb.id} pb={pb} onChange={(p) => update(list.map((x) => (x.id === pb.id ? p : x)))} onDelete={() => update(list.filter((x) => x.id !== pb.id))} />
      ))}

      <div className="card pad0">
        <div className="card-head"><h2>Recent runs</h2><span className="sub">this session</span></div>
        <div className="table-wrap" style={{ maxHeight: 320 }}>
          <table className="t compact">
            <tbody>
              {(log ?? []).map((r: RunLog, i) => (
                <tr key={i}>
                  <td className="muted small" style={{ whiteSpace: "nowrap" }}>{ago(r.ts)}</td>
                  <td>{r.ok ? <span className="chip good"><Icon name="check" size={11} /> ok</span> : <span className="sev high">failed</span>}</td>
                  <td><div className="name">{r.playbook}</div><div className="muted small">alert #{r.alertId} · {r.alertTitle}</div></td>
                  <td className="small dim">{r.results.join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!log?.length && <div className="empty small">No playbook has run yet.</div>}
        </div>
      </div>

      <div className="savebar">
        <button className="btn primary" onClick={save} disabled={!dirty}>Save playbooks</button>
        {dirty && <span className="muted small">Unsaved changes</span>}
      </div>
    </>
  );
}
