import { useState } from "react";
import { api, type NetworkSummary } from "../api";
import { Icon } from "../components/Icon";
import { Mac } from "../components/Mac";
import { ago, dateTime } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

const KIND_LABEL: Record<string, string> = { live: "Network", file: "Capture file", demo: "Demo", legacy: "Earlier data" };
const KIND_ICON: Record<string, string> = { live: "globe", file: "file", demo: "beaker", legacy: "database" };

/** Every network Niv.ON has profiled, each with its own devices, baselines and alerts. */
export function Networks({ onMessage }: { onMessage: (m: string) => void }) {
  const { status, refresh } = useLive();
  const nav = useNav();
  const [nets, reload] = usePoll(api.listNetworks, 3000);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const running = !!status?.running;

  async function act(fn: () => Promise<unknown>, msg: string) {
    try {
      await fn();
      onMessage(msg);
    } catch (e) {
      onMessage(String(e));
    } finally {
      reload();
      refresh();
    }
  }

  const demo = nets?.find((n) => n.kind === "demo");
  const list = nets ?? [];

  const row = (n: NetworkSummary) => (
    <tr key={n.id}>
      <td>
        <div className="dev-cell">
          <span className={`avatar ${n.current ? "self" : ""}`}><Icon name={KIND_ICON[n.kind] ?? "globe"} /></span>
          <div style={{ minWidth: 0 }}>
            {editing === n.id ? (
              <form className="row" style={{ flexWrap: "nowrap" }} onSubmit={(e) => {
                e.preventDefault();
                setEditing(null);
                act(() => api.renameNetwork(n.id, draft), "Network renamed.");
              }}>
                <input id={`rename-${n.id}`} className="input" autoFocus value={draft} onChange={(e) => setDraft(e.target.value)} style={{ width: 240 }} />
                <button className="btn sm primary" type="submit">Save</button>
                <button className="btn sm ghost" type="button" onClick={() => setEditing(null)}>Cancel</button>
              </form>
            ) : (
              <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                <span className="name ellipsis" style={{ maxWidth: 300 }}>{n.name}</span>
                {n.current && <span className="chip accent">current</span>}
              </div>
            )}
            <div className="muted small">
              {KIND_LABEL[n.kind]}
              {n.interface ? ` · ${n.interface}` : ""}
              {n.ssid && n.ssid !== n.name ? ` · ${n.ssid}` : ""}
            </div>
          </div>
        </div>
      </td>
      <td className="mono small">{n.subnet ?? "—"}</td>
      <td className="small">{n.gatewayMac ? <Mac mac={n.gatewayMac} /> : <span className="muted">—</span>}</td>
      <td className="r num">{n.devices}</td>
      <td className="r num">{n.openAlerts || <span className="muted">—</span>}</td>
      <td className="r muted small" title={dateTime(n.lastUsed)}>{ago(n.lastUsed)}</td>
      <td className="r">
        {confirmDelete === n.id ? (
          <div className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
            <span className="small dim">Delete {n.devices} devices?</span>
            <button className="btn sm danger" onClick={() => { setConfirmDelete(null); act(() => api.deleteNetwork(n.id), `Forgot “${n.name}”.`); }}>Forget</button>
            <button className="btn sm ghost" onClick={() => setConfirmDelete(null)}>Keep</button>
          </div>
        ) : (
          <div className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
            {!n.current && n.kind !== "demo" && (
              <button className="btn sm" disabled={running} title={running ? "Stop the capture to browse another network" : ""}
                onClick={() => act(() => api.openNetwork(n.id), `Showing “${n.name}”.`)}>View</button>
            )}
            {n.current && <button className="btn sm" onClick={() => nav.go("devices")}>Devices</button>}
            {n.kind !== "demo" && (
              <button className="btn sm ghost" onClick={() => { setEditing(n.id); setDraft(n.name); }}>Rename</button>
            )}
            <button className="btn sm ghost danger" disabled={n.current && running} onClick={() => setConfirmDelete(n.id)}
              title={n.current && running ? "Stop the capture first" : "Delete this network's devices, baselines and alerts"}>
              <Icon name="trash" size={12} />
            </button>
          </div>
        )}
      </td>
    </tr>
  );

  return (
    <>
      <div className="banner">
        <Icon name="info" />
        <div className="grow">
          Each network keeps its own devices, baselines and alerts. Niv.ON recognizes a network by its router and switches
          automatically when you capture on it. Demo data is never saved and starts fresh on every simulator run.
        </div>
      </div>
      {demo && (
        <div className="banner warn">
          <Icon name="beaker" />
          <div className="grow"><b>Demo data loaded</b> — {demo.devices} simulated devices{demo.current ? " are showing right now" : ""}.</div>
          <button className="btn sm" onClick={() => act(() => api.clearDemo(), "Demo data cleared.")}>Clear demo data</button>
        </div>
      )}
      <div className="card pad0">
        <div className="card-head">
          <h2>Networks</h2>
          <span className="sub">{list.filter((n) => n.kind !== "demo").length} saved</span>
        </div>
        <div className="table-wrap">
          <table className="t">
            <thead>
              <tr><th>Network</th><th>Subnet</th><th>Router</th><th className="r">Devices</th><th className="r">Open alerts</th><th className="r">Last used</th><th /></tr>
            </thead>
            <tbody>{list.map(row)}</tbody>
          </table>
          {list.length === 0 && (
            <div className="empty">
              <Icon name="globe" size={28} />
              No networks yet. Start a capture and Niv.ON creates one automatically.
            </div>
          )}
        </div>
      </div>
    </>
  );
}
