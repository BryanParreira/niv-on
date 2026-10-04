import { useUpdater } from "../updater";
import { Icon } from "./Icon";

/** Compact sidebar notice shown only when an update is available or installing. */
export function UpdateNotice() {
  const u = useUpdater();
  if (!["available", "downloading", "installing"].includes(u.phase) || !u.update) return null;
  const pct = u.progress != null ? Math.round(u.progress * 100) : null;
  return (
    <div className="update-notice">
      <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
        <Icon name="download" size={14} />
        <b className="small">Version {u.update.version} available</b>
      </div>
      {u.phase === "available" ? (
        <button className="btn sm primary" style={{ width: "100%", marginTop: 8 }} onClick={u.install}>
          Install &amp; restart
        </button>
      ) : (
        <div style={{ marginTop: 8 }}>
          <div className="progress"><div style={{ width: `${pct ?? 100}%` }} /></div>
          <div className="muted small" style={{ marginTop: 4 }}>
            {u.phase === "installing" ? "Installing… the app will restart" : pct != null ? `Downloading ${pct}%` : "Downloading…"}
          </div>
        </div>
      )}
    </div>
  );
}

/** About + manual update check (Rules & data page). */
export function AboutCard() {
  const u = useUpdater();
  return (
    <div className="card">
      <div className="card-head"><h2>About &amp; updates</h2></div>
      <dl className="kv">
        <dt>Version</dt><dd className="mono">{u.version ?? "—"}</dd>
        <dt>Status</dt>
        <dd>
          {u.phase === "checking" && "Checking for updates…"}
          {u.phase === "current" && "You're on the latest version."}
          {u.phase === "available" && u.update && <>Version <b>{u.update.version}</b> is available.</>}
          {u.phase === "downloading" && `Downloading${u.progress != null ? ` ${Math.round(u.progress * 100)}%` : "…"}`}
          {u.phase === "installing" && "Installing — the app will restart."}
          {u.phase === "error" && <span style={{ color: "var(--critical)" }}>{u.error}</span>}
          {u.phase === "idle" && "Checks automatically at launch and every 6 hours."}
        </dd>
        {u.lastChecked && (<><dt>Last check</dt><dd>{u.lastChecked.toLocaleString()}</dd></>)}
        {u.update?.body && (<><dt>Release notes</dt><dd style={{ whiteSpace: "pre-wrap" }} className="small dim">{u.update.body}</dd></>)}
      </dl>
      <div className="row" style={{ marginTop: 14 }}>
        <button className="btn" onClick={() => u.checkNow(true)} disabled={u.phase === "checking" || u.phase === "downloading"}>
          <Icon name="refresh" size={14} /> Check for updates
        </button>
        {u.phase === "available" && <button className="btn primary" onClick={u.install}>Install &amp; restart</button>}
      </div>
    </div>
  );
}
