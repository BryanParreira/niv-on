import { useEffect, useMemo, useRef, useState } from "react";
import { api, inTauri, type FeedItem } from "../api";
import { Icon } from "../components/Icon";
import { Mac } from "../components/Mac";
import { clockTime } from "../format";
import { useNav } from "../nav";
import { useLive, usePoll } from "../store";

const KEEP = 600;
type Kind = "all" | "management" | "control" | "data" | "ethernet";

/** Scrolling, filterable list of decoded frames — great for demos. */
export function LiveFeed() {
  const nav = useNav();
  const { status } = useLive();
  const [items, setItems] = useState<FeedItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [hideCtrl, setHideCtrl] = useState(true);
  const last = useRef(0);
  const [devices] = usePoll(api.getDevices, 3000);
  const labels = useMemo(() => new Map((devices ?? []).map((d) => [d.mac, d.label])), [devices]);

  useEffect(() => {
    if (!inTauri || paused) return;
    const tick = () =>
      api.getFeed(last.current).then((fresh) => {
        if (!fresh.length) return;
        // A restarted session resets sequence numbers.
        if (fresh[0].seq < last.current) last.current = 0;
        last.current = fresh[fresh.length - 1].seq;
        setItems((cur) => [...fresh.reverse(), ...cur].slice(0, KEEP));
      });
    tick();
    const id = setInterval(tick, 700);
    return () => clearInterval(id);
  }, [paused]);

  useEffect(() => {
    // New session → start fresh.
    last.current = 0;
    setItems([]);
  }, [status?.session?.startedAt]);

  const shown = items.filter((f) => {
    if (kind !== "all" && f.kind !== kind) return false;
    if (hideCtrl && f.kind === "control") return false;
    if (!q) return true;
    const ql = q.toLowerCase();
    return `${f.protocol} ${f.info} ${f.src ?? ""} ${f.dst ?? ""} ${labels.get(f.src ?? "") ?? ""} ${labels.get(f.dst ?? "") ?? ""}`
      .toLowerCase()
      .includes(ql);
  });

  const who = (m: string | null) => {
    if (!m) return <span className="muted">—</span>;
    if (m === "ff:ff:ff:ff:ff:ff") return <span className="muted">broadcast</span>;
    const l = labels.get(m);
    return l ? (
      <button className="linkish ellipsis" style={{ maxWidth: 190, display: "inline-block" }} onClick={() => nav.openDevice(m)} title={m}>{l}</button>
    ) : (
      <Mac mac={m} />
    );
  };

  return (
    <div className="card pad0">
      <div className="card-head" style={{ padding: "16px 16px 0" }}>
        <div className="seg">
          {(["all", "data", "management", "control", "ethernet"] as Kind[]).map((k) => (
            <button key={k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
              {k === "all" ? "All" : k[0].toUpperCase() + k.slice(1)}
            </button>
          ))}
        </div>
        <label className="toggle small">
          <input type="checkbox" checked={hideCtrl} onChange={(e) => setHideCtrl(e.target.checked)} />
          Hide ACK/control noise
        </label>
        <div className="right">
          <div className="search">
            <Icon name="search" size={14} />
            <input className="input" style={{ width: 240 }} placeholder="Filter: dns, tls, beacon, device…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <button className={`btn ${paused ? "primary" : ""}`} onClick={() => setPaused((p) => !p)}>
            <Icon name={paused ? "play" : "pause"} size={14} /> {paused ? "Resume" : "Pause"}
          </button>
          <button className="btn ghost" onClick={() => setItems([])}>Clear</button>
        </div>
      </div>
      <div className="table-wrap" style={{ maxHeight: "calc(100vh - 200px)" }}>
        <table className="t compact feed">
          <thead>
            <tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Info</th><th className="r">RSSI</th><th className="r">Len</th></tr>
          </thead>
          <tbody>
            {shown.slice(0, 300).map((f) => (
              <tr key={f.seq}>
                <td className="mono small muted">{clockTime(f.ts)}</td>
                <td><span className="proto">{f.protocol}</span></td>
                <td>{who(f.src)}</td>
                <td>{who(f.dst)}</td>
                <td className="small" style={{ maxWidth: 520, overflowWrap: "anywhere" }}>{f.info}</td>
                <td className="r num small dim">{f.rssi ?? ""}</td>
                <td className="r num small dim">{f.len}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <div className="empty">
            <Icon name="activity" size={28} />
            {status?.running ? (paused ? "Paused." : "Waiting for frames…") : "Start a capture to see frames here."}
          </div>
        )}
      </div>
    </div>
  );
}
