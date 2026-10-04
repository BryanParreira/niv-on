import { signalBars } from "../format";

export function Signal({ rssi }: { rssi: number | null }) {
  const n = signalBars(rssi);
  return (
    <span className="row" style={{ gap: 6, flexWrap: "nowrap" }} title={rssi == null ? "No RSSI (not in monitor mode)" : `${rssi} dBm`}>
      <span className="signal" aria-hidden="true">
        {[5, 8, 11, 14].map((h, i) => (
          <i key={i} className={i < n ? "on" : ""} style={{ height: h }} />
        ))}
      </span>
      <span className="num dim">{rssi == null ? "—" : `${rssi} dBm`}</span>
    </span>
  );
}
