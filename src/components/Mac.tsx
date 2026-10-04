/** MAC address with the vendor (OUI) prefix dimmed — the NIC-specific half is what tells devices apart. */
export function Mac({ mac, className }: { mac: string; className?: string }) {
  const oui = mac.slice(0, 8);
  const nic = mac.slice(8);
  return (
    <span className={`mac ${className ?? ""}`} title={mac}>
      <span className="oui">{oui}</span>
      {nic}
    </span>
  );
}
