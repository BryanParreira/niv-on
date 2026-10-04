<p align="center">
  <img src="assets/logo.svg" width="112" alt="Niv.ON logo" />
</p>

<h1 align="center">Niv.ON</h1>

<p align="center">
  <b>See every device on your network. Know when one starts behaving differently.</b><br/>
  Wireless &amp; LAN traffic monitor with per-device behavioral baselines and real-time anomaly detection.
</p>

<p align="center">
  <a href="https://github.com/BryanParreira/niv-on/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/BryanParreira/niv-on?style=flat-square&color=2b2b2f&label=release"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/macOS%20%C2%B7%20Windows%20%C2%B7%20Linux-2b2b2f?style=flat-square">
  <img alt="Built with" src="https://img.shields.io/badge/Rust%20%C2%B7%20Tauri%202%20%C2%B7%20React-2b2b2f?style=flat-square">
  <a href="https://github.com/BryanParreira/niv-on/actions/workflows/build.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/BryanParreira/niv-on/build.yml?style=flat-square&color=2b2b2f"></a>
</p>

---

## Why Niv.ON

Smart cameras, plugs, thermostats and TVs are the least monitored computers in any home or office. They rarely get patched, they talk to the cloud all day, and when one is compromised it keeps working normally — while also scanning the internet, joining a botnet or uploading data somewhere new.

Niv.ON watches the network from the outside. It identifies every device it can see, learns what each one normally does, and flags the moment that changes:

| A device… | Niv.ON raises |
|---|---|
| contacts a server it never used before | **Unknown external destination** |
| opens Telnet, SMB, RDP, ADB, TR-069 or a known IoT exploit port | **Risky / unexpected service port** |
| sends 4× more data than its learned peak | **Traffic volume spike** |
| tries dozens of hosts in seconds | **Connection burst / scanning** |
| is busy at 3 a.m. when it never is | **Activity at unusual times** |
| floods the air with deauthentication frames | **Wi-Fi deauthentication flood** |
| appears on the network for the first time | **New device** |
| answers ARP for the router, or advertises itself as an IPv6 router | **ARP spoofing / rogue router** (man-in-the-middle) |
| looks up long, random-looking domain names | **Suspicious (DGA) domain** |
| contacts an IP, range or domain on your watchlist | **Threat intelligence match** |
| trips several different detections at once | **Risk threshold exceeded** (correlated) |

Every alert links to the device's full profile, is tagged with its **MITRE ATT&CK** technique, and *Mark as normal* folds legitimate changes into its baseline.

---

## Highlights

**Capture anywhere.** Live capture on Ethernet or Wi-Fi in managed mode, raw 802.11 in monitor mode with channel hopping, replay of `.pcap`/`.pcapng` files, or the built-in simulator. Interfaces are detected with their real names, the one carrying your internet connection is marked as recommended, and a one-click self-test confirms capture works before you start.

**Identify devices without agents.** Niv.ON reads what devices already announce — DHCP hostnames and vendor classes, mDNS/DNS-SD services, UPnP banners, HTTP user agents, DNS and TLS server names — and combines it with the IEEE vendor registry (~38,000 manufacturers, downloadable in-app) to name and classify devices automatically: camera, thermostat, speaker, TV, printer, phone, laptop, router. An ARP sweep finds devices that stay silent.

**Behavioral baselines.** For each device: hosts and domains contacted, service ports, peak and average traffic per 10 seconds, and hour-of-day activity. Learning periods range from minutes for demos to days for real deployments; baselines persist across restarts.

**Wireless visibility.** In monitor mode: signal strength (dBm), channel, frame types, SSIDs advertised and probed (the networks a phone remembers), access-point associations and deauth attacks.

**One inventory per network.** Each network keeps its own devices, baselines and alerts. Niv.ON recognizes a network by its router and switches automatically when you capture on it, so moving between home, campus and a client site never mixes devices. Demo data is never saved and starts fresh on every simulator run; *Clear demo data* removes it in one click.

**Risk-based alerting.** Like Splunk Enterprise Security, every open alert adds risk to its device — weighted by severity, higher for IoT and for devices you mark as high-priority assets, halving every 24 hours. Devices are ranked by risk, and one correlated critical alert fires when a device crosses the threshold from multiple detections, so analysts look at the few devices that matter instead of every individual event.

**Search your data like Splunk.** The Search page speaks a subset of SPL over alerts, devices and the live feed: `index=alerts severity>=high | stats count, dc(device) by tactic, mitre` or `index=devices risk>0 | sort -risk | table label ip vendor risk`. Wildcards, comparisons, `NOT`, `OR`, relative time (`_time>-24h`), `stats`, `timechart`, `top`, `rare`, `sort`, `head`, `table`, `dedup`, `rename`, an event timeline, table / bar / line / single-value views, real-time refresh and saved searches.

**Dashboards.** Any search can become a dashboard panel that refreshes every 10 seconds. One click builds a security-operations overview: open alerts, alerts over time, urgency, ATT&CK tactics, riskiest devices, live traffic by protocol and incidents in progress.

**Custom detections.** Save any search as a detection (Splunk's correlation searches): it runs every minute and raises an alert for each device it returns, throttled per device. Starter detections cover critical assets at risk, Telnet on the network, unknown devices with many peers and repeat offenders.

**Incident review.** Alerts move through *New → In progress → Resolved / False positive* with an owner and an investigation-notes timeline, bulk triage, and **urgency** — severity adjusted by each device's asset priority (low, medium, high, critical) — so a medium alert on a critical camera outranks a high alert on a guest phone.

**Signatures and threat intelligence.** Every packet is checked against Suricata / Snort rules — built-in rules for IoT exploits (Mirai loaders, Hikvision / Huawei / Realtek / GPON RCEs, Log4Shell, miners, cleartext credentials) plus any Emerging Threats Open category or `.rules` file you add — and every connection and DNS lookup against auto-updating feeds (abuse.ch Feodo Tracker, URLhaus, ThreatFox, Tor exit nodes) and your own watchlist.

**Exposure and compliance.** Devices are checked for Telnet/FTP/ADB/RTSP services, SMBv1, legacy TLS, cleartext MQTT, hard-coded DNS, outdated UPnP stacks and vendors in CISA's Known Exploited Vulnerabilities catalog. Findings add to risk scores and roll up into a compliance view with a posture score.

**Investigate like a SOC.** Each alert opens a detail panel showing the request that triggered it (source → destination, protocol, service, name, payload excerpt), what to do about it, the device's risk breakdown, and one-click packet evidence as a Wireshark `.pcap`. Devices have an investigation timeline, a connection log and a DNS log (kept in SQLite for a configurable retention period and searchable as `index=conn` / `index=dns`), TLS (JA3/JA4) and DHCP fingerprints, and peer-group comparison against devices of the same type.

**See the network.** A network diagram lays out internet → router / access points → device groups with live status and risk, and highlights paths with suspicious destinations; a force-directed graph shows every link.

**Automate the response.** Playbooks react to alerts: desktop notification, packet evidence, open an investigation, raise asset priority, tag the device, or run your own script (for example to block the device on an OpenWrt / pfSense router). Custom detections turn any search into an alert rule; dashboards turn searches into live panels; scheduled HTML reports summarise a day or week.

**Monitor-mode adapters (ALFA).** Niv.ON lists Wi-Fi adapters with their chipset (RTL8812AU / RTL8814AU / MT7612U / MT7921AU / AR9271 / RT3070…), switches monitor mode on Linux (`iw`) and Windows (Npcap WlanHelper), and captures from them. macOS has no monitor-mode driver for USB adapters, so on a Mac plug the ALFA into a Raspberry Pi or Kali box and add it as a **Remote sensor**: Niv.ON logs in over SSH, enables monitor mode, optionally hops channels, and streams the capture back.

**Built for daily use.** Overview dashboard, sortable device inventory with CSV export, tabbed device profiles, a live decoded-frame feed, alert triage, a ⌘K command palette, JSON reports, and automatic updates.

---

## Install

Download the installer for your system from **[Releases](https://github.com/BryanParreira/niv-on/releases/latest)**.

| Platform | Installer | Capture requirement |
|---|---|---|
| **macOS 11+** (Apple Silicon & Intel) | `Niv.ON_x.y.z_universal.dmg` — signed & notarized | Click **Grant access** on first launch (admin password, until reboot), or install Wireshark's *ChmodBPF* for a permanent fix |
| **Windows 10/11** | `Niv.ON_x.y.z_x64-setup.exe` or `.msi` | Install **[Npcap](https://npcap.com)** — tick *Support raw 802.11 traffic* for monitor mode |
| **Linux** | `.AppImage`, `.deb`, `.rpm` | Click **Grant access** (adds `cap_net_raw,cap_net_admin` to the binary), then restart |

The simulator works everywhere without any permissions. Niv.ON checks for updates at launch and every six hours; updates are signed and install with one click.

---

## Where to capture

What Niv.ON can see depends on where it listens:

| Position | Devices | Signal / SSIDs / deauths | Destinations per device |
|---|---|---|---|
| Laptop, managed mode | Everything that broadcasts, plus **Scan network** | — | This computer only |
| Wi-Fi monitor mode | Every nearby Wi-Fi device | ✓ | Open networks only (WPA2/3 data is encrypted) |
| Gateway, mirrored switch port, or Raspberry Pi access point | All LAN devices | — | ✓ for every device |
| Simulator | Simulated smart home | ✓ | ✓ |

For an IoT lab, run Niv.ON on the machine that acts as the access point for the devices (for example a Raspberry Pi running `hostapd`), or on a switch port that mirrors the router.

---

## Five-minute demo

1. **Overview → Demo simulator.** Devices appear and name themselves from DHCP, mDNS and SSDP — *HIKVISION-DS2CD2143*, *Living-Room-Roku*, *Student-Laptop* — each in its learning phase.
2. **Open the camera.** Identity clues, destinations with DNS names, hour-of-day profile, signal strength, connection history. Give it a name.
3. **Live feed.** Filter by `dns`, `tls` or `beacon` to show what is on the air.
4. **After two minutes the network turns hostile**, one scenario about every 45 seconds:
   - the camera reaches a Tor relay on port 9001,
   - the smart plug runs a Mirai-style Telnet scan,
   - the thermostat uploads 6 MB to an unknown domain,
   - the access point is hit with a deauthentication flood,
   - an unknown ESP32 board joins the network.
5. **Alerts.** Triage by severity, acknowledge, or mark as normal.
6. **Switch to the real network** from the source switcher in the top bar, then **Devices → Scan network**. The demo devices disappear — they live in their own ephemeral workspace — and you can clear them from **Networks**.

---

## Architecture

```
┌──────────────────────────── Rust engine ────────────────────────────┐
│  libpcap / file / simulator ──► bounded queue ──► processor         │
│        │                                             │              │
│  parser: radiotap · 802.11 · Ethernet · ARP · IPv4/6 · TCP/UDP      │
│          DNS · TLS SNI · DHCP · mDNS · SSDP · HTTP                  │
│                                                      ▼              │
│  engine: device profiles ─► baselines ─► anomaly rules ─► alerts    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ Tauri commands & events (1 Hz)
┌───────────────────────────────▼─────────────────────────────────────┐
│  React + TypeScript: overview · devices · live feed · alerts · setup│
└─────────────────────────────────────────────────────────────────────┘
```

| Path | Responsibility |
|---|---|
| `src-tauri/src/capture.rs` | Capture sessions, channel hopping, processing pipeline |
| `src-tauri/src/parser.rs` | Zero-copy protocol decoders |
| `src-tauri/src/engine.rs` | Device profiles, baselines, anomaly rules, live feed |
| `src-tauri/src/netif.rs` | Interface discovery per OS, permissions, self-test, ARP sweep |
| `src-tauri/src/oui.rs` | Vendor registry and device classifier |
| `src-tauri/src/simulator.rs` | Synthetic smart home with scripted attacks |
| `src/` | Desktop interface |

Memory stays bounded on busy networks (≤3,000 destinations per device, ≤5,000 devices, transient devices pruned after 30 minutes). Capture threads never wait on the UI.

---

## Development

Requirements: Rust (stable), Node.js 20+, and on Linux `libpcap-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev`. Windows builds also need the [Npcap SDK](https://npcap.com/#download) on the `LIB` path.

```bash
npm install
npm run tauri dev                                  # run with hot reload
cd src-tauri && cargo test                         # decoders, rules, full attack simulation
cargo test real_ -- --ignored --nocapture          # against this machine's real network
```

### Releasing

```bash
scripts/setup-release.sh --github   # once: Apple notarization login + CI secrets
scripts/release.sh 0.2.0            # bump version, tag, push
```

The tag triggers CI, which builds all platforms, signs and notarizes the macOS app, signs every update package, and publishes the release with `latest.json` — the feed installed copies check. `scripts/build-mac.sh` produces a signed and notarized DMG locally.

---

## Responsible use

Capture only on networks you own or are explicitly authorized to assess. Intercepting other people's communications without permission is illegal in most jurisdictions.

## Known limits

- WPA2/WPA3 encryption hides IP-level behavior from a monitor-mode observer; devices are still profiled by MAC, signal, timing and probes.
- Learned active-hours detection needs at least 24 hours of learning; shorter periods rely on configurable quiet hours.
- Phones that rotate private MAC addresses can appear as more than one device over time.

<p align="center"><sub>Niv.ON · © 2026 Bryan Parreira</sub></p>
