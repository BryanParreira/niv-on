// Typed bridge to the Rust backend (Tauri commands + events).
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Source = "live" | "simulator" | "file" | "remote";

export interface Alert {
  id: number;
  ts: string;
  severity: Severity;
  rule: string;
  title: string;
  message: string;
  device: string | null;
  deviceLabel: string | null;
  remote: string | null;
  port: number | null;
  value: number | null;
  acknowledged: boolean;
  /** MITRE ATT&CK technique, e.g. "T1046". */
  mitreId: string | null;
  mitreName: string | null;
  tactic: string | null;
  status: AlertStatus;
  owner: string | null;
  notes: { ts: string; text: string }[];
  /** Severity adjusted by the device's asset priority. */
  urgency: Severity | null;
  /** Saved packet-evidence pcap. */
  evidence: string | null;
  /** The triggering packet. */
  context: AlertContext | null;
}

export interface AlertContext {
  protocol: string;
  summary: string;
  transport: string | null;
  srcMac: string | null;
  dstMac: string | null;
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  service: string | null;
  domain: string | null;
  direction: "outbound" | "inbound" | "local";
  frameLen: number;
  payload: string | null;
  payloadHex: string | null;
  /** Rate rules: this is the packet that crossed the threshold. */
  aggregate: boolean;
}

export interface RiskPart {
  source: string;
  kind: "alert" | "exposure";
  points: number;
  count: number;
  severity: Severity;
}

export type AlertStatus = "new" | "in-progress" | "resolved" | "false-positive";
export type Priority = "low" | "medium" | "high" | "critical";
export const PRIORITIES: Priority[] = ["low", "medium", "high", "critical"];

export interface TrafficPoint {
  t: number;
  bytes: number;
  packets: number;
  management: number;
  control: number;
  data: number;
  ethernet: number;
}

export interface FrameCounts {
  management: number;
  control: number;
  data: number;
  ethernet: number;
}

export interface Totals {
  packets: number;
  bytes: number;
  frames: FrameCounts;
  withIp: number;
  protected: number;
}

export interface CaptureStats {
  received: number;
  dropped: number;
  ifDropped: number;
  queueDropped: number;
  undecoded: number;
  error: string | null;
  finished: boolean;
}

export interface SessionInfo {
  source: Source;
  interface: string | null;
  file: string | null;
  linktype: string | null;
  monitorMode: boolean;
  hopping: boolean;
  startedAt: string;
  notes: string[];
}

export interface Status {
  running: boolean;
  session: SessionInfo | null;
  channel: number | null;
  stats: CaptureStats;
  totals: Totals;
  clock: string;
  devices: number;
  activeDevices: number;
  alerts: { open: number; critical: number; high: number; medium: number; low: number; info: number };
  packetsPerSec: number;
  bytesPerSec: number;
  dataDir: string;
  ouiEntries: number;
  network: { id: string; name: string; kind: NetKind } | null;
  /** Packet evidence can be saved for current alerts. */
  evidence: boolean;
}

export type NetKind = "live" | "file" | "demo" | "legacy";

export interface NetworkSummary {
  id: string;
  name: string;
  kind: NetKind;
  created: string;
  lastUsed: string;
  interface: string | null;
  subnet: string | null;
  gatewayMac: string | null;
  ssid: string | null;
  devices: number;
  openAlerts: number;
  current: boolean;
}

export interface DeviceSummary {
  mac: string;
  label: string;
  vendor: string | null;
  name: string | null;
  tag: string | null;
  autoClass: string;
  class: string;
  isIot: boolean;
  randomized: boolean;
  isAp: boolean;
  rssi: number | null;
  rssiAvg: number | null;
  channel: number | null;
  firstSeen: string;
  lastSeen: string;
  frames: number;
  txBytes: number;
  rxBytes: number;
  ssid: string | null;
  ips: string[];
  destinations: number;
  learning: boolean;
  openAlerts: number;
  recentBytes: number;
  hostname: string | null;
  isGateway: boolean;
  isSelf: boolean;
  services: number;
  /** 0-100, from open alerts with a 24 h half-life. */
  risk: number;
  priority: Priority;
  os: string | null;
  findings: number;
  exposure: Severity | null;
}

export interface Destination {
  ip: string;
  domain: string | null;
  external: boolean;
  ports: number[];
  txBytes: number;
  rxBytes: number;
  packets: number;
  firstSeen: string;
  lastSeen: string;
  inBaseline: boolean;
  alerted: boolean;
}

export interface Connection {
  bssid: string;
  ssid: string | null;
  firstSeen: string;
  lastSeen: string;
  frames: number;
}

export interface Baseline {
  learningStarted: string;
  learningUntil: string;
  hours: boolean[];
  destinations: string[];
  domains: string[];
  ports: number[];
  peakWindowBytes: number;
  avgWindowBytes: number;
  windows: number;
  /** JA4 fingerprints learned. */
  tls?: string[];
}

export interface DeviceDetail {
  mac: string;
  vendor: string | null;
  randomized: boolean;
  name: string | null;
  tag: string | null;
  notes: string;
  autoClass: string;
  firstSeen: string;
  lastSeen: string;
  rssi: number | null;
  rssiAvg: number | null;
  channel: number | null;
  isAp: boolean;
  onNetwork: boolean;
  frames: FrameCounts;
  txBytes: number;
  rxBytes: number;
  txPackets: number;
  rxPackets: number;
  ssids: string[];
  probedSsids: string[];
  connections: Connection[];
  ips: string[];
  destinations: Record<string, Destination>;
  ports: Record<string, number>;
  hourly: number[];
  baseline: Baseline;
  alertedPorts: number[];
  label: string;
  class: string;
  isIot: boolean;
  learning: boolean;
  learningProgress: number;
  history: [number, number][];
  alerts: Alert[];
  hostname: string | null;
  hostnames: string[];
  vendorClass: string | null;
  services: string[];
  banners: string[];
  isGateway: boolean;
  isSelf: boolean;
  risk: number;
  flagged: string[];
  priority: Priority;
  os: string | null;
  findings: Finding[];
  dhcpParams: string | null;
  tls: Record<string, { ja3: string; firstSeen: string; lastSeen: string; count: number; sni: string | null; legacy: boolean }>;
  serverPorts: Record<string, number>;
  insecure: string[];
  resolvers: string[];
  riskParts: RiskPart[];
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  detail: string;
  cves: string[];
}

export interface CheckResult {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  /** [mac, label, detail] */
  failing: [string, string, string][];
  evaluated: number;
}

export interface Flow {
  start: string;
  end: string;
  mac: string;
  localIp: string;
  localPort: number | null;
  remoteIp: string;
  remotePort: number | null;
  proto: string;
  service: number | null;
  domain: string | null;
  bytesOut: number;
  bytesIn: number;
  packets: number;
  external: boolean;
  outbound: boolean;
  label: string | null;
  open: boolean;
}

export interface DnsRow {
  ts: string;
  mac: string;
  query: string;
  answers: string[];
  rcode: number;
  resolver: string;
  label: string | null;
}

export interface TimelineEvent {
  ts: string;
  kind: "device" | "baseline" | "alert" | "contact" | "new-contact" | "fingerprint" | "dns" | "transfer";
  title: string;
  detail: string;
  severity: Severity | null;
}

export interface TopoNode {
  id: string;
  label: string;
  kind: "device" | "router" | "self" | "ap" | "internet";
  class: string;
  risk: number;
  alerts: number;
  iot: boolean;
  flagged: boolean;
}
export interface TopoEdge {
  from: string;
  to: string;
  kind: "lan" | "internet" | "peer";
  bytes: number;
  suspicious: boolean;
}

export interface FeedStatus {
  id: string;
  name: string;
  description: string;
  url: string;
  severity: Severity;
  enabled: boolean;
  updated: string | null;
  count: number;
  error: string | null;
}
export interface IntelStatus {
  feeds: FeedStatus[];
  kev: { updated: string | null; count: number; error: string | null };
  indicators: number;
  watchlist: number;
  autoUpdate: boolean;
}

export interface RulesStatus {
  total: number;
  enabled: boolean;
  sources: { name: string; loaded: number; skipped: number; builtin: boolean }[];
  etCategories: { id: string; description: string; installed: boolean }[];
}

export type PlaybookAction =
  | { type: "notify" }
  | { type: "evidence" }
  | { type: "investigate"; owner: string }
  | { type: "tag"; tag: string }
  | { type: "priority"; priority: Priority }
  | { type: "script"; path: string };

export interface Playbook {
  id: string;
  name: string;
  enabled: boolean;
  minSeverity: Severity;
  rules: string[];
  iotOnly: boolean;
  actions: PlaybookAction[];
}

export interface RunLog {
  ts: string;
  playbook: string;
  alertId: number;
  alertTitle: string;
  results: string[];
  ok: boolean;
}

export interface StoreStats {
  connections: number;
  dns: number;
  bytes: number;
  oldest: string | null;
}

export interface DataSettings {
  retentionDays: number;
  feeds: string[];
  autoUpdateIntel: boolean;
  autoEvidence: boolean;
  reportSchedule: "off" | "daily" | "weekly";
  lastReport: string | null;
}

export type IfKind = "wifi" | "ethernet" | "loopback" | "vpn" | "virtual" | "other";

export interface InterfaceInfo {
  name: string;
  friendly: string;
  description: string | null;
  kind: IfKind;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
  network: string | null;
  up: boolean;
  running: boolean;
  isDefault: boolean;
  gateway: string | null;
  hidden: boolean;
}

export interface Access {
  ok: boolean;
  message: string;
  canFix: boolean;
  platform: "macos" | "linux" | "windows";
}

export interface TestResult {
  ok: boolean;
  linktype: string | null;
  packets: number;
  decoded: number;
  withRssi: number;
  seconds: number;
  message: string;
}

export interface FeedItem {
  seq: number;
  ts: string;
  kind: "management" | "control" | "data" | "ethernet";
  protocol: string;
  src: string | null;
  dst: string | null;
  rssi: number | null;
  channel: number | null;
  len: number;
  info: string;
}

export interface CaptureSettings {
  source: Source;
  interface: string | null;
  monitorMode: boolean;
  promiscuous: boolean;
  channel: number | null;
  hop: boolean;
  hopChannels: number[];
  hopDwellMs: number;
  bpfFilter: string;
  filePath: string | null;
  remote: RemoteSensor;
}

export interface RemoteSensor {
  host: string;
  port: number;
  iface: string;
  monitor: boolean;
  channel: number;
  hop: boolean;
  customCommand: string;
}

export interface Adapter {
  iface: string | null;
  name: string;
  chipset: string | null;
  driver: string | null;
  usbId: string | null;
  usb: boolean;
  alfaChipset: boolean;
  mode: "managed" | "monitor" | "unknown";
  monitorSupported: boolean;
  canToggle: boolean;
  note: string;
}

export interface RuleSettings {
  learningMinutes: number;
  newDestination: boolean;
  newDestinationIotOnly: boolean;
  unusualTime: boolean;
  quietHoursEnabled: boolean;
  quietStartHour: number;
  quietEndHour: number;
  volumeSpike: boolean;
  spikeFactor: number;
  spikeMinBytes: number;
  connectionBurst: boolean;
  synThreshold: number;
  unexpectedPort: boolean;
  riskyPorts: number[];
  deauthFlood: boolean;
  deauthThreshold: number;
  newDevice: boolean;
  threatIntel: boolean;
  watchlist: string[];
  suspiciousDomains: boolean;
  spoofing: boolean;
  riskThreshold: number;
  ids: boolean;
  peerGroups: boolean;
  fingerprintDrift: boolean;
}

export interface SavedSearch {
  name: string;
  query: string;
}

export type Viz = "table" | "bar" | "line" | "single";
export interface Panel {
  id: string;
  title: string;
  query: string;
  viz: Viz;
  width: 1 | 2;
}

export interface Detection {
  id: string;
  name: string;
  query: string;
  severity: Severity;
  enabled: boolean;
  throttleMinutes: number;
}

export interface Lookup {
  name: string;
  columns: string[];
  rows: string[][];
}

export interface Library {
  savedSearches: SavedSearch[];
  panels: Panel[];
  detections: Detection[];
  lookups: Lookup[];
}

export interface Settings {
  capture: CaptureSettings;
  rules: RuleSettings;
  library: Library;
  data: DataSettings;
  playbooks: Playbook[];
}

export interface Tick {
  status: Status;
  traffic: TrafficPoint[];
}

export const api = {
  listInterfaces: () => invoke<InterfaceInfo[]>("list_interfaces"),
  checkAccess: () => invoke<Access>("check_access"),
  fixAccess: () => invoke<string>("fix_access"),
  testInterface: (name: string, monitor: boolean, promiscuous: boolean) =>
    invoke<TestResult>("test_interface", { name, monitor, promiscuous }),
  scanNetwork: () => invoke<string>("scan_network"),
  listNetworks: () => invoke<NetworkSummary[]>("list_networks"),
  openNetwork: (id: string) => invoke<void>("open_network", { id }),
  renameNetwork: (id: string, name: string) => invoke<void>("rename_network", { id, name }),
  deleteNetwork: (id: string) => invoke<void>("delete_network", { id }),
  clearDemo: () => invoke<void>("clear_demo"),
  updateVendorDb: () => invoke<string>("update_vendor_db"),
  getFeed: (after?: number) => invoke<FeedItem[]>("get_feed", { after }),
  switchSource: (source: Source, iface?: string | null, monitorMode?: boolean) =>
    invoke<SessionInfo>("switch_source", { source, interface: iface ?? null, monitorMode: monitorMode ?? null }),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<void>("save_settings", { settings }),
  startCapture: () => invoke<SessionInfo>("start_capture"),
  stopCapture: () => invoke<void>("stop_capture"),
  getStatus: () => invoke<Status>("get_status"),
  getTraffic: () => invoke<TrafficPoint[]>("get_traffic"),
  getDevices: () => invoke<DeviceSummary[]>("get_devices"),
  getDevice: (mac: string) => invoke<DeviceDetail | null>("get_device", { mac }),
  updateDevice: (mac: string, patch: { name?: string; tag?: string; notes?: string; priority?: Priority }) =>
    invoke<boolean>("update_device", { mac, ...patch }),
  relearnDevice: (mac: string) => invoke<boolean>("relearn_device", { mac }),
  forgetDevice: (mac: string) => invoke<boolean>("forget_device", { mac }),
  getAlerts: (limit?: number) => invoke<Alert[]>("get_alerts", { limit }),
  ackAlert: (id?: number) => invoke<void>("ack_alert", { id }),
  acceptAlert: (id: number) => invoke<void>("accept_alert", { id }),
  clearAlerts: () => invoke<void>("clear_alerts"),
  resetData: () => invoke<void>("reset_data"),
  exportReport: () => invoke<string>("export_report"),
  updateAlerts: (ids: number[], patch: { status?: AlertStatus; owner?: string; note?: string }) =>
    invoke<number>("update_alerts", { ids, status: patch.status ?? null, owner: patch.owner ?? null, note: patch.note ?? null }),
  raiseDetection: (name: string, severity: Severity, message: string, devices: string[], throttleMinutes: number) =>
    invoke<number>("raise_detection", { name, severity, message, devices, throttleMinutes }),
  getConnections: (opts: { mac?: string; hours?: number; limit?: number } = {}) =>
    invoke<Flow[]>("get_connections", { mac: opts.mac ?? null, hours: opts.hours ?? null, limit: opts.limit ?? null }),
  getDns: (opts: { mac?: string; hours?: number; limit?: number } = {}) =>
    invoke<DnsRow[]>("get_dns", { mac: opts.mac ?? null, hours: opts.hours ?? null, limit: opts.limit ?? null }),
  getTimeline: (mac: string) => invoke<TimelineEvent[]>("get_timeline", { mac }),
  getTopology: () => invoke<{ nodes: TopoNode[]; edges: TopoEdge[] }>("get_topology"),
  getCompliance: () => invoke<CheckResult[]>("get_compliance"),
  intelStatus: () => invoke<IntelStatus>("intel_status"),
  updateIntel: () => invoke<IntelStatus>("update_intel"),
  rulesStatus: () => invoke<RulesStatus>("rules_status"),
  importRules: (path: string) => invoke<string>("import_rules", { path }),
  removeRules: (name: string) => invoke<string>("remove_rules", { name }),
  downloadEt: (categories: string[]) => invoke<string>("download_et", { categories }),
  saveEvidence: (id: number) => invoke<string>("save_evidence", { id }),
  revealPath: (path: string) => invoke<void>("reveal_path", { path }),
  openPath: (path: string) => invoke<void>("open_path", { path }),
  generateReport: (days: number) => invoke<string>("generate_report", { days }),
  playbookLog: () => invoke<RunLog[]>("playbook_log"),
  storeStats: () => invoke<StoreStats>("store_stats"),
  listAdapters: () => invoke<Adapter[]>("list_adapters"),
  setMonitorMode: (iface: string, enable: boolean, channel?: number) => invoke<string>("set_monitor_mode", { iface, enable, channel: channel ?? null }),
  testRemoteSensor: (sensor: RemoteSensor) => invoke<string>("test_remote_sensor", { sensor }),
};

/** Read-modify-write the persisted search library. */
export async function updateLibrary(fn: (l: Library) => Library): Promise<Library> {
  const s = await api.getSettings();
  const library = fn(s.library);
  await api.saveSettings({ ...s, library });
  return library;
}

export const newId = () => Math.random().toString(36).slice(2, 10);

export function onTick(cb: (t: Tick) => void): Promise<UnlistenFn> {
  return listen<Tick>("niv://tick", (e) => cb(e.payload));
}

export function onAlerts(cb: (a: Alert[]) => void): Promise<UnlistenFn> {
  return listen<Alert[]>("niv://alerts", (e) => cb(e.payload));
}

/** Rules whose subject can be folded into the device baseline ("mark as normal"). */
export const ACCEPTABLE_RULES = new Set(["new-destination", "unexpected-port", "volume-spike", "unusual-time", "risky-port", "suspicious-domain"]);

export const TAG_PRESETS = [
  "Smart Camera",
  "Doorbell",
  "Thermostat",
  "Smart Plug",
  "Smart Lighting",
  "Smart Speaker",
  "Smart TV",
  "Hub",
  "Sensor",
  "Laptop",
  "Phone",
  "Tablet",
  "Desktop",
  "Printer",
  "Game Console",
  "Router",
  "Access Point",
  "Other",
];
