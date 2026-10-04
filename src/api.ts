// Typed bridge to the Rust backend (Tauri commands + events).
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Source = "live" | "simulator" | "file";

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
}

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
}

export interface Settings {
  capture: CaptureSettings;
  rules: RuleSettings;
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
  updateDevice: (mac: string, patch: { name?: string; tag?: string; notes?: string }) =>
    invoke<boolean>("update_device", { mac, ...patch }),
  relearnDevice: (mac: string) => invoke<boolean>("relearn_device", { mac }),
  forgetDevice: (mac: string) => invoke<boolean>("forget_device", { mac }),
  getAlerts: (limit?: number) => invoke<Alert[]>("get_alerts", { limit }),
  ackAlert: (id?: number) => invoke<void>("ack_alert", { id }),
  acceptAlert: (id: number) => invoke<void>("accept_alert", { id }),
  clearAlerts: () => invoke<void>("clear_alerts"),
  resetData: () => invoke<void>("reset_data"),
  exportReport: () => invoke<string>("export_report"),
};

export function onTick(cb: (t: Tick) => void): Promise<UnlistenFn> {
  return listen<Tick>("niv://tick", (e) => cb(e.payload));
}

export function onAlerts(cb: (a: Alert[]) => void): Promise<UnlistenFn> {
  return listen<Alert[]>("niv://alerts", (e) => cb(e.payload));
}

/** Rules whose subject can be folded into the device baseline ("mark as normal"). */
export const ACCEPTABLE_RULES = new Set(["new-destination", "unexpected-port", "volume-spike", "unusual-time", "risky-port"]);

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
