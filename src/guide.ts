import type { Page } from "./nav";

/** Plain-language description of every page: sidebar tooltips, page intros and ⌘K search. */
export interface PageGuide {
  /** Name shown in the sidebar, header and links. */
  label: string;
  /** One line: what the page is for. */
  hint: string;
  /** What you can do here. */
  tasks: string[];
  /** Where to go next, in workflow order. */
  next: Page[];
  /** Extra words the ⌘K palette should match. */
  keywords: string;
}

export const GUIDE: Record<Page, PageGuide> = {
  overview: {
    label: "Overview",
    hint: "Health of your network at a glance: activity, open alerts and the devices to look at first.",
    tasks: ["See whether anything needs attention right now", "Spot the busiest and riskiest devices", "Follow the getting-started checklist"],
    next: ["alerts", "devices", "map"],
    keywords: "home summary status health",
  },
  dashboards: {
    label: "Dashboards",
    hint: "Your own panels — charts and tables that refresh every 10 seconds.",
    tasks: ["Add the security-operations starter panels", "Build a panel from any search", "Switch each panel between table, bar, line or single value"],
    next: ["search", "alerts"],
    keywords: "charts panels widgets soc",
  },
  alerts: {
    label: "Alerts",
    hint: "Every alert in one queue. Open one to see the exact traffic that caused it and what to do about it.",
    tasks: ["Click an alert title for the full story and response steps", "Set status: New → In progress → Resolved or False positive", "Assign an owner and add investigation notes"],
    next: ["devices", "map", "automation"],
    keywords: "incident review alerts triage threats warnings notable",
  },
  search: {
    label: "Search",
    hint: "Ask questions of everything Niv.ON recorded — alerts, devices, connections, DNS and live packets.",
    tasks: ["Start from an example query below the search box", "Save a search, add it to a dashboard or turn it into a detection", "Import CSV lookup tables to add your own context"],
    next: ["dashboards", "detections"],
    keywords: "spl query find filter logs splunk",
  },
  devices: {
    label: "Devices",
    hint: "Everything seen on the network: what it is, who made it, its risk score and what it talks to.",
    tasks: ["Open a device for its timeline, connections, DNS and security findings", "Rename or re-classify a device so alerts read clearly", "Set its priority — important devices raise alert urgency"],
    next: ["map", "alerts", "compliance"],
    keywords: "hosts inventory assets iot phones cameras",
  },
  map: {
    label: "Network map",
    hint: "A picture of your network: internet → router → devices, with live traffic and any threat addresses.",
    tasks: ["Watch traffic flow (moving dots, faster = more data)", "Hover a device to trace where its traffic goes", "Check the red Threat addresses box and click Investigate"],
    next: ["alerts", "devices"],
    keywords: "diagram topology graph traffic flow threats",
  },
  feed: {
    label: "Live feed",
    hint: "Packets as they arrive, decoded into plain language.",
    tasks: ["Filter by type (data, management, control) or by text", "Hide routine acknowledgement noise", "Click a device name to open it"],
    next: ["devices", "search"],
    keywords: "packets wireshark realtime stream",
  },
  compliance: {
    label: "Compliance",
    hint: "Security checklist for your devices: weak services, known vulnerabilities and an overall score.",
    tasks: ["See which checks fail and on which devices", "Fix the highest-severity findings first", "Use the posture score to see how many checks pass"],
    next: ["devices", "intel"],
    keywords: "vulnerabilities cve kev posture audit score findings",
  },
  intel: {
    label: "Threat intel",
    hint: "Lists of known-bad addresses and attack signatures Niv.ON checks traffic against.",
    tasks: ["Update threat feeds (malware, botnet, Tor lists)", "Download Emerging Threats signatures or import .rules files", "See how many indicators are active"],
    next: ["rules", "alerts"],
    keywords: "feeds ioc indicators signatures suricata snort ids blocklist",
  },
  capture: {
    label: "Capture & adapters",
    hint: "Where Niv.ON listens: this computer's network card, a Wi-Fi card in monitor mode, a file or a remote sensor.",
    tasks: ["Pick the interface and test that capture works", "Enable monitor mode on a Wi-Fi adapter (e.g. ALFA)", "Stream from a Raspberry Pi / Linux sensor over SSH"],
    next: ["devices", "feed"],
    keywords: "interface adapter alfa monitor mode wifi sensor pcap setup source",
  },
  networks: {
    label: "Networks",
    hint: "Each network you monitor keeps its own devices, baselines and alerts.",
    tasks: ["See every saved network with its router, devices and open alerts", "Rename a network or forget its data", "Clear demo data"],
    next: ["capture", "overview"],
    keywords: "workspaces sites home office",
  },
  rules: {
    label: "Detection rules",
    hint: "Turn detections on or off, tune their sensitivity, and set data retention and reports.",
    tasks: ["Adjust learning time and thresholds", "Choose which threat feeds and checks run", "Schedule reports and set how long history is kept"],
    next: ["detections", "automation"],
    keywords: "settings thresholds tuning retention reports baseline",
  },
  detections: {
    label: "Custom detections",
    hint: "Your own alert rules, written as searches that run every minute.",
    tasks: ["Start from the example detections", "Write a search that returns rows when something is wrong", "Choose the severity of the alert it raises"],
    next: ["search", "alerts"],
    keywords: "correlation custom rules saved search",
  },
  automation: {
    label: "Automation",
    hint: "Playbooks that react to alerts automatically — notify you, save evidence, tag or run a script.",
    tasks: ["Create a playbook that runs from a chosen severity upwards", "Choose actions: notify, save packets, assign, tag, raise priority", "Check the run history"],
    next: ["alerts", "rules"],
    keywords: "soar playbooks response notify script actions",
  },
};

export const pageLabel = (p: Page) => GUIDE[p]?.label ?? p;
