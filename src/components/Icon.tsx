// Minimal inline stroke icon set (24px grid, rendered at any size).
const paths: Record<string, string> = {
  dashboard: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  devices: "M4 5h16v10H4zM2 19h20M9 15v4M15 15v4",
  alerts: "M12 3l9 16H3zM12 10v4M12 17.5v.5",
  settings:
    "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  sliders: "M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  play: "M7 4l13 8-13 8z",
  stop: "M6 6h12v12H6z",
  pause: "M7 4h3v16H7zM14 4h3v16h-3z",
  back: "M15 18l-6-6 6-6",
  chevron: "M9 18l6-6-6-6",
  down: "M6 9l6 6 6-6",
  check: "M5 12l5 5 9-11",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  lock: "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.5v.5",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  download: "M12 3v12M7 10l5 5 5-5M4 21h16",
  wifi: "M2 9a15 15 0 0 1 20 0M5 13a10 10 0 0 1 14 0M8.5 16.5a5 5 0 0 1 7 0M12 20h.01",
  ethernet: "M4 8h16v9H4zM8 17v3M12 17v3M16 17v3M8 8V5h8v3",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-5-5",
  x: "M6 6l12 12M18 6L6 18",
  octagon: "M8 3h8l5 5v8l-5 5H8l-5-5V8zM12 8v5M12 16v.5",
  circle: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z",
  folder: "M3 6h6l2 2h10v11H3z",
  file: "M6 2h9l5 5v15H6zM14 2v6h6",
  radar: "M12 12l7-7M12 21a9 9 0 1 1 9-9M12 17a5 5 0 1 1 5-5M12 12h.01",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18",
  zap: "M13 2L4 14h7l-1 8 9-12h-7z",
  beaker: "M9 3h6M10 3v6L4 19a2 2 0 0 0 2 3h12a2 2 0 0 0 2-3l-6-10V3",
  command: "M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z",
  database: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  // device classes
  laptop: "M4 5h16v11H4zM2 19h20",
  phone: "M7 2h10v20H7zM11 18h2",
  camera: "M3 7h4l2-3h6l2 3h4v13H3zM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
  thermostat: "M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0z",
  speaker: "M6 2h12v20H6zM12 18a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 6.5v.5",
  tv: "M3 5h18v12H3zM8 21h8M12 17v4",
  plug: "M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4",
  bulb: "M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V17h8v-2.3A7 7 0 0 0 12 2z",
  printer: "M6 9V2h12v7M6 18H4v-9h16v9h-2M6 14h12v8H6z",
  router: "M3 14h18v6H3zM7 17h.01M11 17h.01M12 14V9M8.5 7a5 5 0 0 1 7 0M6 4.5a8.5 8.5 0 0 1 12 0",
  ap: "M12 13v8M5 8a10 10 0 0 1 14 0M8 11a5 5 0 0 1 8 0M12 13h.01",
  chip: "M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4",
  gamepad: "M6 11h4M8 9v4M15 12h.01M18 10h.01M17.3 5H6.7a4 4 0 0 0-4 3.6L2 15a3 3 0 0 0 5 2.2L9 15h6l2 2.2A3 3 0 0 0 22 15l-.7-6.4A4 4 0 0 0 17.3 5z",
  home: "M3 11l9-8 9 8M5 9v12h14V9",
  question: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.5-3 4.5M12 17.5v.5",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
};

export function Icon({ name, size = 16, className }: { name: string; size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d={paths[name] ?? paths.circle} />
    </svg>
  );
}

/** Icon for a device class / tag. */
export function classIcon(cls: string): string {
  const c = cls.toLowerCase();
  if (c.includes("camera") || c.includes("doorbell")) return "camera";
  if (c.includes("thermostat") || c.includes("sensor")) return "thermostat";
  if (c.includes("speaker")) return "speaker";
  if (c.includes("tv") || c.includes("media")) return "tv";
  if (c.includes("plug") || c.includes("hub")) return "plug";
  if (c.includes("light")) return "bulb";
  if (c.includes("printer")) return "printer";
  if (c.includes("router") || c.includes("gateway")) return "router";
  if (c.includes("access point")) return "ap";
  if (c.includes("iot") || c.includes("single-board")) return "chip";
  if (c.includes("game")) return "gamepad";
  if (c.includes("phone") || c.includes("tablet")) return "phone";
  if (c.includes("laptop") || c.includes("pc") || c.includes("desktop")) return "laptop";
  if (c.includes("network")) return "router";
  return "question";
}

/** Device avatar: class icon in a tinted tile. */
export function Avatar({ cls, iot, net, self, large }: { cls: string; iot?: boolean; net?: boolean; self?: boolean; large?: boolean }) {
  const tone = self ? "self" : net ? "net" : iot ? "iot" : "";
  return (
    <span className={`avatar ${tone} ${large ? "lg" : ""}`}>
      <Icon name={self ? "user" : classIcon(cls)} size={large ? 24 : 17} />
    </span>
  );
}
