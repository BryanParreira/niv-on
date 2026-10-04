import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

export type Page =
  | "overview"
  | "dashboards"
  | "map"
  | "devices"
  | "feed"
  | "search"
  | "alerts"
  | "compliance"
  | "networks"
  | "intel"
  | "capture"
  | "rules"
  | "detections"
  | "automation";
export interface Route {
  page: Page;
  device?: string;
  /** Optional sub-tab (e.g. device detail tab). */
  tab?: string;
}

interface Nav {
  route: Route;
  go: (r: Route | Page) => void;
  openDevice: (mac: string, tab?: string) => void;
  back: () => void;
  canBack: boolean;
}

const Ctx = createContext<Nav>(null as unknown as Nav);

/** Tiny in-memory router with a back stack (no URL needed in a desktop app). */
export function NavProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<Route[]>([{ page: "overview" }]);
  const route = stack[stack.length - 1];
  const go = useCallback((r: Route | Page) => {
    const next = typeof r === "string" ? { page: r } : r;
    setStack((s) => {
      const cur = s[s.length - 1];
      if (cur.page === next.page && cur.device === next.device && cur.tab === next.tab) return s;
      return [...s.slice(-30), next];
    });
  }, []);
  const openDevice = useCallback((mac: string, tab?: string) => go({ page: "devices", device: mac, tab }), [go]);
  const back = useCallback(() => setStack((s) => (s.length > 1 ? s.slice(0, -1) : s)), []);
  return (
    <Ctx.Provider value={{ route, go, openDevice, back, canBack: stack.length > 1 }}>{children}</Ctx.Provider>
  );
}

export const useNav = () => useContext(Ctx);
