import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, inTauri, onTick, type Access, type Status, type TrafficPoint } from "./api";

interface Live {
  status: Status | null;
  traffic: TrafficPoint[];
  refresh: () => void;
  /** Can this user capture live packets? (null = not checked yet) */
  access: Access | null;
  recheckAccess: () => Promise<Access | null>;
}

const Ctx = createContext<Live>({
  status: null,
  traffic: [],
  refresh: () => {},
  access: null,
  recheckAccess: async () => null,
});

/** Holds the 1 Hz status + traffic stream pushed by the backend. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  const [access, setAccess] = useState<Access | null>(null);

  const recheckAccess = useCallback(async () => {
    if (!inTauri) return null;
    try {
      const a = await api.checkAccess();
      setAccess(a);
      return a;
    } catch {
      return null;
    }
  }, []);

  const refresh = useCallback(() => {
    if (!inTauri) return;
    api.getStatus().then(setStatus).catch(console.error);
    api.getTraffic().then(setTraffic).catch(console.error);
  }, []);

  useEffect(() => {
    if (!inTauri) return;
    refresh();
    recheckAccess();
    const un = onTick((t) => {
      setStatus(t.status);
      setTraffic(t.traffic);
    });
    return () => {
      un.then((f) => f());
    };
  }, [refresh, recheckAccess]);

  return <Ctx.Provider value={{ status, traffic, refresh, access, recheckAccess }}>{children}</Ctx.Provider>;
}

export const useLive = () => useContext(Ctx);

/** Poll an async loader every `ms` while mounted. */
export function usePoll<T>(load: () => Promise<T>, ms: number, deps: unknown[] = []): [T | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const loader = useRef(load);
  loader.current = load;
  const run = useCallback(() => {
    if (!inTauri) return;
    loader.current().then(setData).catch(console.error);
  }, []);
  useEffect(() => {
    run();
    const id = setInterval(run, ms);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, run, ...deps]);
  return [data, run];
}
