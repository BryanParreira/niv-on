import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, inTauri } from "./api";

type Phase = "idle" | "checking" | "current" | "available" | "downloading" | "installing" | "error";

interface UpdaterState {
  version: string | null;
  phase: Phase;
  update: Update | null;
  /** 0..1 while downloading, null when size unknown */
  progress: number | null;
  error: string | null;
  lastChecked: Date | null;
  checkNow: (manual?: boolean) => Promise<void>;
  install: () => Promise<void>;
}

const Ctx = createContext<UpdaterState>(null as unknown as UpdaterState);
const SIX_HOURS = 6 * 60 * 60 * 1000;

/** Checks GitHub Releases for a signed update at launch and every 6 hours. */
export function UpdaterProvider({ children }: { children: ReactNode }) {
  const [version, setVersion] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [update, setUpdate] = useState<Update | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const busy = useRef(false);

  const checkNow = useCallback(async (manual = false) => {
    if (!inTauri || busy.current) return;
    busy.current = true;
    setPhase("checking");
    setError(null);
    try {
      const u = await check();
      setLastChecked(new Date());
      setUpdate(u);
      setPhase(u ? "available" : "current");
    } catch (e) {
      // Background checks fail quietly (offline, no release yet); manual ones report.
      setPhase(manual ? "error" : "idle");
      if (manual) setError(String(e));
    } finally {
      busy.current = false;
    }
  }, []);

  const install = useCallback(async () => {
    if (!update) return;
    setPhase("downloading");
    setProgress(0);
    let total = 0;
    let done = 0;
    try {
      // Persist profiles/baselines before the installer replaces the app.
      await api.stopCapture().catch(() => {});
      await update.downloadAndInstall((ev) => {
        if (ev.event === "Started") {
          total = ev.data.contentLength ?? 0;
          setProgress(total ? 0 : null);
        } else if (ev.event === "Progress") {
          done += ev.data.chunkLength;
          if (total) setProgress(done / total);
        } else if (ev.event === "Finished") {
          setPhase("installing");
        }
      });
      await relaunch();
    } catch (e) {
      setPhase("error");
      setError(String(e));
    }
  }, [update]);

  useEffect(() => {
    if (!inTauri) return;
    getVersion().then(setVersion).catch(() => {});
    const first = setTimeout(() => checkNow(false), 4000);
    const every = setInterval(() => checkNow(false), SIX_HOURS);
    return () => {
      clearTimeout(first);
      clearInterval(every);
    };
  }, [checkNow]);

  return (
    <Ctx.Provider value={{ version, phase, update, progress, error, lastChecked, checkNow, install }}>{children}</Ctx.Provider>
  );
}

export const useUpdater = () => useContext(Ctx);
