import { useEffect, useState } from "react";
import { api, inTauri } from "../api";
import { GUIDE, pageLabel } from "../guide";
import { useNav, type Page } from "../nav";
import { useLive } from "../store";
import { Icon } from "./Icon";

// Per-viewer onboarding state (pages visited, intros dismissed). Browser
// storage is a convenience here: losing it only re-shows the hints.
const KEY = "niv.guide";
interface State {
  visited: Page[];
  dismissed: Page[];
  checklistHidden: boolean;
}
const EMPTY: State = { visited: [], dismissed: [], checklistHidden: false };

function read(): State {
  try {
    return { ...EMPTY, ...(JSON.parse(localStorage.getItem(KEY) ?? "{}") as Partial<State>) };
  } catch {
    return EMPTY;
  }
}

function write(s: State) {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* hints just show again next time */
  }
  window.dispatchEvent(new Event(KEY));
}

export function useGuide(): [State, (f: (s: State) => State) => void] {
  const [s, setS] = useState(read);
  useEffect(() => {
    const on = () => setS(read());
    window.addEventListener(KEY, on);
    return () => window.removeEventListener(KEY, on);
  }, []);
  return [s, (f) => write(f(read()))];
}

/** Remember which pages the user has opened (drives the checklist). */
export function useTrackVisit(page: Page) {
  useEffect(() => {
    const s = read();
    if (!s.visited.includes(page)) write({ ...s, visited: [...s.visited, page] });
  }, [page]);
}

/** "What is this page?" strip under the header; dismissible, reopened with the ? button. */
export function PageIntro({ page, open, onClose }: { page: Page; open: boolean; onClose: () => void }) {
  const nav = useNav();
  const g = GUIDE[page];
  if (!open || !g) return null;
  return (
    <div className="page-intro" role="note">
      <Icon name="info" size={16} />
      <div className="grow">
        <div className="intro-hint">{g.hint}</div>
        <ul className="intro-tasks">
          {g.tasks.map((t) => <li key={t}>{t}</li>)}
        </ul>
        <div className="intro-next small">
          <span className="muted">Next:</span>
          {g.next.map((p) => (
            <button key={p} className="linkish" onClick={() => nav.go(p)}>{pageLabel(p)} →</button>
          ))}
        </div>
      </div>
      <button className="btn sm ghost" onClick={onClose} title="Hide this guide (the ? button brings it back)">Got it</button>
    </div>
  );
}

interface Step {
  id: string;
  title: string;
  why: string;
  page: Page;
  done: boolean;
}

/** Overview checklist: the path through the app, ticked off as it's used. */
export function GettingStarted() {
  const nav = useNav();
  const { status } = useLive();
  const [g, setG] = useGuide();
  const [playbooks, setPlaybooks] = useState(0);
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    if (inTauri) api.getSettings().then((s) => setPlaybooks(s.playbooks.length)).catch(() => {});
  }, []);
  if (g.checklistHidden) return null;
  const seen = (p: Page) => g.visited.includes(p);
  const steps: Step[] = [
    { id: "listen", title: "Start listening", why: "Pick a network card (or a Wi-Fi card in monitor mode) and press Start capture.", page: "capture", done: !!status?.running || (status?.devices ?? 0) > 0 },
    { id: "devices", title: "Meet your devices", why: "Name the ones you recognise so alerts are easy to read.", page: "devices", done: seen("devices") },
    { id: "map", title: "See the network map", why: "Where traffic flows, and any threat addresses.", page: "map", done: seen("map") },
    { id: "alerts", title: "Review alerts", why: "Open each alert to see the traffic behind it and what to do.", page: "alerts", done: seen("alerts") && (status?.alerts.open ?? 0) === 0 },
    { id: "posture", title: "Check your security posture", why: "Weak services and known vulnerabilities on your devices.", page: "compliance", done: seen("compliance") },
    { id: "intel", title: "Load threat intelligence", why: "Lists of known-bad addresses and attack signatures.", page: "intel", done: seen("intel") },
    { id: "auto", title: "Automate a response", why: "Get notified or save evidence automatically when alerts fire.", page: "automation", done: playbooks > 0 },
  ];
  const done = steps.filter((s) => s.done).length;
  const nextStep = steps.find((s) => !s.done);
  return (
    <div className="card checklist">
      <div className="card-head">
        <h3>Getting started</h3>
        <span className="sub">{done} of {steps.length} done</span>
        <div className="right">
          <button className="btn sm ghost" onClick={() => setExpanded(!expanded)}>{expanded ? "Show next step only" : `Show all ${steps.length} steps`}</button>
          <button className="btn sm ghost" onClick={() => setG((s) => ({ ...s, checklistHidden: true }))} title="Hide (bring it back from ⌘K → Show getting started)">Hide</button>
        </div>
      </div>
      <div className="progress"><div style={{ width: `${(done / steps.length) * 100}%` }} /></div>
      <ol className="steps">
        {steps.map((s, i) => (expanded || s === nextStep) && (
          <li key={s.id} className={`${s.done ? "done" : ""} ${s === nextStep ? "current" : ""}`}>
            <span className="step-mark">{s.done ? <Icon name="check" size={12} /> : i + 1}</span>
            <div className="grow">
              <button className="linkish-plain step-title" onClick={() => nav.go(s.page)}>{s.title}</button>
              <div className="muted small">{s.why}</div>
            </div>
            {s === nextStep && <button className="btn sm primary" onClick={() => nav.go(s.page)}>Open {pageLabel(s.page)}</button>}
          </li>
        ))}
      </ol>
      {!nextStep && <div className="small muted">All done — you know your way around. Hide this checklist, or bring it back any time from ⌘K → “Show getting started checklist”.</div>}
    </div>
  );
}
