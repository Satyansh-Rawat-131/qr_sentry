// Continuous evaluation: users confirm / correct verdicts; we keep a running
// confusion matrix per model (in this browser) and snapshots over time.
import { useEffect, useState } from "react";
import type { Confusion, ModelId } from "./ml";

export type FeedbackEntry = { payload: string; truth: 0 | 1; probs: Record<ModelId, number>; at: number };
const KEY = "qrsentry.feedback.v1";
const EVENT = "qrsentry-feedback";

export function loadFeedback(): FeedbackEntry[] {
  if (typeof window === "undefined") return [];
  try { return JSON.parse(localStorage.getItem(KEY) ?? "[]") as FeedbackEntry[]; } catch { return []; }
}

export function addFeedback(e: FeedbackEntry) {
  const all = [...loadFeedback().filter((x) => x.payload !== e.payload), e].slice(-500);
  localStorage.setItem(KEY, JSON.stringify(all));
  window.dispatchEvent(new Event(EVENT));
}

export function clearFeedback() {
  localStorage.removeItem(KEY);
  window.dispatchEvent(new Event(EVENT));
}

export function confusionFrom(entries: FeedbackEntry[], id: ModelId): Confusion {
  const c: Confusion = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const e of entries) {
    const pred = e.probs[id] >= 0.5;
    if (pred && e.truth) c.tp++; else if (pred) c.fp++; else if (e.truth) c.fn++; else c.tn++;
  }
  return c;
}

export function useFeedback() {
  const [list, setList] = useState<FeedbackEntry[]>([]);
  useEffect(() => {
    const sync = () => setList(loadFeedback());
    sync();
    window.addEventListener(EVENT, sync);
    window.addEventListener("storage", sync);
    return () => { window.removeEventListener(EVENT, sync); window.removeEventListener("storage", sync); };
  }, []);
  return list;
}
