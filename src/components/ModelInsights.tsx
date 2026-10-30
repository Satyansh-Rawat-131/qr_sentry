import { useMemo } from "react";
import type { Verdict } from "@/lib/detector";
import { explainX, FEATURES, MODEL_IDS, MODEL_NAMES, type ModelId } from "@/lib/ml";
import { addFeedback, useFeedback } from "@/lib/feedback";

const pct = (v: number) => `${Math.round(v * 100)}%`;

export function ModelPicker({ value, onChange }: { value: ModelId; onChange: (m: ModelId) => void }) {
  return (
    <div role="radiogroup" aria-label="Model" className="flex flex-wrap gap-1.5">
      {MODEL_IDS.map((id) => (
        <button key={id} role="radio" aria-checked={value === id} onClick={() => onChange(id)}
          className={`chip px-3 py-1 text-[11px] ${value === id ? "border-accent text-foreground" : "text-muted-foreground"}`}>
          {MODEL_NAMES[id]}
        </button>
      ))}
    </div>
  );
}

export function ConfidencePanel({ v }: { v: Verdict }) {
  const c = v.confidence;
  const tone = c.level === "high" ? "text-ok" : c.level === "medium" ? "text-warn" : "text-destructive";
  return (
    <div className="mt-6 rounded-2xl border p-4">
      <div className="flex items-baseline justify-between">
        <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Model confidence</p>
        <p className={`font-serif text-2xl ${tone}`}>{pct(c.score)} <span className="text-sm">· {c.level}</span></p>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-border">
        <div className="h-full rounded-full bg-gradient-to-r from-accent to-accent-2 transition-all duration-700" style={{ width: pct(c.score) }} />
      </div>
      <ul className="mt-3 space-y-0.5 text-xs text-muted-foreground">
        {c.reasons.map((r) => <li key={r}>· {r}</li>)}
        {v.ruleOverride && <li className="text-destructive">· A hard safety rule raised the risk above the model's estimate</li>}
      </ul>
      <div className="mt-3 grid grid-cols-3 gap-2">
        {MODEL_IDS.map((id) => (
          <div key={id} className={`rounded-xl border px-2 py-1.5 text-center ${id === v.model ? "border-accent" : ""}`}>
            <p className="truncate text-[10px] text-muted-foreground">{MODEL_NAMES[id]}</p>
            <p className={`font-mono text-sm ${v.probs[id] >= 0.5 ? "text-destructive" : "text-ok"}`}>{pct(v.probs[id])}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ShapPanel({ v }: { v: Verdict }) {
  const e = useMemo(() => explainX(v.model, v.x), [v]);
  const rows = FEATURES.map((f, i) => ({ ...f, raw: v.x[i]!, s: e.values[i]! }))
    .sort((a, b) => Math.abs(b.s) - Math.abs(a.s)).slice(0, 8);
  const max = Math.max(...rows.map((r) => Math.abs(r.s)), 1e-6);
  const unit = e.space === "probability" ? "prob." : "log-odds";
  return (
    <div className="mt-6">
      <h3 className="font-serif text-2xl">Why the model decided this</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        SHAP values for {MODEL_NAMES[v.model]} ({unit}). Red pushes toward malicious, green toward safe. Baseline {e.space === "probability" ? pct(e.base) : e.base.toFixed(2)}.
      </p>
      <ul className="mt-3 space-y-1.5">
        {rows.map((r) => (
          <li key={r.key} className="grid grid-cols-[1fr_1fr_3.5rem] items-center gap-3 text-xs">
            <span className="truncate">{r.label} <span className="font-mono text-muted-foreground">= {Number.isInteger(r.raw) ? r.raw : r.raw.toFixed(2)}</span></span>
            <span className="relative h-4">
              <span className="absolute inset-y-0 left-1/2 w-px bg-border" />
              <span className={`absolute inset-y-0.5 rounded-sm ${r.s >= 0 ? "left-1/2 bg-destructive" : "right-1/2 bg-ok"}`} style={{ width: `${(Math.abs(r.s) / max) * 50}%` }} />
            </span>
            <span className={`text-right font-mono text-[10px] ${r.s >= 0 ? "text-destructive" : "text-ok"}`}>{r.s >= 0 ? "+" : ""}{r.s.toFixed(3)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function FeedbackButtons({ v }: { v: Verdict }) {
  const list = useFeedback();
  const given = list.find((x) => x.payload === v.payload);
  const send = (truth: 0 | 1) => addFeedback({ payload: v.payload, truth, probs: v.probs, at: Date.now() });
  return (
    <div className="mt-6 flex flex-wrap items-center gap-2 text-xs">
      <span className="text-muted-foreground">Help evaluate the model — this link is actually:</span>
      <button onClick={() => send(0)} className={`chip px-3 py-1 ${given?.truth === 0 ? "border-ok text-ok" : "text-muted-foreground"}`}>Safe</button>
      <button onClick={() => send(1)} className={`chip px-3 py-1 ${given?.truth === 1 ? "border-destructive text-destructive" : "text-muted-foreground"}`}>Malicious</button>
      {given && <span className="text-muted-foreground">Recorded ✓</span>}
    </div>
  );
}
