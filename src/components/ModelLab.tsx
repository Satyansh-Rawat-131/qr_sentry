import { useState } from "react";
import { evaluate, MODEL_IDS, MODEL_NAMES, scoreConfusion, TRAINED_METRICS, TRAINED_ON, type Confusion, type ModelId } from "@/lib/ml";
import { clearFeedback, confusionFrom, useFeedback } from "@/lib/feedback";

const f = (v: number) => (v * 100).toFixed(1) + "%";
const COLS = [
  ["accuracy", "Accuracy", true], ["precision", "Precision", true], ["recall", "Recall", true],
  ["f1", "F1", true], ["fpr", "False-pos. rate", false], ["auc", "ROC AUC", true],
] as const;

export function ModelComparison() {
  const best = (k: (typeof COLS)[number][0], hi: boolean) =>
    MODEL_IDS.reduce((a, b) => ((hi ? TRAINED_METRICS[b][k] > TRAINED_METRICS[a][k] : TRAINED_METRICS[b][k] < TRAINED_METRICS[a][k]) ? b : a));
  return (
    <div className="glass p-6 md:p-8">
      <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Model comparison</p>
      <h2 className="font-serif text-3xl">Three models, one test set</h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Trained on {TRAINED_ON.rows.toLocaleString()} labelled URLs, scored on {TRAINED_ON.test.toLocaleString()} held-out ones. Best in each column is highlighted.
      </p>
      <div className="mt-5 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-normal">Model</th>
              {COLS.map(([, l]) => <th key={l} className="py-2 pr-4 font-normal">{l}</th>)}
            </tr>
          </thead>
          <tbody>
            {MODEL_IDS.map((id) => (
              <tr key={id} className="border-b last:border-0">
                <td className="py-2.5 pr-4 font-serif text-lg">{MODEL_NAMES[id]}</td>
                {COLS.map(([k, , hi]) => (
                  <td key={k} className={`py-2.5 pr-4 font-mono text-xs ${best(k, hi) === id ? "text-accent" : ""}`}>{f(TRAINED_METRICS[id][k])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MetricRow({ c }: { c: Confusion }) {
  const s = scoreConfusion(c);
  return (
    <div className="grid grid-cols-4 gap-2">
      {([["Precision", s.precision], ["Recall", s.recall], ["F1", s.f1], ["FPR", s.fpr]] as const).map(([l, v]) => (
        <div key={l} className="rounded-xl border px-2 py-2 text-center">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{l}</p>
          <p className="font-mono text-sm">{s.total ? f(v) : "—"}</p>
        </div>
      ))}
    </div>
  );
}

export function ContinuousEvaluation() {
  const feedback = useFeedback();
  const [model, setModel] = useState<ModelId>("xgb");
  const [live, setLive] = useState<{ c: Confusion; n: number; ms: number } | null>(null);
  const [busy, setBusy] = useState(false);

  const runHoldout = async () => {
    setBusy(true);
    const rows = (await import("@/ml/holdout.json")).default as { u: string; y: number }[];
    const t = performance.now();
    const c = evaluate(model, rows);
    setLive({ c, n: rows.length, ms: performance.now() - t });
    setBusy(false);
  };
  const fc = confusionFrom(feedback, model);

  return (
    <div className="glass p-6 md:p-8">
      <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Continuous evaluation</p>
      <h2 className="font-serif text-3xl">Is it still accurate?</h2>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {MODEL_IDS.map((id) => (
          <button key={id} onClick={() => { setModel(id); setLive(null); }} className={`chip px-3 py-1 text-[11px] ${model === id ? "border-accent text-foreground" : "text-muted-foreground"}`}>{MODEL_NAMES[id]}</button>
        ))}
      </div>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between">
          <p className="text-sm">Re-test in your browser</p>
          <button onClick={runHoldout} disabled={busy} className="btn-glow px-4 py-1.5 text-xs font-medium disabled:opacity-50">{busy ? "Running…" : "Run evaluation"}</button>
        </div>
        {live ? (
          <>
            <MetricRow c={live.c} />
            <p className="mt-1.5 text-[11px] text-muted-foreground">{live.n.toLocaleString()} held-out URLs · {Math.round(live.ms)} ms · TP {live.c.tp} · FP {live.c.fp} · TN {live.c.tn} · FN {live.c.fn}</p>
          </>
        ) : <p className="text-xs text-muted-foreground">Scores the shipped model against held-out labelled URLs it never saw in training.</p>}
      </div>

      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <p className="text-sm">From your feedback <span className="text-muted-foreground">({feedback.length} labelled)</span></p>
          {feedback.length > 0 && <button onClick={clearFeedback} className="chip px-3 py-1 text-[11px] text-muted-foreground">Reset</button>}
        </div>
        <MetricRow c={fc} />
        <p className="mt-1.5 text-[11px] text-muted-foreground">
          {feedback.length ? `TP ${fc.tp} · FP ${fc.fp} · TN ${fc.tn} · FN ${fc.fn} — saved in this browser.` : "Check a link, then mark it Safe or Malicious to start tracking real-world accuracy."}
        </p>
      </div>
    </div>
  );
}
