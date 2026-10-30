// In-browser inference + explainability for the models trained by ml/train.py.
import model from "@/ml/model.json";
import { featurize } from "./features";

// Node: [feature, threshold, left, right, leafValue, cover]
type Node = [number, number, number, number, number, number];
type Tree = Node[];

export type ModelId = "logreg" | "rf" | "xgb";
export const MODEL_NAMES: Record<ModelId, string> = { logreg: "Logistic Regression", rf: "Random Forest", xgb: "XGBoost" };
export const MODEL_IDS: ModelId[] = ["xgb", "rf", "logreg"];
export type Metrics = { accuracy: number; precision: number; recall: number; f1: number; fpr: number; auc: number; tp: number; fp: number; tn: number; fn: number };

const M = model as unknown as {
  features: { key: string; label: string }[];
  mean: number[];
  logreg: { w: number[]; b: number };
  rf: { trees: Tree[]; leq: boolean };
  xgb: { trees: Tree[]; base: number; leq: boolean };
  metrics: Record<ModelId, Metrics>;
  trainedOn: { rows: number; test: number; source: string };
};

export const FEATURES = M.features;
export const TRAINED_METRICS = M.metrics;
export const TRAINED_ON = M.trainedOn;

const sigmoid = (z: number) => 1 / (1 + Math.exp(-z));
const goLeft = (x: number, t: number, leq: boolean) => (leq ? x <= t : x < t);

function treeValue(tree: Tree, x: number[], leq: boolean) {
  let i = 0;
  for (;;) {
    const n = tree[i]!;
    if (n[0] < 0) return n[4];
    i = goLeft(x[n[0]]!, n[1], leq) ? n[2] : n[3];
  }
}

export function predictX(id: ModelId, x: number[]): number {
  if (id === "logreg") return sigmoid(M.logreg.b + x.reduce((s, v, i) => s + v * M.logreg.w[i]!, 0));
  if (id === "rf") return M.rf.trees.reduce((s, t) => s + treeValue(t, x, true), 0) / M.rf.trees.length;
  return sigmoid(M.xgb.base + M.xgb.trees.reduce((s, t) => s + treeValue(t, x, false), 0));
}

/** Per-tree votes of the forest — used for confidence spread. */
export function rfVotes(x: number[]) {
  return M.rf.trees.map((t) => treeValue(t, x, true));
}

// ---------- TreeSHAP (Lundberg et al. 2018, path-dependent algorithm) ----------
type PathEl = { d: number; z: number; o: number; w: number };

function extend(m: PathEl[], pz: number, po: number, pi: number): PathEl[] {
  const l = m.length;
  const out = m.map((e) => ({ ...e }));
  out.push({ d: pi, z: pz, o: po, w: l === 0 ? 1 : 0 });
  for (let i = l - 1; i >= 0; i--) {
    out[i + 1]!.w += (po * out[i]!.w * (i + 1)) / (l + 1);
    out[i]!.w = (pz * out[i]!.w * (l - i)) / (l + 1);
  }
  return out;
}

function unwind(m: PathEl[], i: number): PathEl[] {
  const l = m.length - 1;
  const out = m.map((e) => ({ ...e }));
  let n = out[l]!.w;
  const { o, z } = out[i]!;
  for (let j = l - 1; j >= 0; j--) {
    if (o !== 0) {
      const t = out[j]!.w;
      out[j]!.w = (n * (l + 1)) / ((j + 1) * o);
      n = t - (out[j]!.w * z * (l - j)) / (l + 1);
    } else {
      out[j]!.w = (out[j]!.w * (l + 1)) / (z * (l - j));
    }
  }
  for (let j = i; j < l; j++) { out[j]!.d = out[j + 1]!.d; out[j]!.z = out[j + 1]!.z; out[j]!.o = out[j + 1]!.o; }
  return out.slice(0, l);
}

function treeShap(tree: Tree, x: number[], leq: boolean, phi: number[]) {
  const recurse = (j: number, m: PathEl[], pz: number, po: number, pi: number) => {
    m = extend(m, pz, po, pi);
    const n = tree[j]!;
    if (n[0] < 0) {
      for (let i = 1; i < m.length; i++) {
        const w = unwind(m, i).reduce((s, e) => s + e.w, 0);
        phi[m[i]!.d]! += w * (m[i]!.o - m[i]!.z) * n[4];
      }
      return;
    }
    const [f, t, L, R] = n;
    const [hot, cold] = goLeft(x[f]!, t, leq) ? [L, R] : [R, L];
    let iz = 1, io = 1;
    const k = m.findIndex((e, idx) => idx > 0 && e.d === f);
    if (k !== -1) { iz = m[k]!.z; io = m[k]!.o; m = unwind(m, k); }
    recurse(hot, m, (iz * tree[hot]![5]) / n[5], io, f);
    recurse(cold, m, (iz * tree[cold]![5]) / n[5], 0, f);
  };
  recurse(0, [], 1, 1, -1);
}

function expectedTree(tree: Tree) {
  let s = 0;
  for (const n of tree) if (n[0] < 0) s += n[4] * n[5];
  return s / tree[0]![5];
}

export type Explanation = { base: number; values: number[]; space: "probability" | "log-odds" };

/** SHAP values: contribution of each feature, summing (with base) to the model output. */
export function explainX(id: ModelId, x: number[]): Explanation {
  const nf = FEATURES.length;
  if (id === "logreg") {
    const values = x.map((v, i) => M.logreg.w[i]! * (v - M.mean[i]!));
    const base = M.logreg.b + M.mean.reduce((s, v, i) => s + v * M.logreg.w[i]!, 0);
    return { base, values, space: "log-odds" };
  }
  const phi = new Array<number>(nf).fill(0);
  if (id === "rf") {
    for (const t of M.rf.trees) treeShap(t, x, true, phi);
    const k = M.rf.trees.length;
    return { base: M.rf.trees.reduce((s, t) => s + expectedTree(t), 0) / k, values: phi.map((v) => v / k), space: "probability" };
  }
  for (const t of M.xgb.trees) treeShap(t, x, false, phi);
  return { base: M.xgb.base + M.xgb.trees.reduce((s, t) => s + expectedTree(t), 0), values: phi, space: "log-odds" };
}

// ---------- Confidence ----------
export type Confidence = { score: number; level: "high" | "medium" | "low"; agreement: number; spread: number; reasons: string[] };

export function confidenceOf(probs: Record<ModelId, number>, selected: ModelId, x: number[]): Confidence {
  const p = probs[selected];
  const margin = Math.abs(p - 0.5) * 2; // 0 = coin flip, 1 = certain
  const verdict = p >= 0.5;
  const agreement = MODEL_IDS.filter((id) => (probs[id] >= 0.5) === verdict).length;
  const votes = rfVotes(x);
  const mean = votes.reduce((a, b) => a + b, 0) / votes.length;
  const spread = Math.sqrt(votes.reduce((s, v) => s + (v - mean) ** 2, 0) / votes.length);
  const score = Math.max(0, Math.min(1, 0.6 * margin + 0.25 * ((agreement - 1) / 2) + 0.15 * (1 - Math.min(spread / 0.5, 1))));
  const reasons = [
    `${Math.round(margin * 100)}% away from the 50/50 decision line`,
    `${agreement} of 3 models agree`,
    `Forest trees ${spread < 0.15 ? "mostly agree" : spread < 0.3 ? "partly disagree" : "strongly disagree"} (spread ${spread.toFixed(2)})`,
  ];
  return { score, level: score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low", agreement, spread, reasons };
}

export type MlResult = { x: number[]; probs: Record<ModelId, number> };
export function runAll(payload: string): MlResult {
  const x = featurize(payload);
  return { x, probs: { logreg: predictX("logreg", x), rf: predictX("rf", x), xgb: predictX("xgb", x) } };
}

// ---------- Evaluation ----------
export type Confusion = { tp: number; fp: number; tn: number; fn: number };
export function scoreConfusion(c: Confusion) {
  const div = (a: number, b: number) => (b === 0 ? 0 : a / b);
  const precision = div(c.tp, c.tp + c.fp);
  const recall = div(c.tp, c.tp + c.fn);
  return {
    precision, recall,
    f1: div(2 * precision * recall, precision + recall),
    fpr: div(c.fp, c.fp + c.tn),
    accuracy: div(c.tp + c.tn, c.tp + c.tn + c.fp + c.fn),
    total: c.tp + c.tn + c.fp + c.fn,
  };
}

export function evaluate(id: ModelId, rows: { u: string; y: number }[]): Confusion {
  const c: Confusion = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const r of rows) {
    const pred = predictX(id, featurize(r.u)) >= 0.5 ? 1 : 0;
    if (pred && r.y) c.tp++; else if (pred) c.fp++; else if (r.y) c.fn++; else c.tn++;
  }
  return c;
}
