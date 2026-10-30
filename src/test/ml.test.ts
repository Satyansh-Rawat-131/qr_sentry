import { describe, expect, it } from "vitest";
import ref from "./ml-reference.json";
import holdout from "@/ml/holdout.json";
import { featurize } from "@/lib/features";
import { evaluate, explainX, predictX, scoreConfusion, TRAINED_METRICS, type ModelId } from "@/lib/ml";

const sig = (z: number) => 1 / (1 + Math.exp(-z));

describe("trained models (parity with Python)", () => {
  it("extracts identical features", () => {
    ref.urls.forEach((u, i) => expect(featurize(u)).toEqual(ref.x[i]));
  });
  (["logreg", "rf", "xgb"] as ModelId[]).forEach((id) =>
    it(`${id} predictions match sklearn/xgboost`, () => {
      ref.x.forEach((x, i) => expect(predictX(id, x)).toBeCloseTo(ref.p[id][i]!, 3));
    }),
  );
  it("TreeSHAP matches the shap library", () => {
    for (const id of ["rf", "xgb"] as const) {
      ref.x.forEach((x, i) => {
        const e = explainX(id, x);
        e.values.forEach((v, j) => expect(v).toBeCloseTo(ref.shap[id][i]![j]!, 3));
      });
    }
  });
  it("SHAP values add up to the model output", () => {
    for (const id of ["logreg", "rf", "xgb"] as ModelId[]) {
      const x = ref.x[0]!;
      const e = explainX(id, x);
      const total = e.base + e.values.reduce((a, b) => a + b, 0);
      expect(e.space === "probability" ? total : sig(total)).toBeCloseTo(predictX(id, x), 4);
    }
  });
});

describe("evaluation metrics", () => {
  it("computes precision, recall, F1 and false-positive rate", () => {
    const s = scoreConfusion({ tp: 8, fp: 2, tn: 18, fn: 2 });
    expect(s.precision).toBeCloseTo(0.8);
    expect(s.recall).toBeCloseTo(0.8);
    expect(s.f1).toBeCloseTo(0.8);
    expect(s.fpr).toBeCloseTo(0.1);
  });
  it("in-browser evaluation reproduces the training-time test metrics", () => {
    const c = evaluate("xgb", holdout);
    const s = scoreConfusion(c);
    expect(Math.abs(s.f1 - TRAINED_METRICS.xgb.f1)).toBeLessThan(0.03);
  });
});
