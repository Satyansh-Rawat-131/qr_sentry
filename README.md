# QRSentry — Malicious QR Code Detection with Machine Learning

> Scan or upload a QR code, or paste a link. QRSentry decodes it in your browser, runs three trained ML models on it, explains the decision with SHAP, shows how confident it is, and lets you see a **safe, simulated preview** of the page before you ever open it.

Everything (QR decoding, ML inference, SHAP, evaluation) runs **client-side in the browser**. Nothing is uploaded, and the suspicious URL is **never fetched**.

---

## Table of contents
1. [Features](#1-features)
2. [Quick start (run locally)](#2-quick-start-run-locally)
3. [All commands](#3-all-commands)
4. [Tech stack](#4-tech-stack)
5. [Project structure](#5-project-structure)
6. [How it works — end-to-end flow](#6-how-it-works--end-to-end-flow)
7. [Feature engineering (the 19 features)](#7-feature-engineering-the-19-features)
8. [Dataset & training pipeline](#8-dataset--training-pipeline)
9. [The three models & comparison](#9-the-three-models--comparison)
10. [Explainability (SHAP / TreeSHAP)](#10-explainability-shap--treeshap)
11. [Confidence analysis](#11-confidence-analysis)
12. [Continuous evaluation](#12-continuous-evaluation)
13. [Rule-based safety layer](#13-rule-based-safety-layer)
14. [Safe Preview sandbox](#14-safe-preview-sandbox)
15. [Testing](#15-testing)
16. [Security & privacy](#16-security--privacy)
17. [Limitations & future work](#17-limitations--future-work)
18. [Glossary](#18-glossary)
19. [Likely questions & answers (viva / interview prep)](#19-likely-questions--answers)

---

## 1. Features

| # | Feature | Where |
|---|---------|-------|
| 1 | QR decoding from image upload / drag-and-drop | `src/routes/index.tsx` (jsQR) |
| 2 | Live camera scanning | `src/routes/index.tsx` (`getUserMedia` + jsQR) |
| 3 | Paste-a-link check + sample links | `src/routes/index.tsx` |
| 4 | **Safe Preview sandbox** — simulated page, link anatomy, danger list | `src/components/SafePreview.tsx`, `src/lib/sandbox.ts` |
| 5 | **Real ML models** — XGBoost, Random Forest, Logistic Regression trained on 60k labelled URLs | `ml/train.py`, `src/ml/model.json`, `src/lib/ml.ts` |
| 6 | **Model comparison** — accuracy, precision, recall, F1, FPR, ROC-AUC table | `src/components/ModelLab.tsx` |
| 7 | **Explainability** — exact SHAP values per URL (TreeSHAP for trees, linear SHAP for LR) | `src/lib/ml.ts`, `ShapPanel` |
| 8 | **Confidence analysis** — confidence score + model agreement + forest vote spread | `confidenceOf()` in `src/lib/ml.ts` |
| 9 | **Continuous evaluation** — in-browser re-evaluation on held-out data + user-feedback metrics | `src/components/ModelLab.tsx`, `src/lib/feedback.ts` |
| 10 | Recent checks history, plain-language warning signs | `src/routes/index.tsx`, `src/lib/detector.ts` |

---

## 2. Quick start (run locally)

**Prerequisites**
- **Node.js 20+** (or **Bun 1.1+**, recommended — the project uses `bun.lock`)
- **Python 3.10+** — *only* if you want to retrain the models

```bash
# 1. Unzip and enter the project
unzip qrsentry.zip && cd qrsentry

# 2. Install dependencies (pick one)
bun install          # recommended
# npm install

# 3. Start the dev server
bun run dev          # or: npm run dev
# open the URL it prints (usually http://localhost:8080 or :5173)
```

Camera scanning needs `localhost` or HTTPS (browser rule for `getUserMedia`).

---

## 3. All commands

### App
| Command | What it does |
|---|---|
| `bun install` / `npm install` | Install JS dependencies |
| `bun run dev` / `npm run dev` | Start dev server with hot reload |
| `bun run build` / `npm run build` | Production build |
| `bun run preview` / `npm run preview` | Serve the production build locally |
| `bunx vitest run` / `npx vitest run` | Run all unit tests (16 tests) |
| `bunx vitest run src/test/ml.test.ts` | Run only the ML parity / metrics tests |
| `bunx tsc --noEmit` / `npx tsc --noEmit` | Type-check |
| `bun run lint` / `npm run lint` | Lint (ESLint) |

(Check `package.json → scripts` for the exact script names available.)

### Retraining the models (optional)
```bash
# 1. Python deps
python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install scikit-learn xgboost shap numpy

# 2. Download the dataset (≈22 MB, not committed to the repo)
curl -L -o ml/data.csv https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv

# 3. Train + export (writes src/ml/model.json, src/ml/holdout.json, src/test/ml-reference.json)
python ml/train.py ml/data.csv

# 4. Verify the browser implementation still matches Python exactly
bunx vitest run
```
Training takes ~1–2 minutes on a laptop.

---

## 4. Tech stack

| Layer | Technology |
|---|---|
| Framework | **TanStack Start v1** (React 19, file-based routing via TanStack Router, SSR) |
| Build tool | **Vite 7** |
| Language | **TypeScript** (strict, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`) |
| Styling | **Tailwind CSS v4** with semantic design tokens (oklch) in `src/styles.css` |
| UI primitives | shadcn/ui (Radix) components in `src/components/ui` |
| QR decoding | **jsQR** |
| ML training | **Python**: scikit-learn (LR, RF), **XGBoost**, **SHAP** (reference values) |
| ML inference | Hand-written TypeScript (`src/lib/ml.ts`) reading exported JSON models |
| Tests | **Vitest** + Testing Library (jsdom) |
| Deployment target | Edge runtime (Cloudflare Workers compatible) — but all ML is client-side |

---

## 5. Project structure

```text
qrsentry/
├── ml/
│   └── train.py                 # Feature extraction + training + export (Python)
├── src/
│   ├── ml/
│   │   ├── model.json           # Exported LR weights, RF trees, XGB trees, test metrics
│   │   └── holdout.json         # 3,000 labelled held-out URLs for in-browser evaluation
│   ├── lib/
│   │   ├── features.ts          # TS feature extraction (mirror of train.py featurize)
│   │   ├── ml.ts                # Inference, TreeSHAP, confidence, evaluation metrics
│   │   ├── detector.ts          # analyze(): ML + rule layer → Verdict
│   │   ├── sandbox.ts           # Safe Preview: URL dissection, findings, sandbox HTML
│   │   └── feedback.ts          # User feedback store (localStorage) for continuous eval
│   ├── components/
│   │   ├── SafePreview.tsx      # Sandbox modal
│   │   ├── ModelInsights.tsx    # Model picker, confidence panel, SHAP chart, feedback
│   │   ├── ModelLab.tsx         # Model comparison table + continuous evaluation
│   │   └── ui/                  # shadcn components
│   ├── routes/
│   │   ├── __root.tsx           # HTML shell, global head
│   │   └── index.tsx            # Main page (scan, results, lab)
│   ├── test/
│   │   ├── detector.test.ts     # Verdict rules
│   │   ├── sandbox.test.ts      # Safe Preview logic & escaping
│   │   ├── ml.test.ts           # Python↔TS parity, SHAP, metrics
│   │   └── ml-reference.json    # Reference predictions/SHAP from Python
│   └── styles.css               # Design system tokens
├── package.json
└── README.md                    # ← you are here
```

---

## 6. How it works — end-to-end flow

```text
QR image / camera frame / pasted text
        │
        ▼
 jsQR decode (canvas → pixels → payload string)
        │
        ▼
 detector.analyze(payload, model)
   ├─ rule signals (plain-language warning signs, hard safety rules)
   └─ ml.runAll(payload)
        ├─ features.featurize()  → 19-number vector x
        ├─ predict LR / RF / XGB → 3 probabilities
        └─ confidenceOf()        → confidence score
        │
        ▼
 Verdict { probability, label (safe/suspicious/malicious), probs, x, confidence, ... }
        │
        ▼
 UI: risk ring · confidence panel · SHAP chart · warning signs · Safe Preview · feedback
```

**Labels:** probability ≥ 0.60 → *malicious*, ≥ 0.30 → *suspicious*, else *safe*.
Plain text that isn't a URL is fixed at 3% (nothing to open).

---

## 7. Feature engineering (the 19 features)

Computed identically in `ml/train.py` (`featurize`) and `src/lib/features.ts`.

**Canonicalisation first:** strip a leading `http://`/`https://`, a leading `www.`, and a bare trailing `/`.
*Why:* in the dataset, legitimate URLs **never** have a scheme or `www.`, while some malicious ones do. Without this step, the model learned the shortcut "has https:// ⇒ malicious" (data leakage) and flagged `https://github.com`. Canonicalisation removes the shortcut.

URLs are parsed with a small hand-written parser (same in both languages) into **host, port, path**, so Python and JS never disagree.

| # | Key | Meaning |
|---|---|---|
| 1 | `len` | Total URL length |
| 2 | `ip` | Host is a raw IPv4 address |
| 3 | `at` | Contains `@` (userinfo trick) |
| 4 | `dots` | Number of dots in host (subdomain depth) |
| 5 | `dash` | Hyphens in host |
| 6 | `tld` | Suspicious TLD (`xyz, top, tk, zip, ru, …`) |
| 7 | `short` | Known link shortener (`bit.ly, tinyurl.com, …`) |
| 8 | `kw` | Count of phishing keywords (`login, verify, bank, paypal, …`), capped at 3 |
| 9 | `puny` | Punycode `xn--` (homograph / lookalike) |
| 10 | `ent` | Shannon entropy of host+path (randomness) |
| 11 | `dbl` | `//` inside the path (redirect trick) |
| 12 | `exe` | Ends in `.exe/.apk/.scr/.bat/.msi/.jar` |
| 13 | `js` | `javascript:`/`data:`/`vbscript:` scheme |
| 14 | `port` | Non-standard port |
| 15 | `digits` | Digits in host |
| 16 | `depth` | Number of `/` in path |
| 17 | `hlen` | Host length |
| 18 | `plen` | Path length |
| 19 | `spec` | Count of special characters `= & % _ ~` |

Shannon entropy: \(H = -\sum_c p_c \log_2 p_c\) over character frequencies.

---

## 8. Dataset & training pipeline

- **Source:** [faizann24 / Using-machine-learning-to-detect-malicious-URLs](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs) — ~420k URLs labelled `good` / `bad` (≈345k good, ≈76k bad).
- **Sampling:** deduplicated, then **30,000 per class** (balanced, 60,000 total), random seed 42.
- **Split:** 80/20 stratified → **48,000 train / 12,000 test**.
- **Export:** models are serialised to compact JSON:
  - LR → weights `w`, bias `b` (standardisation folded back into raw-scale weights)
  - Trees → arrays of nodes `[feature, threshold, left, right, leafValue, cover]`
  - Also exported: training feature means (for linear SHAP), test metrics, 3,000 held-out URLs, and reference predictions + SHAP values from the Python `shap` library for parity tests.
- **Why JSON + TS instead of a Python server?** Zero backend, works offline, private (URLs never leave the device), and deployable to edge hosting.

---

## 9. The three models & comparison

| Model | Hyper-parameters |
|---|---|
| Logistic Regression | standardised inputs, C = 1.0, max_iter 2000 |
| Random Forest | 40 trees, max_depth 10, min_samples_leaf 5 |
| XGBoost | 120 rounds, max_depth 4, learning_rate 0.15, subsample 0.9, colsample 0.9 |

**Results on the 12,000-URL test set** (threshold 0.5):

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| **XGBoost** | **80.7%** | **83.2%** | **77.0%** | **80.0%** | 15.6% | **89.5%** |
| Random Forest | 78.7% | 82.9% | 72.4% | 77.3% | **14.9%** | 87.4% |
| Logistic Regression | 70.9% | 78.0% | 58.3% | 66.7% | 16.4% | 79.1% |

**Interpretation**
- XGBoost wins on most metrics — gradient boosting captures non-linear feature interactions (e.g. "long path **and** suspicious TLD").
- Random Forest has the lowest false-positive rate (fewest safe sites wrongly blocked).
- Logistic Regression is a linear baseline; it can't model interactions, so recall is much lower.
- Default model in the UI is **XGBoost**; users can switch models live.

**Metric definitions**
- Precision \(= \frac{TP}{TP+FP}\) — of links flagged malicious, how many really were.
- Recall \(= \frac{TP}{TP+FN}\) — of truly malicious links, how many we caught.
- F1 \(= \frac{2PR}{P+R}\) — harmonic mean of precision & recall.
- FPR \(= \frac{FP}{FP+TN}\) — share of safe links wrongly flagged.
- ROC-AUC — probability a random malicious URL scores higher than a random safe one.

---

## 10. Explainability (SHAP / TreeSHAP)

**SHAP** (SHapley Additive exPlanations) assigns each feature a contribution \(\phi_i\) such that
\[ f(x) = \phi_0 + \sum_i \phi_i \]
where \(\phi_0\) is the model's average output (baseline). Positive \(\phi_i\) → pushes toward malicious; negative → toward safe.

- **Trees (RF, XGBoost):** we implemented the exact **path-dependent TreeSHAP** algorithm (Lundberg et al., 2018) in TypeScript (`treeShap()` in `src/lib/ml.ts`, using the `extend`/`unwind` path-weight recursion and node cover counts).
  - RF explained in **probability** space; XGBoost in **log-odds** space (same as the `shap` library).
- **Logistic Regression:** linear SHAP, \(\phi_i = w_i (x_i - \mathbb{E}[x_i])\), in log-odds.
- **Correctness:** `src/test/ml.test.ts` checks our SHAP values against the official Python `shap.TreeExplainer` output to 3 decimal places, and checks the additivity property (baseline + Σφ = prediction).
- UI shows the top 8 features by |φ| as a diverging bar chart.

---

## 11. Confidence analysis

Probability alone ≠ confidence. `confidenceOf()` combines three signals:

| Signal | Weight | Meaning |
|---|---|---|
| Margin \(= |p - 0.5| \times 2\) | 60% | Distance from the decision line |
| Model agreement | 25% | How many of the 3 models give the same verdict |
| Forest vote spread | 15% | Std-dev of the 40 RF trees' outputs (low spread = consensus) |

Score → **high** (≥70%), **medium** (≥40%), **low**. The panel also shows each model's probability side-by-side, and notes when a hard safety rule overrode the model.

---

## 12. Continuous evaluation

Two independent ways to track precision, recall, F1 and false-positive rate:

1. **Re-test in your browser** — "Run evaluation" scores the selected model against **3,000 held-out labelled URLs** the model never saw in training, entirely in the browser (~70 ms). It reproduces the training-time numbers, proving the shipped model works as trained.
2. **From your feedback** — after each check, the user can mark the link as actually *Safe* or *Malicious*. Each label (with all 3 models' predictions) is stored in `localStorage`; a live confusion matrix (TP/FP/TN/FN) and metrics are computed per model. This measures real-world performance and would detect **model drift** over time. "Reset" clears it.

---

## 13. Rule-based safety layer

`src/lib/detector.ts` also keeps 15 human-readable rule signals (shown as "Plain-language warning signs"). They:
- explain the link to non-technical users, and
- act as **hard overrides**: for `javascript:`/`data:` URIs or executable downloads — patterns rare in training data — the risk is raised to at least 95% if the rules score higher than the model.

This is a **hybrid** design: ML for generalisation, rules for known critical patterns.

---

## 14. Safe Preview sandbox

Instead of only saying "dangerous", QRSentry shows **what the page would likely look like and why it's dangerous — without loading it**.

- `predictPage()` guesses the page type from the URL: fake **login**, forced **download**, hidden **redirect** (shortener), **script** URI, or generic.
- `buildPreviewDoc()` renders a mock page (e.g. fake "Verify your identity" form) with numbered red annotations ("Captured in plain text", "Sent to <real owner>").
- `dissect()` splits the URL into scheme / userinfo / subdomain / domain / port / path / query and flags dangerous parts; `realOwner()` shows the actual registrable domain; `impersonates()` detects brand names used outside their real domain.
- **Isolation:** the mock is rendered in `<iframe sandbox="" srcdoc=…>` (no scripts, forms, same-origin, popups), plus a CSP `default-src 'none'`, and **every** piece of URL text is HTML-escaped. The real URL is never requested.
- "Open anyway" requires two deliberate clicks and uses `rel="noopener noreferrer nofollow"`.

---

## 15. Testing

```bash
bunx vitest run
```
16 tests across 4 files:
- `detector.test.ts` — Wikipedia is safe; IP-hosted PayPal login is malicious; `javascript:` is malicious.
- `sandbox.test.ts` — real-owner extraction, fake-login prediction, brand impersonation, HTML escaping & CSP.
- `ml.test.ts` — **feature parity** with Python, **prediction parity** for all 3 models, **SHAP parity** with the `shap` library, SHAP additivity, metric formulas, and in-browser holdout F1 within 3% of training.
- `app-routing.test.tsx` — the app renders.

---

## 16. Security & privacy

- No backend, no database, no uploads — QR images are decoded on a `<canvas>` locally.
- Suspicious URLs are never fetched (not even by the Safe Preview).
- Sandbox iframe: empty `sandbox` attribute + strict CSP + escaped content → no XSS from crafted QR payloads.
- Feedback data lives only in the user's own browser (`localStorage`).

---

## 17. Limitations & future work

- **Lexical-only features**: the model sees only the URL text — no WHOIS/domain age, SSL certificate, page content or reputation feeds. That caps accuracy around 80%.
- **Dataset age/bias**: the dataset is older and its legit URLs have no scheme (handled via canonicalisation).
- **Brand impersonation list** is fixed.
- Future: add domain-age / certificate / threat-intel lookups via a server function, character-level CNN/transformer models, threshold tuning per use-case, calibrated probabilities (Platt/isotonic), and syncing feedback to a database for global drift monitoring & periodic retraining.

---

## 18. Glossary

- **Phishing** — fake site that tricks users into giving credentials.
- **Quishing** — phishing delivered via QR code.
- **Punycode / homograph attack** — `xn--` domains that look like real brands using lookalike Unicode letters.
- **TP / FP / TN / FN** — true/false positives/negatives (positive = malicious).
- **Log-odds** — \(\ln\frac{p}{1-p}\); XGBoost and LR add contributions in this space, then apply sigmoid.
- **Cover** — number (or hessian weight) of training samples reaching a tree node; used by TreeSHAP.
- **Data leakage** — a feature that reveals the label for the wrong reason (here: the `https://` prefix).
- **Model drift** — performance degrading as real-world data changes.

---

## 19. Likely questions & answers

**Q: Why three models?** To compare a linear baseline (LR), a bagging ensemble (RF) and a boosting ensemble (XGBoost). XGBoost performed best (F1 80.0%, AUC 89.5%).

**Q: Why does XGBoost beat Random Forest?** Boosting builds trees sequentially, each correcting the previous one's errors, which reduces bias; RF averages independent deep trees, reducing variance. On these tabular features the bias reduction helps more.

**Q: How do you run Python models in the browser?** We don't run Python. After training we export the learned parameters (weights / tree nodes) to JSON and wrote a small TypeScript evaluator. Tests guarantee its outputs match sklearn/XGBoost to 3 decimals.

**Q: How is SHAP computed without the Python library?** We implemented the exact TreeSHAP algorithm in TypeScript and verified it against `shap.TreeExplainer`.

**Q: What is the difference between probability and confidence?** Probability is the model's malicious score. Confidence measures how *trustworthy* that score is: distance from 0.5, agreement among models, and agreement among forest trees.

**Q: Why balance the dataset?** The raw data is ~82% good; without balancing, a model could get high accuracy by predicting "good" for everything while missing attacks.

**Q: Why is FPR important?** A high false-positive rate means blocking legitimate links, which makes users ignore warnings.

**Q: What data leakage did you find?** Legit URLs in the dataset never start with `http(s)://` or `www.`. The model learned that shortcut, so we canonicalise URLs (strip those prefixes) in both training and inference.

**Q: Is the Safe Preview really safe?** Yes — it never contacts the URL. It's a locally generated mock rendered in a fully sandboxed iframe with CSP and escaped text.

**Q: How would you deploy continuous learning?** Store feedback server-side, monitor metrics over time for drift, and periodically retrain with `ml/train.py` on fresh labelled data, re-running parity tests before shipping the new JSON.

**Q: Why the hybrid rules + ML?** Some attacks (`javascript:` URIs, `.apk` downloads) are rare in training data; deterministic rules guarantee they're always caught.

**Q: What's the threshold?** 0.5 for metrics; in the UI ≥0.6 is "malicious" and 0.3–0.6 "suspicious" to give a cautionary middle band.
