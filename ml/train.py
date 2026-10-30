"""
QRSentry model training.

Trains Logistic Regression, Random Forest and XGBoost on labelled URLs and
exports them (plus metrics and a holdout set) to src/ml/*.json so the browser
can run inference + TreeSHAP without any server.

Usage:
  pip install scikit-learn xgboost shap
  curl -L -o ml/data.csv https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv
  python ml/train.py [path/to/data.csv]   # data.csv is not committed (too large)
"""
import csv, json, math, random, re, sys
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, roc_auc_score, confusion_matrix
import xgboost as xgb

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "ml"
SEED = 42
PER_CLASS = 30000

# ---- Feature extraction: MUST stay identical to src/lib/features.ts ----
SUSPICIOUS_TLDS = {"zip","mov","xyz","top","tk","ml","ga","cf","gq","click","country","work","loan","ru","cn"}
SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy"}
KEYWORDS = ["login","verify","update","secure","account","bank","paypal","signin","wallet","confirm","password","free","gift","bonus","invoice"]
FEATURES = [
  ("len", "URL length"), ("ip", "Host is raw IP address"), ("at", "Contains '@' symbol"),
("dots", "Dots in hostname"), ("dash", "Hyphens in hostname"),
  ("tld", "Suspicious top-level domain"), ("short", "Link shortener"), ("kw", "Phishing keywords"),
  ("puny", "Punycode / lookalike domain"), ("ent", "Character randomness (entropy)"), ("dbl", "'//' redirect in path"),
  ("exe", "Executable / APK download"), ("js", "Script / data URI scheme"), ("port", "Non-standard port"),
  ("digits", "Digits in hostname"), ("depth", "Path depth"),
  ("hlen", "Hostname length"), ("plen", "Path length"), ("spec", "Special characters (=&%_~)"),
]
SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*:", re.I)
EXE = re.compile(r"\.(exe|apk|scr|bat|msi|jar)(\?|$)")
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def parse(p):
    m = SCHEME.match(p)
    rest = p
    if m:
        if p[m.end():m.end()+2] != "//":
            return "", "", ""
        rest = p[m.end()+2:]
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1 and i < cut: cut = i
    auth, tail = rest[:cut], rest[cut:]
    path = ""
    if tail.startswith("/"):
        e = len(tail)
        for ch in "?#":
            i = tail.find(ch)
            if i != -1 and i < e: e = i
        path = tail[:e]
    at = auth.rfind("@")
    if at != -1: auth = auth[at+1:]
    port = ""
    c = auth.rfind(":")
    if c != -1 and auth[c+1:].isdigit() and auth[c+1:].isascii():
        port = auth[c+1:]; auth = auth[:c]
    return auth.lower(), port, path

def entropy(s):
    if not s: return 0.0
    counts = {}
    for ch in s: counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in counts.values())

def canonical(raw):
    # The dataset's legit URLs never carry a scheme or "www." while some
    # malicious ones do; strip both so the model can't learn that shortcut.
    p = raw.strip()
    p = re.sub(r"^https?://", "", p, flags=re.I)
    p = re.sub(r"^www\\.", "", p, flags=re.I)
    if p.endswith("/") and p.count("/") == 1: p = p[:-1]
    return p

def featurize(raw):
    p = canonical(raw)
    l = p.lower()
    host, port, path = parse(p)
    h = host[4:] if host.startswith("www.") else host
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    return [
        len(p),
        1 if IP.match(host) else 0,
        1 if ("@" in l and not l.startswith("mailto:")) else 0,
        host.count("."),
        host.count("-"),
        1 if tld in SUSPICIOUS_TLDS else 0,
        1 if h in SHORTENERS else 0,
        min(sum(1 for k in KEYWORDS if k in l), 3),
        1 if "xn--" in host else 0,
        round(entropy(host + path), 6),
        1 if "//" in path else 0,
        1 if EXE.search(l) else 0,
        1 if re.match(r"^(javascript|data|vbscript):", l) else 0,
        1 if (port and port not in ("80", "443")) else 0,
        sum(1 for ch in host if ch.isdigit() and ch.isascii()),
        path.count("/"),
        len(host),
        len(path),
        sum(1 for ch in p if ch in "=&%_~"),
    ]

# ---- Tree export ----
def export_sklearn_tree(est):
    t = est.tree_
    nodes = []
    for i in range(t.node_count):
        if t.children_left[i] == -1:
            v = t.value[i][0]
            nodes.append([-1, 0, -1, -1, round(float(v[1] / v.sum()), 6), float(t.weighted_n_node_samples[i])])
        else:
            nodes.append([int(t.feature[i]), round(float(t.threshold[i]), 6), int(t.children_left[i]), int(t.children_right[i]), 0, float(t.weighted_n_node_samples[i])])
    return nodes

def export_xgb(booster):
    out = []
    for tj in booster.get_dump(dump_format="json", with_stats=True):
        root = json.loads(tj)
        nodes, idmap = [], {}
        def walk(n):
            idx = len(nodes); nodes.append(None); idmap[n["nodeid"]] = idx
            if "leaf" in n:
                nodes[idx] = [-1, 0, -1, -1, round(n["leaf"], 6), n["cover"]]
            else:
                kids = {c["nodeid"]: c for c in n["children"]}
                L = walk(kids[n["yes"]]); R = walk(kids[n["no"]])
                nodes[idx] = [int(n["split"][1:]), n["split_condition"], L, R, 0, n["cover"]]
            return idx
        walk(root)
        out.append(nodes)
    return out

def metrics(y, p):
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred), 4),
        "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
        "fpr": round(float(fp / (fp + tn)), 4), "auc": round(roc_auc_score(y, p), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }

def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "ml" / "data.csv"
    rows = {}
    with open(src, newline="", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            u, lab = (r.get("url") or "").strip(), r.get("label")
            if u and lab in ("good", "bad"): rows[u] = 1 if lab == "bad" else 0
    rnd = random.Random(SEED)
    good = [u for u, y in rows.items() if y == 0]; bad = [u for u, y in rows.items() if y == 1]
    rnd.shuffle(good); rnd.shuffle(bad)
    urls = good[:PER_CLASS] + bad[:PER_CLASS]
    y = np.array([0] * min(PER_CLASS, len(good)) + [1] * min(PER_CLASS, len(bad)))
    X = np.array([featurize(u) for u in urls], dtype=float)
    Xtr, Xte, ytr, yte, utr, ute = train_test_split(X, y, urls, test_size=0.2, random_state=SEED, stratify=y)
    print(f"train={len(ytr)} test={len(yte)}")

    # Logistic regression on standardized features, folded back to raw scale
    mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-9
    lr = LogisticRegression(max_iter=2000, C=1.0).fit((Xtr - mu) / sd, ytr)
    w = lr.coef_[0] / sd; b = float(lr.intercept_[0] - (lr.coef_[0] * mu / sd).sum())
    p_lr = 1 / (1 + np.exp(-(Xte @ w + b)))

    rf = RandomForestClassifier(n_estimators=40, max_depth=10, min_samples_leaf=5, random_state=SEED, n_jobs=-1).fit(Xtr, ytr)
    p_rf = rf.predict_proba(Xte)[:, 1]

    xg = xgb.XGBClassifier(n_estimators=120, max_depth=4, learning_rate=0.15, subsample=0.9, colsample_bytree=0.9, random_state=SEED, base_score=0.5, tree_method="exact")
    xg.fit(Xtr, ytr)
    booster = xg.get_booster()
    p_xg = xg.predict_proba(Xte)[:, 1]
    base_margin = float(str(json.loads(booster.save_config())["learner"]["learner_model_param"]["base_score"]).strip("[]"))
    base_margin = math.log(base_margin / (1 - base_margin))

    res = {"logreg": metrics(yte, p_lr), "rf": metrics(yte, p_rf), "xgb": metrics(yte, p_xg)}
    for k, v in res.items(): print(k, v)

    # Reference SHAP values for parity tests
    import shap
    ref_idx = list(range(5))
    sv_rf = shap.TreeExplainer(rf).shap_values(Xte[ref_idx])
    sv_rf = sv_rf[:, :, 1] if np.ndim(sv_rf) == 3 else (sv_rf[1] if isinstance(sv_rf, list) else sv_rf)
    sv_xg = shap.TreeExplainer(xg).shap_values(Xte[ref_idx])

    OUT.mkdir(parents=True, exist_ok=True)
    model = {
        "features": [{"key": k, "label": l} for k, l in FEATURES],
        "mean": [round(float(v), 6) for v in Xtr.mean(0)],
        "logreg": {"w": [round(float(v), 6) for v in w], "b": round(b, 6)},
        "rf": {"trees": [export_sklearn_tree(e) for e in rf.estimators_], "leq": True},
        "xgb": {"trees": export_xgb(booster), "base": round(base_margin, 6), "leq": False},
        "metrics": res,
        "trainedOn": {"rows": int(len(ytr)), "test": int(len(yte)), "source": "faizann24 malicious URL dataset (good/bad labels)"},
    }
    (OUT / "model.json").write_text(json.dumps(model, separators=(",", ":")))
    hold = [{"u": u, "y": int(t)} for u, t in list(zip(ute, yte))[:3000]]
    (OUT / "holdout.json").write_text(json.dumps(hold, separators=(",", ":")))
    ref = {
        "urls": [ute[i] for i in ref_idx], "x": Xte[ref_idx].tolist(),
        "p": {"logreg": p_lr[ref_idx].tolist(), "rf": p_rf[ref_idx].tolist(), "xgb": p_xg[ref_idx].tolist()},
        "shap": {"rf": np.asarray(sv_rf).tolist(), "xgb": np.asarray(sv_xg).tolist()},
    }
    (ROOT / "src" / "test" / "ml-reference.json").write_text(json.dumps(ref))
    print("exported", (OUT / "model.json").stat().st_size, "bytes")

if __name__ == "__main__":
    sys.exit(main())
