// QR payload analysis: trained ML models (see ./ml.ts) + hand-written safety rules.
// Rule signals below explain the link in plain language; the hand-tuned classifier for QR payloads (URLs / text).
// Weights were tuned on public phishing-URL feature research (lexical features).

import { confidenceOf, runAll, type Confidence, type ModelId } from "./ml";

export type Feature = { key: string; label: string; value: number; weight: number };
export type Verdict = {
  payload: string;
  isUrl: boolean;
  probability: number; // probability malicious, 0..1
  label: "safe" | "suspicious" | "malicious";
  features: Feature[];
  model: ModelId;
  probs: Record<ModelId, number>;
  x: number[];
  confidence: Confidence;
  /** True when a hard safety rule (e.g. javascript: URI) overrode the model. */
  ruleOverride: boolean;
};

const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "loan", "ru", "cn"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"];
const KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "paypal", "signin", "wallet", "confirm", "password", "free", "gift", "bonus", "invoice"];

function entropy(s: string) {
  if (!s) return 0;
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1);
  let e = 0;
  for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}

const BIAS = -3.2;

export function analyze(raw: string, model: ModelId = "xgb"): Verdict {
  const payload = raw.trim();
  let url: URL | null = null;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(payload) ? payload : `http://${payload}`);
    if (!url.hostname.includes(".")) url = null;
  } catch { url = null; }

  const lower = payload.toLowerCase();
  const host = url?.hostname.toLowerCase() ?? "";
  const tld = host.split(".").pop() ?? "";
  const f: Feature[] = [];
  const add = (key: string, label: string, value: number, weight: number) => f.push({ key, label, value, weight });

  add("len", "URL length > 75", payload.length > 75 ? 1 : 0, 1.0);
  add("ip", "Host is raw IP address", /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1 : 0, 2.6);
  add("at", "Contains '@' symbol", lower.includes("@") && !lower.startsWith("mailto:") ? 1 : 0, 2.0);
  add("http", "No HTTPS encryption", url && url.protocol === "http:" ? 1 : 0, 1.1);
  add("sub", "Many subdomains (≥3 dots)", (host.match(/\./g)?.length ?? 0) >= 3 ? 1 : 0, 1.3);
  add("dash", "Hyphens in domain", (host.match(/-/g)?.length ?? 0) >= 2 ? 1 : 0, 1.2);
  add("tld", "Suspicious top-level domain", SUSPICIOUS_TLDS.includes(tld) ? 1 : 0, 1.8);
  add("short", "Link shortener hides target", SHORTENERS.includes(host) ? 1 : 0, 1.5);
  add("kw", "Phishing keywords", Math.min(KEYWORDS.filter((k) => lower.includes(k)).length, 3), 0.9);
  add("puny", "Punycode / lookalike domain", host.includes("xn--") ? 1 : 0, 2.2);
  add("ent", "High randomness (entropy > 4.2)", entropy(host + (url?.pathname ?? "")) > 4.2 ? 1 : 0, 1.0);
  add("dbl", "Redirect via '//' in path", (url?.pathname ?? "").includes("//") ? 1 : 0, 1.4);
  add("exe", "Downloads an executable/APK", /\.(exe|apk|scr|bat|msi|jar)(\?|$)/.test(lower) ? 1 : 0, 2.8);
  add("js", "Script / data URI scheme", /^(javascript|data|vbscript):/.test(lower) ? 1 : 0, 5);
  add("port", "Non-standard port", url?.port && !["80", "443"].includes(url.port) ? 1 : 0, 1.2);

  const z = BIAS + f.reduce((s, x) => s + x.value * x.weight, 0);
  const isScript = /^(javascript|data|vbscript):/.test(lower);
  const ml = runAll(payload);
  let probability = ml.probs[model];
  let ruleOverride = false;
  if (!url && !isScript) probability = 0.03; // plain text — nothing to open
  else if (isScript || f.some((x) => x.key === "exe" && x.value)) {
    const rule = 1 / (1 + Math.exp(-z));
    if (rule > probability) { probability = Math.max(rule, 0.95); ruleOverride = true; }
  }
  const label = probability >= 0.6 ? "malicious" : probability >= 0.3 ? "suspicious" : "safe";
  return { payload, isUrl: !!url, probability, label, features: f, model, probs: ml.probs, x: ml.x, confidence: confidenceOf(ml.probs, model, ml.x), ruleOverride };
}
