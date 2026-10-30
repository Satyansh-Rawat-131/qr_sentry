// Feature extraction for the trained models. MUST stay identical to ml/train.py `featurize`.
const SUSPICIOUS_TLDS = new Set(["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "loan", "ru", "cn"]);
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"]);
const KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "paypal", "signin", "wallet", "confirm", "password", "free", "gift", "bonus", "invoice"];

function firstOf(s: string, chars: string) {
  let cut = s.length;
  for (const ch of chars) {
    const i = s.indexOf(ch);
    if (i !== -1 && i < cut) cut = i;
  }
  return cut;
}

export function parseUrl(p: string): { host: string; port: string; path: string } {
  const m = /^[a-z][a-z0-9+.-]*:/i.exec(p);
  let rest = p;
  if (m) {
    const end = m[0].length;
    if (p.slice(end, end + 2) !== "//") return { host: "", port: "", path: "" };
    rest = p.slice(end + 2);
  }
  const cut = firstOf(rest, "/?#");
  let auth = rest.slice(0, cut);
  const tail = rest.slice(cut);
  const path = tail.startsWith("/") ? tail.slice(0, firstOf(tail, "?#")) : "";
  const at = auth.lastIndexOf("@");
  if (at !== -1) auth = auth.slice(at + 1);
  let port = "";
  const c = auth.lastIndexOf(":");
  if (c !== -1 && /^[0-9]+$/.test(auth.slice(c + 1))) {
    port = auth.slice(c + 1);
    auth = auth.slice(0, c);
  }
  return { host: auth.toLowerCase(), port, path };
}

function entropy(s: string) {
  if (!s) return 0;
  const counts = new Map<string, number>();
  let n = 0;
  for (const ch of s) { counts.set(ch, (counts.get(ch) ?? 0) + 1); n++; }
  let e = 0;
  for (const v of counts.values()) e -= (v / n) * Math.log2(v / n);
  return Math.round(e * 1e6) / 1e6;
}

const count = (s: string, ch: string) => s.split(ch).length - 1;
const pyLen = (s: string) => [...s].length; // Python len() counts code points

/** Strip scheme / "www." / bare trailing slash — mirrors `canonical` in ml/train.py. */
export function canonical(raw: string) {
  let p = raw.trim().replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  if (p.endsWith("/") && count(p, "/") === 1) p = p.slice(0, -1);
  return p;
}

export function featurize(raw: string): number[] {
  const p = canonical(raw);
  const l = p.toLowerCase();
  const { host, port, path } = parseUrl(p);
  const h = host.startsWith("www.") ? host.slice(4) : host;
  const tld = host.includes(".") ? host.slice(host.lastIndexOf(".") + 1) : "";
  return [
    pyLen(p),
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1 : 0,
    l.includes("@") && !l.startsWith("mailto:") ? 1 : 0,
    count(host, "."),
    count(host, "-"),
    SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    SHORTENERS.has(h) ? 1 : 0,
    Math.min(KEYWORDS.filter((k) => l.includes(k)).length, 3),
    host.includes("xn--") ? 1 : 0,
    entropy(host + path),
    path.includes("//") ? 1 : 0,
    /\.(exe|apk|scr|bat|msi|jar)(\?|$)/.test(l) ? 1 : 0,
    /^(javascript|data|vbscript):/.test(l) ? 1 : 0,
    port && port !== "80" && port !== "443" ? 1 : 0,
    [...host].filter((ch) => ch >= "0" && ch <= "9").length,
    count(path, "/"),
    pyLen(host),
    pyLen(path),
    [...p].filter((ch) => "=&%_~".includes(ch)).length,
  ];
}
