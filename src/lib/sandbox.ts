// Safe Preview: builds an isolated, simulated view of what a URL would show,
// WITHOUT ever contacting the URL. Everything is derived from the string itself.
import type { Verdict } from "./detector";

export type Part = { kind: string; text: string; danger?: string | undefined };
export type Finding = { title: string; detail: string; severity: "high" | "medium" | "low" };

const BRANDS = ["paypal", "bank", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram", "whatsapp", "wallet", "chase", "wellsfargo", "sbi", "hdfc", "icici", "paytm"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"];

export const escapeHtml = (s: string) =>
  s.replace(/[&<>"'`]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]!);

function parse(payload: string): URL | null {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(payload) ? payload : `http://${payload}`);
    return u;
  } catch { return null; }
}

/** Splits a URL into labelled, colour-codable pieces. */
export function dissect(payload: string): Part[] {
  const u = parse(payload);
  if (!u || !["http:", "https:"].includes(u.protocol)) {
    return [{ kind: "raw", text: payload, danger: /^(javascript|data|vbscript):/i.test(payload) ? "Runs code directly in your browser" : undefined }];
  }
  const parts: Part[] = [];
  parts.push({ kind: "scheme", text: u.protocol + "//", danger: u.protocol === "http:" ? "Unencrypted — anyone on the network can read what you type" : undefined });
  if (u.username) parts.push({ kind: "userinfo", text: decodeURIComponent(u.username) + (u.password ? ":***" : "") + "@", danger: "Everything before '@' is ignored — this is a disguise" });
  const host = u.hostname;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if (isIp) parts.push({ kind: "domain", text: host, danger: "A raw IP address — real companies use names" });
  else {
    const labels = host.split(".");
    const reg = labels.slice(-2).join(".");
    const sub = labels.slice(0, -2).join(".");
    if (sub) parts.push({ kind: "subdomain", text: sub + ".", danger: BRANDS.some((b) => sub.includes(b)) || labels.length > 3 ? "Brand names here are decoration — the owner is to the right" : undefined });
    parts.push({ kind: "domain", text: reg, danger: host.includes("xn--") ? "Punycode — may look like a famous site but isn't" : undefined });
  }
  if (u.port) parts.push({ kind: "port", text: ":" + u.port, danger: "Unusual port — often used by throwaway servers" });
  if (u.pathname && u.pathname !== "/") parts.push({ kind: "path", text: u.pathname, danger: /\.(exe|apk|scr|bat|msi|jar)$/i.test(u.pathname) ? "Downloads a program onto your device" : undefined });
  if (u.search) parts.push({ kind: "query", text: u.search });
  if (u.hash) parts.push({ kind: "hash", text: u.hash });
  return parts;
}

/** The real owner of the link (registrable domain), or null. */
export function realOwner(payload: string): string | null {
  const u = parse(payload);
  if (!u || !u.hostname.includes(".")) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) return u.hostname;
  return u.hostname.split(".").slice(-2).join(".");
}

export function impersonates(payload: string): string | null {
  const lower = payload.toLowerCase();
  const owner = realOwner(payload) ?? "";
  const b = BRANDS.find((x) => lower.includes(x) && !owner.startsWith(x + "."));
  return b ? b.charAt(0).toUpperCase() + b.slice(1) : null;
}

/** What the page would most likely try to do. */
export function predictPage(v: Verdict): "credential" | "download" | "redirect" | "script" | "generic" {
  const l = v.payload.toLowerCase();
  if (/^(javascript|data|vbscript):/.test(l)) return "script";
  if (/\.(exe|apk|scr|bat|msi|jar)(\?|#|$)/.test(l)) return "download";
  const owner = realOwner(v.payload);
  if (owner && SHORTENERS.includes(owner)) return "redirect";
  if (/login|signin|verify|account|password|secure|update|wallet|bank|confirm/.test(l)) return "credential";
  return "generic";
}

export function findings(v: Verdict): Finding[] {
  const out: Finding[] = [];
  const brand = impersonates(v.payload);
  const owner = realOwner(v.payload);
  if (brand) out.push({ severity: "high", title: `Pretends to be ${brand}`, detail: `The link mentions ${brand}, but it's actually owned by "${owner ?? "unknown"}".` });
  for (const p of dissect(v.payload)) if (p.danger) out.push({ severity: p.kind === "query" ? "low" : "high", title: p.danger, detail: `Found in: ${p.text}` });
  const page = predictPage(v);
  if (page === "credential") out.push({ severity: "high", title: "Likely a fake sign-in page", detail: "Anything typed here (passwords, card numbers, OTPs) goes straight to the attacker." });
  if (page === "redirect") out.push({ severity: "medium", title: "Hidden final destination", detail: "Link shorteners hide where you'll really end up." });
  if (page === "download") out.push({ severity: "high", title: "Automatic file download", detail: "Opening this could install malware or spyware." });
  if (page === "script") out.push({ severity: "high", title: "Executes code instead of opening a page", detail: "This can steal data from the page you're on." });
  const seen = new Set<string>();
  return out.filter((f) => (seen.has(f.title) ? false : (seen.add(f.title), true)));
}

/**
 * Builds the HTML for the sandboxed iframe. All user content is escaped and a
 * strict CSP blocks scripts, network requests, forms and images.
 */
export function buildPreviewDoc(v: Verdict): string {
  const e = escapeHtml;
  const page = predictPage(v);
  const brand = impersonates(v.payload) ?? "Your Account";
  const owner = e(realOwner(v.payload) ?? "unknown");
  const tag = (n: number, text: string) =>
    `<span class="tag"><b>${n}</b>${e(text)}</span>`;

  let body = "";
  if (page === "credential") {
    body = `<div class="card"><div class="logo">${e(brand)}</div><h1>Verify your identity</h1>
      <p class="sub">Your account has been temporarily limited. Sign in to restore access.</p>
      <div class="field">Email or phone ${tag(1, "Sent to " + (realOwner(v.payload) ?? "attacker"))}</div>
      <div class="field">Password ${tag(2, "Captured in plain text")}</div>
      <div class="btn">Continue ${tag(3, "Fake button — no real login")}</div>
      <p class="fine">Urgency like "limited" or "suspended" is a classic pressure tactic.</p></div>`;
  } else if (page === "download") {
    body = `<div class="card"><h1>Your file is ready</h1><p class="sub">Update required to view this content.</p>
      <div class="btn">Download now ${tag(1, "Installs an unknown program")}</div>
      <p class="fine">Legitimate sites rarely push app installs from a QR code.</p></div>`;
  } else if (page === "redirect") {
    body = `<div class="card"><h1>Redirecting…</h1><div class="hops"><span>QR code</span>→<span>${owner}</span>→<span>?? unknown</span>→<span>?? final page</span></div>
      ${tag(1, "Destination is hidden until you click")}</div>`;
  } else if (page === "script") {
    body = `<div class="card"><h1>Not a web page</h1><pre>${e(v.payload.slice(0, 300))}</pre>${tag(1, "This would run as code")}</div>`;
  } else {
    body = `<div class="card"><h1>${owner}</h1><p class="sub">No specific trap detected. The page would load from the domain above.</p></div>`;
  }

  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<style>
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:repeating-linear-gradient(45deg,#f6f3ee 0 14px,#efe9e1 14px 28px);color:#222;padding:22px;min-height:100vh}
.ribbon{position:fixed;top:0;left:0;right:0;background:#b42318;color:#fff;font:600 11px/1 monospace;letter-spacing:.12em;text-transform:uppercase;padding:7px;text-align:center}
.card{max-width:340px;margin:28px auto 0;background:#fff;border-radius:12px;padding:22px;box-shadow:0 10px 30px #0002;filter:saturate(.75)}
.logo{font-weight:800;font-size:20px;color:#1b4fb8;margin-bottom:8px}h1{font-size:19px;margin:0 0 4px}.sub{color:#666;margin:0 0 14px}
.field{position:relative;border:1px solid #ccc;border-radius:8px;padding:10px;color:#999;margin:10px 0}
.btn{position:relative;background:#1b4fb8;color:#fff;border-radius:8px;padding:10px;text-align:center;font-weight:600;margin-top:12px}
.tag{display:inline-flex;gap:6px;align-items:center;float:right;background:#b42318;color:#fff;font:600 10px/1.2 monospace;padding:3px 7px;border-radius:99px}
.tag b{background:#fff;color:#b42318;border-radius:99px;width:14px;height:14px;display:inline-grid;place-items:center}
.btn .tag{float:none;margin-left:8px}.fine{font-size:11px;color:#888;margin-top:14px}
.hops{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:12px 0;font:12px monospace}.hops span{border:1px dashed #999;border-radius:6px;padding:4px 6px}
pre{white-space:pre-wrap;word-break:break-all;background:#111;color:#f88;padding:10px;border-radius:8px;font-size:11px}
</style></head><body><div class="ribbon">⚠ Simulated preview · nothing was loaded · inputs disabled</div>${body}</body></html>`;
}
