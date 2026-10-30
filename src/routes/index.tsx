import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import jsQR from "jsqr";
import { analyze, type Verdict } from "@/lib/detector";
import { SafePreview } from "@/components/SafePreview";
import { ConfidencePanel, FeedbackButtons, ModelPicker, ShapPanel } from "@/components/ModelInsights";
import { ContinuousEvaluation, ModelComparison } from "@/components/ModelLab";
import type { ModelId } from "@/lib/ml";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "QRSentry — Malicious QR Code Detection" },
      { name: "description", content: "Scan or upload a QR code and a machine learning model tells you if its link is safe." },
      { property: "og:title", content: "QRSentry — Malicious QR Code Detection" },
      { property: "og:description", content: "ML-powered QR code threat analysis in your browser." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

const SAMPLES = [
  { label: "Wikipedia", url: "https://www.wikipedia.org" },
  { label: "Fake PayPal", url: "http://192.168.4.20/paypal-login/verify-account.php" },
  { label: "Bank lookalike", url: "https://secure-update-bank.account-verify.xyz/login" },
  { label: "Free gift", url: "https://bit.ly/3xFree-gift" },
];
const STEPS = ["Decoding payload", "Extracting features", "Running ML models", "Computing SHAP explanation"];
const WORDS = { safe: "Looks safe.", suspicious: "Tread carefully.", malicious: "Don't open it." };
const TONE = {
  safe: { text: "text-ok", stroke: "var(--ok)" },
  suspicious: { text: "text-warn", stroke: "var(--warn)" },
  malicious: { text: "text-destructive", stroke: "var(--destructive)" },
};

function useCountUp(target: number) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf = 0; const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min((t - start) / 1100, 1);
      setV(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return v;
}

function QrMosaic() {
  const cells = useMemo(() => Array.from({ length: 21 * 21 }, (_, i) => {
    const x = i % 21, y = Math.floor(i / 21);
    const finder = (a: number, b: number) => x >= a && x < a + 7 && y >= b && y < b + 7;
    if (finder(0, 0) || finder(14, 0) || finder(0, 14)) {
      const lx = x % 14 % 7, ly = y % 14 % 7;
      const ring = lx === 0 || lx === 6 || ly === 0 || ly === 6;
      const core = lx >= 2 && lx <= 4 && ly >= 2 && ly <= 4;
      return { on: ring || core, fixed: true, d: 0 };
    }
    return { on: Math.sin(i * 12.9898) * 43758.5453 % 1 > 0.05, fixed: false, d: (i * 37) % 30 / 10 };
  }), []);
  return (
    <div className="float relative aspect-square w-full max-w-sm">
      <div className="absolute -inset-10 rounded-full bg-[var(--glow)] blur-3xl" />
      <div className="glass relative grid h-full grid-cols-[repeat(21,1fr)] gap-[2px] p-6">
        {cells.map((c, i) => (
          <span key={i} className={`rounded-[2px] ${c.on ? (c.fixed ? "bg-foreground" : "pixel bg-accent") : ""}`} style={{ animationDelay: `${c.d}s` }} />
        ))}
      </div>
    </div>
  );
}

function Index() {
  const [result, setResult] = useState<Verdict | null>(null);
  const [error, setError] = useState("");
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [step, setStep] = useState(-1);
  const [drag, setDrag] = useState(false);
  const [cam, setCam] = useState(false);
  const [history, setHistory] = useState<Verdict[]>([]);
  const [sandbox, setSandbox] = useState(false);
  const [model, setModel] = useState<ModelId>("xgb");
  const pickModel = (m: ModelId) => { setModel(m); if (result) setResult(analyze(result.payload, m)); };
  const fileRef = useRef<HTMLInputElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const mainRef = useRef<HTMLElement>(null);

  const run = (s: string) => {
    setError(""); setText(s); setResult(null); setStep(0);
    STEPS.forEach((_, i) => setTimeout(() => setStep(i), i * 380));
    setTimeout(() => {
      const v = analyze(s, model);
      setStep(-1); setResult(v);
      setHistory((h) => [v, ...h.filter((x) => x.payload !== v.payload)].slice(0, 5));
      resultRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }, STEPS.length * 380 + 150);
  };

  const decodeImage = (src: CanvasImageSource, w: number, h: number) => {
    const c = document.createElement("canvas"); c.width = w; c.height = h;
    const ctx = c.getContext("2d")!; ctx.drawImage(src, 0, 0, w, h);
    const d = ctx.getImageData(0, 0, w, h);
    return jsQR(d.data, w, h)?.data;
  };

  const onFile = (file?: File) => {
    if (!file) return;
    const url = URL.createObjectURL(file);
    setPreview(url);
    const img = new Image();
    img.onload = () => {
      const data = decodeImage(img, img.width, img.height);
      if (data) run(data);
      else { setResult(null); setError("Couldn't find a QR code in that image. Try a sharper, closer shot."); }
    };
    img.src = url;
  };

  useEffect(() => {
    if (!cam) return;
    let stream: MediaStream | undefined; let raf = 0; let alive = true;
    navigator.mediaDevices?.getUserMedia({ video: { facingMode: "environment" } }).then((s) => {
      stream = s; const v = videoRef.current!; v.srcObject = s; v.play();
      const loop = () => {
        if (!alive) return;
        if (v.videoWidth) {
          const data = decodeImage(v, v.videoWidth, v.videoHeight);
          if (data) { setCam(false); setPreview(null); run(data); return; }
        }
        raf = requestAnimationFrame(loop);
      };
      loop();
    }).catch(() => { setCam(false); setError("Camera access was blocked. Upload an image instead."); });
    return () => { alive = false; cancelAnimationFrame(raf); stream?.getTracks().forEach((t) => t.stop()); };
  }, [cam]);

  const onMove = (e: React.MouseEvent) => {
    mainRef.current?.style.setProperty("--mx", `${e.clientX}px`);
    mainRef.current?.style.setProperty("--my", `${e.clientY + window.scrollY}px`);
  };

  const pct = useCountUp(result ? Math.round(result.probability * 100) : 0);
  const tone = result ? TONE[result.label] : TONE.safe;
  const R = 70, C = 2 * Math.PI * R;
  const busy = step >= 0;

  return (
    <main ref={mainRef} onMouseMove={onMove} className="spotlight grain min-h-screen overflow-hidden px-5 pb-16 md:px-10">
      <div className="mx-auto max-w-6xl">
        <nav className="fade-up flex items-center justify-between py-6">
          <span className="flex items-center gap-2 font-mono text-sm">
            <span className="grid h-7 w-7 grid-cols-2 gap-[3px] rounded-md border p-1">
              <i className="rounded-[1px] bg-foreground" /><i className="pixel rounded-[1px] bg-accent" />
              <i className="pixel rounded-[1px] bg-accent" style={{ animationDelay: "1s" }} /><i className="rounded-[1px] bg-foreground" />
            </span>
            QRSentry
          </span>
          <a href="#scan" className="chip px-4 py-1.5 font-mono text-xs text-muted-foreground">Start scanning ↓</a>
        </nav>

        <header className="grid items-center gap-12 py-14 md:grid-cols-[1.3fr_1fr] md:py-20">
          <div>
            <p className="fade-up mb-6 inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-xs text-muted-foreground">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ok" /> XGBoost · Random Forest · SHAP · runs on your device
            </p>
            <h1 className="font-serif text-6xl leading-[0.92] tracking-tight md:text-[6.5rem]">
              {["Every", "square", "hides", "a"].map((w, i) => (
                <span key={w} className="inline-block overflow-hidden pr-4 align-bottom"><span className="reveal inline-block" style={{ animationDelay: `${i * 90}ms` }}>{w}</span></span>
              ))}
              <span className="inline-block overflow-hidden align-bottom"><em className="reveal text-gradient inline-block pr-2" style={{ animationDelay: "380ms" }}>destination.</em></span>
            </h1>
            <p className="fade-up mt-8 max-w-md text-lg text-muted-foreground" style={{ animationDelay: "600ms" }}>
              Find out where a QR code really takes you — before your phone does. Upload it, point your camera, or paste a link.
            </p>
            <a href="#scan" className="btn-glow fade-up mt-10 inline-flex items-center gap-3 px-7 py-4 font-medium" style={{ animationDelay: "750ms" }}>
              Check a QR code <span aria-hidden>→</span>
            </a>
          </div>
          <div className="fade-up flex justify-center" style={{ animationDelay: "300ms" }}><QrMosaic /></div>
        </header>

        <section id="scan" className="grid scroll-mt-6 gap-6 md:grid-cols-[1fr_1.1fr]">
          <div className="glass p-6 md:p-8">
            <h2 className="font-serif text-3xl">Bring the code</h2>
            <p className="mt-1 text-sm text-muted-foreground">Drop an image, use your camera, or paste the link.</p>

            <div
              role="button" tabIndex={0}
              onClick={() => !cam && fileRef.current?.click()}
              onKeyDown={(e) => e.key === "Enter" && fileRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
              className={`relative mt-6 flex aspect-[4/3] cursor-pointer items-center justify-center overflow-hidden rounded-2xl border border-dashed transition-all duration-300 ${drag ? "scale-[1.02] border-accent bg-[var(--glow)]" : "border-input hover:border-accent"} ${busy || cam ? "scanline" : ""}`}
            >
              {cam ? <video ref={videoRef} muted playsInline className="h-full w-full object-cover" />
                : preview ? <img src={preview} alt="Uploaded QR code" className="h-4/5 object-contain" />
                : (
                  <div className="text-center">
                    <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl border text-2xl transition group-hover:rotate-6">⌗</div>
                    <p className="font-serif text-2xl italic">{drag ? "Let it go…" : "Drop a QR image"}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">or click to browse</p>
                  </div>
                )}
              {["left-3 top-3 border-l-2 border-t-2", "right-3 top-3 border-r-2 border-t-2", "bottom-3 left-3 border-b-2 border-l-2", "bottom-3 right-3 border-b-2 border-r-2"].map((p) => (
                <span key={p} className={`pointer-events-none absolute h-6 w-6 border-accent ${p}`} />
              ))}
            </div>
            <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />

            <button onClick={() => { setError(""); setCam((c) => !c); }} className="chip mt-4 w-full py-3 text-sm text-muted-foreground">
              {cam ? "Stop camera" : "◉  Scan with camera"}
            </button>

            <form onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text); }} className="mt-4 flex items-center gap-2 rounded-full border border-input p-1.5 pl-5 transition focus-within:border-accent focus-within:shadow-[0_0_0_4px_var(--glow)]">
              <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste a link…" className="min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:text-muted-foreground" />
              <button disabled={busy} className="btn-glow px-5 py-2 text-sm font-medium disabled:opacity-50">Check</button>
            </form>

            <p className="mt-6 mb-2 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Try one</p>
            <div className="flex flex-wrap gap-2">
              {SAMPLES.map((s) => (
                <button key={s.url} onClick={() => { setPreview(null); run(s.url); }} className="chip px-3 py-1.5 text-xs text-muted-foreground">{s.label}</button>
              ))}
            </div>
            {error && <p className="fade-up mt-4 rounded-xl border border-destructive/40 px-4 py-3 text-sm text-destructive">{error}</p>}
          </div>

          <div ref={resultRef} className="glass relative min-h-[520px] overflow-hidden p-6 md:p-8">
            <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
              <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Model</p>
              <ModelPicker value={model} onChange={pickModel} />
            </div>
            {busy ? (
              <div className="flex h-full flex-col justify-center gap-4">
                {STEPS.map((s, i) => (
                  <div key={s} className={`flex items-center gap-3 font-mono text-sm transition-all duration-300 ${i <= step ? "opacity-100" : "translate-x-2 opacity-20"}`}>
                    <span className={`h-2 w-2 rounded-full ${i < step ? "bg-ok" : i === step ? "animate-ping bg-accent" : "bg-muted-foreground"}`} />{s}…
                  </div>
                ))}
              </div>
            ) : !result ? (
              <div className="flex h-full flex-col items-center justify-center text-center">
                <div className="mb-6 h-32 w-32 rounded-full border border-dashed border-input" />
                <p className="font-serif text-3xl italic text-muted-foreground">Your verdict appears here.</p>
                <p className="mt-2 text-sm text-muted-foreground">Pick an example to see it in action.</p>
              </div>
            ) : (
              <div key={result.payload + history.length}>
                <div className="flex items-center gap-6">
                  <div className="relative h-40 w-40 shrink-0">
                    <svg viewBox="0 0 160 160" className="-rotate-90 overflow-visible">
                      <circle cx="80" cy="80" r={R} fill="none" stroke="var(--border)" strokeWidth="10" />
                      <circle cx="80" cy="80" r={R} fill="none" stroke={tone.stroke} strokeWidth="10" strokeLinecap="round"
                        strokeDasharray={C} strokeDashoffset={C - (C * pct) / 100} style={{ filter: `drop-shadow(0 0 10px ${tone.stroke})` }} />
                    </svg>
                    <div className="absolute inset-0 grid place-items-center">
                      <span className="font-serif text-5xl tabular-nums">{pct}<span className="text-xl text-muted-foreground">%</span></span>
                    </div>
                  </div>
                  <div className="fade-up">
                    <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Risk · {result.label}</p>
                    <p className={`font-serif text-4xl leading-tight md:text-5xl ${tone.text}`}>{WORDS[result.label]}</p>
                  </div>
                </div>

                <div className="fade-up mt-6 flex items-center gap-2 rounded-xl border px-4 py-3" style={{ animationDelay: "150ms" }}>
                  <p className="min-w-0 flex-1 truncate font-mono text-xs">{result.payload}</p>
                  <button onClick={() => navigator.clipboard?.writeText(result.payload)} className="chip px-3 py-1 text-[11px] text-muted-foreground">Copy</button>
                </div>
                {!result.isUrl && <p className="mt-2 text-sm text-muted-foreground">Plain text, not a link — low risk.</p>}
                {(result.isUrl || result.label !== "safe") && (
                  <button onClick={() => setSandbox(true)} className="btn-glow fade-up mt-4 w-full py-3 text-sm font-medium" style={{ animationDelay: "200ms" }}>
                    ◫ Open safe preview — see why before you click
                  </button>
                )}

                <ConfidencePanel v={result} />
                <ShapPanel v={result} />
                <FeedbackButtons v={result} />

                <h3 className="mt-8 mb-3 font-serif text-2xl">Plain-language warning signs</h3>
                <ul className="space-y-1.5">
                  {[...result.features].sort((a, b) => b.value * b.weight - a.value * a.weight).map((f, i) => {
                    const s = f.value * f.weight;
                    return (
                      <li key={f.key} className="fade-up group" style={{ animationDelay: `${200 + i * 40}ms` }}>
                        <div className={`flex justify-between text-sm ${s ? "" : "text-muted-foreground/50"}`}>
                          <span>{f.label}</span>
                          <span className={`font-mono text-xs ${s ? "text-accent" : ""}`}>{s ? `+${s.toFixed(1)}` : "—"}</span>
                        </div>
                        {s > 0 && (
                          <div className="mt-1 h-[3px] overflow-hidden rounded-full bg-border">
                            <div className="h-full rounded-full bg-gradient-to-r from-accent to-accent-2 transition-all duration-1000" style={{ width: `${Math.min(s / 3, 1) * 100}%` }} />
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        </section>

        {history.length > 0 && (
          <section className="fade-up mt-6">
            <p className="mb-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Recent checks</p>
            <div className="flex flex-wrap gap-2">
              {history.map((h) => (
                <button key={h.payload} onClick={() => setResult(analyze(h.payload, model))} className="chip flex max-w-xs items-center gap-2 px-3 py-1.5 text-xs">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: TONE[h.label].stroke }} />
                  <span className="truncate font-mono text-muted-foreground">{h.payload}</span>
                </button>
              ))}
            </div>
          </section>
        )}

        <section id="lab" className="mt-16 grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <ModelComparison />
          <ContinuousEvaluation />
        </section>

        <section className="mt-24 grid gap-6 md:grid-cols-3">
          {[
            ["01", "Decode", "The image is read right in your browser. Nothing is uploaded."],
            ["02", "Dissect", "Nineteen signals: lookalike domains, raw IPs, shorteners, scam words, randomness and more."],
            ["03", "Decide", "XGBoost, Random Forest or Logistic Regression score it, and SHAP shows exactly why."],
          ].map(([n, t, d]) => (
            <div key={n} className="glass group p-7 transition duration-500 hover:-translate-y-1">
              <span className="font-mono text-xs text-accent">{n}</span>
              <h3 className="mt-6 font-serif text-4xl transition group-hover:italic">{t}</h3>
              <p className="mt-2 text-sm text-muted-foreground">{d}</p>
            </div>
          ))}
        </section>

        <footer className="mt-20 flex justify-between border-t pt-6 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
          <span>QRSentry</span><span>Scan smart. Stay safe.</span>
        </footer>
      </div>
      {sandbox && result && <SafePreview result={result} onClose={() => setSandbox(false)} />}
    </main>
  );
}
