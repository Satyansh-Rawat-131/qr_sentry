import { useMemo, useState } from "react";
import type { Verdict } from "@/lib/detector";
import { buildPreviewDoc, dissect, findings, realOwner } from "@/lib/sandbox";

export function SafePreview({ result, onClose }: { result: Verdict; onClose: () => void }) {
  const doc = useMemo(() => buildPreviewDoc(result), [result]);
  const parts = useMemo(() => dissect(result.payload), [result]);
  const list = useMemo(() => findings(result), [result]);
  const owner = realOwner(result.payload);
  const [confirm, setConfirm] = useState(false);
  const isWeb = /^https?:\/\//i.test(result.payload) || (result.isUrl && !/^[a-z]+:/i.test(result.payload));

  return (
    <div role="dialog" aria-modal="true" aria-label="Safe preview" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-md" onClick={onClose}>
      <div className="glass fade-up max-h-[92vh] w-full max-w-5xl overflow-y-auto p-5 md:p-7" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Safe preview · isolated sandbox</p>
            <h2 className="font-serif text-3xl">What this link would show you</h2>
          </div>
          <button onClick={onClose} className="chip px-3 py-1 text-xs text-muted-foreground">Close ✕</button>
        </div>

        <div className="mt-5 grid gap-5 md:grid-cols-[1.2fr_1fr]">
          <div className="overflow-hidden rounded-2xl border">
            <div className="flex items-center gap-2 border-b px-3 py-2">
              <span className="h-2.5 w-2.5 rounded-full bg-destructive" /><span className="h-2.5 w-2.5 rounded-full bg-warn" /><span className="h-2.5 w-2.5 rounded-full bg-ok" />
              <p className="ml-2 min-w-0 flex-1 truncate rounded-md border px-2 py-1 font-mono text-[11px]">
                {parts.map((p, i) => (
                  <span key={i} className={p.danger ? "text-destructive underline decoration-wavy" : p.kind === "domain" ? "font-bold text-foreground" : "text-muted-foreground"}>{p.text}</span>
                ))}
              </p>
            </div>
            <iframe title="Sandboxed simulated page" sandbox="" srcDoc={doc} referrerPolicy="no-referrer" className="block h-[380px] w-full" />
          </div>

          <div>
            <h3 className="font-serif text-xl">Anatomy of the link</h3>
            {owner && <p className="mt-1 text-sm text-muted-foreground">Real owner: <span className="font-mono text-foreground">{owner}</span></p>}
            <ul className="mt-3 space-y-1.5">
              {parts.map((p, i) => (
                <li key={i} className="flex gap-3 text-xs">
                  <span className="w-20 shrink-0 font-mono uppercase tracking-wider text-muted-foreground">{p.kind}</span>
                  <span className="min-w-0 flex-1">
                    <span className={`break-all font-mono ${p.danger ? "text-destructive" : ""}`}>{p.text}</span>
                    {p.danger && <span className="block text-muted-foreground">{p.danger}</span>}
                  </span>
                </li>
              ))}
            </ul>

            <h3 className="mt-6 font-serif text-xl">Why it's dangerous</h3>
            {list.length === 0 ? (
              <p className="mt-2 text-sm text-ok">No red flags found in this link.</p>
            ) : (
              <ol className="mt-2 space-y-2">
                {list.map((f, i) => (
                  <li key={f.title} className="rounded-xl border px-3 py-2">
                    <p className={`text-sm font-medium ${f.severity === "high" ? "text-destructive" : f.severity === "medium" ? "text-warn" : ""}`}>{i + 1}. {f.title}</p>
                    <p className="text-xs text-muted-foreground">{f.detail}</p>
                  </li>
                ))}
              </ol>
            )}

            {isWeb && (
              <div className="mt-6">
                {!confirm ? (
                  <button onClick={() => setConfirm(true)} className="chip w-full py-2.5 text-xs text-muted-foreground">I understand the risk — open anyway</button>
                ) : (
                  <a href={/^https?:/i.test(result.payload) ? result.payload : `http://${result.payload}`} target="_blank" rel="noopener noreferrer nofollow"
                    className="block w-full rounded-full border border-destructive py-2.5 text-center text-xs text-destructive">
                    Really open {owner ?? "this link"}? Tap again to continue
                  </a>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
