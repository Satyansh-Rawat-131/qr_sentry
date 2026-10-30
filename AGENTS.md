<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- ML models are trained offline by `ml/train.py` and exported to `src/ml/*.json`; the browser runs inference and TreeSHAP in `src/lib/ml.ts`. Why: no server/Python at runtime. `src/lib/features.ts` must mirror `featurize`/`canonical` in train.py exactly — `src/test/ml.test.ts` enforces parity; retrain after changing either.
