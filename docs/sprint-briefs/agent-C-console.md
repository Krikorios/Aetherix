# Sprint 2 Brief — Agent C (Console)  [re-baselined 2026-05-31]

You own ONLY `apps/console/`. Do not edit other dirs. Do not run git.
Nothing is done unless it builds AND lints clean. Fix lint properly (no blanket
rule-disabling).

Setup: `npm install` then `npm --workspace apps/console run build` /
`run lint` / `run test`. Capture real baselines first — **do NOT trust the repo's
`lint_output.txt` (stale, from another machine).** Earlier "syntax errors" and
"nav↔title mismatches" appear already resolved; verify, don't assume.

## Tasks (priority order)
1. **Stop leaking raw backend errors to users (~91 sites).** Pattern
   `setError(err instanceof Error ? err.message : …)` renders backend/Pydantic/HTTP
   text to end users (e.g. `CompliancePage.tsx:210`, `QuarantinePage.tsx`,
   `BlocklistPage.tsx`, `PolicyPage.tsx`). Introduce a shared error-display helper
   that shows a safe user message and logs the detail to console only. Apply across
   pages.
2. **Remove mock/synthetic data from component bodies (~31 `Date.now()` across
   ~20 files).** Especially `ExecutiveSummaryPage.tsx:69,197` (Date.now() in
   calculations — audit-accuracy risk) and `AntimalwareBehavior.tsx:65`. Replace
   mock fallbacks with real backend data or explicit empty states (no fabricated
   timestamps shown as real).
3. **Clarify locked add-on pages.** EmailSecurity / MobileSecurity / Sandbox render a
   static AddOnPage but sit in nav as if available. Visually mark them as
   locked/upsell so users aren't misled.
4. **Clean lint + build to zero errors** and keep unit tests green. Reduce `any`
   usage (~25 sites) where reasonable.
5. **Add tests for the highest-traffic wired pages** (Dashboard, PolicyPage,
   QuarantinePage) beyond the current ~2/38 coverage.

## Final report (verbatim)
real `npm run build` and `npm run lint` before/after counts; the shared error
helper + how many call-sites converted; mock-data removals (file:line); add-on
labeling; new tests; anything unfixed + why.
