# Sprint 2 Brief — Agent C (Console)  [re-baselined 2026-05-31, PM-verified]

You own ONLY `apps/console/`. Do not edit other dirs. Do not run git.

**PM-verified baseline (after `npm install`):** `build` clean (0 errors);
`lint` = **0 errors / 153 warnings**; **28/28 unit tests pass.** The old
"~165 errors" was a missing-`node_modules` artifact — NOT real errors. The 3
worst "raw developer content" pages (Exec Summary footer, Compliance raw JSON,
Queue "Not Found") and the nav↔title mismatches are ALREADY fixed. Do not redo
those. Do NOT trust the repo's stale `lint_output.txt`.

Setup: `npm install` (root), then `npm --workspace apps/console run build|lint|test`.

## Tasks (priority order) — this sprint is quality burn-down, not firefighting
1. **Burn down the 153 lint warnings to ~0**, fixing the underlying issues (not by
   flipping rules off):
   - 48 `no-unused-vars` (mostly unused `lucide-react` imports) — safe deletions.
   - 62 `no-explicit-any` — give real types; only `eslint-disable` with a comment
     where a third-party type genuinely forces it.
   - 31 `react-hooks/set-state-in-effect` + 6 `purity` + 4 `exhaustive-deps` — fix
     the effect/render patterns properly.
2. **Replace mock data shown as real (~31 `Date.now()` in component bodies).**
   Especially `ExecutiveSummaryPage.tsx:69,197` (Date.now() in calculations —
   audit-accuracy risk) and `AntimalwareBehavior.tsx:65`. Use real backend data or
   explicit empty states; never render a fabricated timestamp as if it were real.
3. **Generalize safe error handling (~91 `err.message` sites).** Add a shared
   helper that shows a user-safe message and logs detail to console only; convert
   the call-sites. (The 3 specific pages are done; this is the broad pattern.)
4. **Clarify locked add-on pages** (EmailSecurity / MobileSecurity / Sandbox) so nav
   visibly marks them locked/upsell rather than implying availability.
5. **Raise test coverage** on the highest-traffic wired pages (Dashboard,
   QuarantinePage) beyond the current ~2/38.

Acceptance: `build` 0 errors, `lint` 0 errors AND ≤ ~10 warnings, `test` green.

## Final report (verbatim)
real `build`/`lint`/`test` before→after (warning counts); the shared error helper +
sites converted; mock-data removals (file:line); add-on labeling; new tests;
anything unfixed + why.
