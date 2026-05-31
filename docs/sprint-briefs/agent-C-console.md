# Sprint 1 Brief — Agent C (Console)

You are working on the **Aetherix** endpoint security platform. The repo is a
monorepo: a Rust endpoint agent (`agent/`), a FastAPI/Postgres backend
(`apps/api/`), and a React/Vite + TypeScript MSP console (`apps/console/`).

**You own ONLY the `apps/console/` directory.** Do not edit `agent/`, `apps/api/`,
or `docs/` (you may READ `docs/console-ui-audit-2026-05-28.md` for reference).

## Rules
- Nothing is "done" unless it builds AND lints clean. Do not overclaim.
- Do not run git. Leave your edits in the working tree.
- Fix lint issues properly — do not blanket-disable rules. Only use a targeted
  `eslint-disable` as a last resort, with a comment explaining why.
- Keep changes small and focused on the tasks below.

## Setup
- `npm install` (from repo root) if needed.
- Build: `npm --workspace apps/console run build`
- Lint: `npm --workspace apps/console run lint`
- Unit tests: `npm --workspace apps/console run test`
- Run build + lint FIRST to capture the baseline error counts.

## Tasks (in priority order)
1. **Clean build.** Fix any syntax/TypeScript errors that block
   `npm --workspace apps/console run build`. The audit historically flags
   `AntimalwareBehavior.tsx` and `EASMPage.tsx` — verify current state.
2. **Clean lint.** Resolve ALL ESLint errors (~165 reported). Common categories:
   unused imports, `any` types, `Date.now()`/`Math.random()` called in render or
   state initializers, and setState-within-effect.
3. **Remove raw backend/developer content shown to logged-in users** (per the audit):
   - Executive Summary footer exposes raw table/route names.
   - Compliance Center shows a raw JSON validation error.
   - Queue page shows a "Not Found" banner.
   Replace each with a user-appropriate empty/error state.
4. **Fix nav-item ↔ page-title mismatches** from the audit, e.g.:
   - "Threats Xplorer" nav → page titled "DLP Scanner"
   - "Sandbox Analyzer" nav → page titled "Threat Sandbox"
   - "Compliance Center" nav → page titled "Compliance Evidence Engine"
   Make the nav label and page title consistent.

Re-run build + lint + unit tests until build and lint are clean and tests pass.

## Required final report (paste this back to me verbatim)
- Changes made (`file:line`).
- `npm run build`: before vs after (error count / status).
- `npm run lint`: before vs after (error count).
- Unit test status.
- Anything you could NOT fix and why. Be precise and honest.
