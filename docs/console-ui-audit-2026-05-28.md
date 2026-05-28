# Aetherix Console UI Audit — May 28, 2026

**Scope:** All 29 pages across all sidebar nav sections, reviewed via live browser session.  
**Method:** Read-only — no code changes made. Screenshots taken of every page.  
**Status:** Working checklist — items should be marked **[DONE]** and committed as they are resolved.

---

## How to use this doc

Each finding has a priority:
- **P0** — Blocks production demo / exposes developer internals to end users
- **P1** — Naming or labelling mismatch that confuses navigation
- **P2** — Visual/structural inconsistency that degrades perceived quality
- **P3** — Polish / minor copy issue

---

## Section A — Build Errors (Vite HMR Overlays)

These two source files have syntax parse errors that trigger a full-screen red Vite overlay during dev/preview. Press **Escape** to dismiss. Must be fixed before any demo session.

| # | File | Error | Priority | Status |
|---|------|-------|----------|--------|
| A-1 | `apps/console/src/pages/AntimalwareBehavior.tsx` | Unexpected token / missing closing brace near EOF | **P0** | [DONE] |
| A-2 | `apps/console/src/pages/EASMPage.tsx` | `PARSE_ERROR` at line 406:1 — unexpected `}` | **P0** | [DONE] |

---

## Section B — Raw Developer / Backend Content Exposed to Users

These are the most critical user-facing quality issues — internal strings visible to logged-in MSP admins.

| # | Page | Issue | Priority | Status |
|---|------|-------|----------|--------|
| B-1 | Executive Summary | Footer contains raw references: `` `ai_reports` table ``, `/companies`, `/alerts` routes | **P0** | [DONE] |
| B-2 | Compliance Center | Raw JSON validation error displayed on the page: `[{"type":"missing","loc":["query","source_table"],"msg":"Field required","input":null}]` | **P0** | [DONE] |
| B-3 | Queue | "Not Found" backend error rendered as a prominent alert banner inside the page body | **P0** | [DONE] |
| B-4 | Configuration | Developer note reads: *"Branding is resolved live from the `/me` endpoint…"* — raw API path in inline `<code>` tag visible to MSP admins | **P1** | [DONE] |

---

## Section C — Nav Label vs. Page Title Mismatches

The sidebar shows one name; the page H1 shows another.

| # | Nav Item | Page H1 | Delta | Priority | Status |
|---|----------|---------|-------|----------|--------|
| C-1 | Threats Xplorer | DLP Scanner | Completely different product term | **P1** | [DONE] |
| C-2 | Web & Email Protection | Web Protection & GenAI Guardrails | Adds "GenAI Guardrails", drops "Email" | **P1** | [DONE] |
| C-3 | Compliance Center | Compliance Evidence Engine | Different product framing | **P1** | [DONE] |
| C-4 | Companies | Companies + Licensing | Adds "+ Licensing" | **P2** | [DONE] |
| C-5 | Installers | Installation packages | Different phrasing | **P2** | [DONE] |
| C-6 | Sandbox Analyzer | Threat Sandbox | Different product name | **P1** | [DONE] |
| C-7 | Agentic AI Investigation | Agentic AI | Title truncated | **P2** | [DONE] |

---

## Section D — Shared Generic Panel Heading Across Multiple Pages

The three-panel board uses the same static heading **"Detections & Rules Security Alerts / Incident Context & Analysis / Response Action Hub"** verbatim on all of the pages below. The first panel heading "Detections & Rules Security Alerts" does not adapt to page context.

Affected pages (6): Blocklist, Custom Rules, Antimalware & Behavior, Web & Email Protection, Digital Risk (DRP), External Attack Surface (EASM).

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| D-1 | Panel heading "Detections & Rules Security Alerts" used on EASM, DRP, Web & Email, Blocklist, Custom Rules — should be context-specific per module | **P2** | [DONE] |

See `docs/protection-module-template-guide.md` for the shared component origin.

---

## Section E — Cross-Section Labelling

| # | Page | Issue | Priority | Status |
|---|------|-------|----------|--------|
| E-1 | Policy Assignments | Subtitle label reads "MSP Governance" but the page lives under the **PROTECTION** nav section | **P2** | [DONE] |

---

## Section F — Missing / Inconsistent Context Labels

Most pages show a small category label above the H1 (e.g., "ENDPOINT THREAT PROTECTION", "MSP Control"). The pages below are missing this or use a mismatched format.

| # | Page | Issue | Priority | Status |
|---|------|-------|----------|--------|
| F-1 | Network | No category label above "Network" H1 | **P3** | [ ] |
| F-2 | Installers | No subtitle/category label above "Installation packages" H1 (other MSP CONTROL pages have one) | **P3** | [ ] |
| F-3 | Queue | Category label reads "MSP Control" (mixed-case) while the nav section heading is "MSP CONTROL" (all-caps) | **P3** | [ ] |

---

## Section G — ADD-ONS & INTEGRATIONS Layout Inconsistency

The section mixes two fundamentally different page types with no nav-level visual distinction.

| # | Issue | Affected Pages | Priority | Status |
|---|-------|---------------|----------|--------|
| G-1 | Locked add-on upsell cards (Sandbox Analyzer, Email Security, Mobile Security) look identical in the nav to fully functional pages (Data Insights, Integrations, Configuration) — users can't tell which are active | **P2** | [ ] |

---

## Section H — Typographical & Grammar Errors

| # | Page | Error | Priority | Status |
|---|------|-------|----------|--------|
| H-1 | Executive Summary | "1 agents" — should be "1 agent" | **P2** | [DONE] |
| H-2 | Compliance Center | Subtitle reads "Govemanee, Risk & Compliance" — should be "Governance, Risk & Compliance" | **P1** | [DONE] |
| H-3 | Compliance Center | Version badge shows "v0.5 v0.5" — version rendered twice | **P2** | [DONE] |

---

## Section I — Policy State Inconsistency

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| I-1 | Quarantine shows policy version **v2.10.4** while Device Control and other Protection pages show **"No active assignment"** — inconsistent policy state across the same nav section with no explanation | **P2** | [ ] |

---

## Section J — Configuration Page Specific Issues

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| J-1 | "Save Changes" button is disabled but renders with full blue fill — disabled buttons should be visually muted/grayed | **P2** | [DONE] `styles.css` — added `.btnPrimary:disabled` override after the `:hover` rule block |
| J-2 | Footer Note field pre-filled with `© 2024 Aetherix MSP Platform…` — year is stale (2024 vs 2026) | **P2** | [ ] |
| J-3 | Primary Color and Accent Color both show the same value `#0b6b57` — the two pickers are visually indistinguishable in current state | **P3** | [ ] |
| J-4 | Logo URL shows placeholder text `https://cdn.example.com/logo.svg` — field appears filled rather than empty | **P3** | [ ] |
| J-5 | Configuration placed under ADD-ONS & INTEGRATIONS nav section — it covers platform-wide settings (white-label, branding, support contacts) and belongs in a top-level Settings/Administration section | **P2** | [ ] |

---

## Section K — Dashboard

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| K-1 | "No active policy" appears as unstyled plain paragraph text at the top of the content area — should be a styled status badge or alert banner | **P2** | [DONE] `Dashboard.tsx` — added `<ErrorBanner>` after the existing error banner when `!policy && !isLoading` |

---

## Section L — Data Insights

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| L-1 | DLP Events (30d) and Blocked (30d) metric cards display red/orange warning triangle icons next to a value of `0` — warning iconography on zero counts is misleading | **P3** | [ ] |
| L-2 | "Avg AI Efficiency" shows 100% when Total Endpoints = 1 and Events = 0 — displaying 100% efficiency with zero events is nonsensical | **P2** | [ ] |

---

## Section M — Queue Page

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| M-1 | Dual redundant filter controls: a row of dark pill-shaped buttons (Queued, Awaiting Approval, Completed, etc.) AND a text tab bar immediately below with the exact same categories — both appear to do the same thing | **P2** | [DONE] `ActionQueuePage.tsx` — removed `queueFilterTabs` text tab bar; `queueSummaryBar` pill chips remain as the sole status filter |

---

## Summary by Priority

| Priority | Count |
|----------|-------|
| P0 (blocks demo) | 5 |
| P1 (navigation confusion) | 7 |
| P2 (quality/consistency) | 17 |
| P3 (polish) | 5 |
| **Total** | **34** |

---

## Resolution Workflow

When fixing an item:
1. Mark `[DONE]` next to the item in this checklist.
2. Reference this doc item ID (e.g. `C-1`) in the commit message.
3. Run `npm run build` to confirm no new Vite errors.
4. For backend-exposed strings (Section B), fix both the API response and the console error-display component.
