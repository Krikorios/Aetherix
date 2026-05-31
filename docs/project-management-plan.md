# Aetherix Path-to-Production Plan

**North star:** design-partner pilot readiness, then production GA.
**First pilot OS:** Windows.
**Team model:** 3 working agents (A/B/C), split **by layer**, run concurrently, PM-reviewed.
**Last updated:** 2026-05-31

---

## 0. TL;DR

Aetherix is an **advanced prototype with a production-ready core**, not a demo.
Backend ~95% real, Rust agent ~80% real, real Postgres/Alembic, real CI. The two
things that can sink it are **docs overclaiming vs. code** and **market/trust risk**
(EDR is a distribution + certification game, not a features game).

The pilot bottleneck is **not** deep EDR. It is: nothing broken, nothing
overclaimed, a clean Windows install/demo path, and stable core flows.

Odds: fundable prototype / design-partner pilot **60–70%** if narrow + honest;
standalone "beat the incumbents" EDR business **10–15%** without funding + a sharp wedge.
Best wedge: **GenAI-DLP + compliance-evidence-by-construction for MSPs.**

---

## 1. Operating Model

### Agent ownership (fixed — prevents merge collisions)
| Agent | Owns | Directory |
| --- | --- | --- |
| **A — Agent** | EDR/DLP enforcement, response actions, VSS, telemetry | `agent/` |
| **B — Backend** | correlation, accounts persistence, RLS, auth, APIs | `apps/api/` |
| **C — Console** | lint/syntax, page wiring, UX, Windows install/demo path | `apps/console/` |

### Rules of engagement
1. **No overclaim.** A feature is ✅ only with code + a passing test. Otherwise 🔄 / ⚠️.
2. **One layer per agent.** Each agent edits only its directory. Cross-layer changes go through PM.
3. **Acceptance criteria on every task.** "Done" = criteria met + tests green + lint clean.
4. **Agents do NOT run git.** The PM (me) reviews diffs and handles all commits/merges/branches.
5. **Small, reviewable changes.** One concern at a time.

### Cadence
Sprint ≈ 1 focused cycle. PM assigns briefs → agents execute concurrently →
PM reviews diffs for correctness + honesty → commits per layer → updates status →
plans next sprint.

---

## 2. Sprint 1

| Agent | Tasks | Acceptance criteria |
| --- | --- | --- |
| **C (Console)** | Fix any build/syntax errors; remove raw backend/error content shown to users (Exec Summary footer, Compliance Center JSON error, Queue "Not Found"); clear lint errors; fix nav↔page-title mismatches. | `npm run build` clean, `npm run lint` 0 errors, no raw JSON/route names visible to users. |
| **B (Backend)** | Persist the **Accounts backend** (currently UI-only) with tenant scoping; wire **DLP↔EDR correlation** (FIM+EDR already done). | Accounts CRUD persists + tenant-scoped + tested; DLP events join into correlation with evidence + tests; `pytest -q` green. |
| **A (Agent)** | **Truth-up first:** implement process-kill syscalls (Unix SIGTERM / Windows TerminateProcess) with a test, OR downgrade the docs claim to ⚠️. Then continue Windows VSS restore copy-out with tests. | Kill works+tested or docs corrected; VSS progress has tests; no ✅ without code. |
| **PM** | Enforce no-overclaim on every merge; review all diffs; keep this doc + status current. | Status matches code reality. |

---

## 3. Definition of "Pilot-Ready" (Windows-first)

- [ ] Console builds clean, no broken pages, no raw errors shown to users.
- [ ] Windows signed installer / Quick Deploy path works end-to-end.
- [ ] Agent enrolls, heartbeats, pulls policy, reports real telemetry.
- [ ] Live flow: alerts → correlation → quarantine → approve/deny → audit trail.
- [ ] DLP + GenAI guardrail demo works on a real flow.
- [ ] Compliance evidence export produces a valid signed bundle.
- [ ] Accounts/RBAC persisted and enforced (not UI-only).
- [ ] Truthful capability one-pager (✅ shipped / 🔄 in progress / 📋 planned).

GA later adds: security review/pentest, SOC 2 prep, code-signing certs,
third-party efficacy testing, SSO/SAML, rate limiting, secrets management, RLS everywhere.

---

## 4. Risk Register (top items)

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Docs overclaim vs. code (trust killer) | High | No-overclaim rule; PM verifies every ✅ against code + test. |
| Market: incumbents converging | High | Lead with GenAI-DLP + compliance wedge, not raw AV. |
| Trust/certification cost (signing, SOC 2, efficacy) | High | Sequence as GA-only; raise funding before GA claims. |
| Single-maintainer bus factor | Medium | Keep this plan + status current; small reviewable PRs. |
| Agent response gaps (kill/isolate/VSS) | Medium | Truth-up docs now; implement + test incrementally. |
| Thin frontend test coverage | Medium | Add tests as pages are wired; gate merges on build+lint. |

---

*PM keeps this document current. Agents follow §1 rules and their per-sprint briefs in §2.*
