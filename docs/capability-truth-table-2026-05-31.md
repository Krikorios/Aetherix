# Aetherix Capability Truth-Table (verified 2026-05-31)

**Method:** Code read at file:line + **tests executed in a real environment**
(Docker Postgres 16 on :55432; Python venv; Rust cargo). This supersedes earlier
snapshots where claims outran code.

**Verification status of the test suites (run by PM, not just claimed):**
- **API:** `pytest -q` → **278 passed, 1 skipped** against real Postgres. ✅ run
- **Agent:** `cargo test` on the **committed tree** → lib **131 passed**;
  integration suites pass (`edr_detector_integration` 12, `file_upload_block` 2,
  `clipboard_block` 2, `policy_hot_reload` 2); 0 failures across **5 consecutive
  PM runs**. ✅ run. NOTE: one background agent run reported a
  `edr::rollback::persistence` parallelism flake (12 fails) — **PM could not
  reproduce it on committed code**; likely caused by that agent's in-progress
  edits or env. Treat as "watch", not confirmed.
- **Console:** after `npm install`, **verified by PM**: `build` clean (0 errors),
  `lint` **0 errors / 153 warnings**, **28/28 unit tests pass**. ✅ run.
  The earlier "~165 lint errors" were a **missing-`node_modules` artifact**, not
  real errors. Caveat: the eslint config sets `no-explicit-any`, `no-unused-vars`,
  `set-state-in-effect`, `purity` to `"warn"`, so "0 errors" partly reflects
  severity config; the 153 warnings are real quality issues (62 `any`, 48 unused,
  31 setState-in-effect, …).

---

## Legend
- **REAL** — code performs the operation AND a test exercises it.
- **REAL-NT** — code performs the operation but no/weak test, or a correctness gap.
- **PARTIAL** — real logic for part; a material piece is stub/hardcoded/missing.
- **STUB** — records intent/returns shape but does not perform the operation.
- **MISSING** — claimed somewhere but not implemented.

---

## Endpoint Agent (`agent/`)

| Capability | Verdict | Evidence | Notes |
|---|---|---|---|
| Process kill (Unix) | **REAL-NT** | `src/edr/response.rs:664` real `libc kill` SIGTERM + sysinfo fallback; self-kill guard | **Committed code returns success the instant SIGTERM rc==0 — does not verify the process actually died.** Only test is `kill_refuses_current_process` (no spawn-and-kill test). Overclaim in detail. |
| Process kill (Windows) | **PARTIAL** | `src/edr/response.rs:697` uses sysinfo `process.kill()` | Committed code does **not** call `TerminateProcess` directly despite docs. |
| Quarantine (AES-256-GCM + Argon2id, move, restore, integrity) | **REAL** | `response.rs:271-405` real encrypt/move/decrypt + sha256 verify | Integration test `test_quarantine_action` removes original, restores, verifies. |
| Network isolation / firewall | **STUB** | `response.rs:~220` records "isolation-intent"; explicit `TODO` firewall backend | Returns Executed but applies **no** firewall rule. Honesty risk. |
| VSS rollback: probe / list / simulate / restore copy-out | **REAL (Windows-only, CI-unverified)** | `src/edr/rollback/vss.rs` real WMI probe, enumerate, dry-run simulate, real copy-out + hash verify | Entire module `#![cfg(windows)]` — **does not run on Linux CI**. Real path covered only by `#[ignore]`d Windows-admin test. Do not mark "restore complete". |
| FIM (notify + sha256) | **REAL** | `src/fim/mod.rs` real watcher + hashing | |
| YARA-x scanning | **REAL (no bundled rules)** | `src/edr/yara_scan.rs` real engine, cache, limits | Rules delivered by control plane; agent ships **zero signatures**. |
| Process-tree monitoring | **REAL** | `src/edr/process_tree.rs` sysinfo polling | |
| IOC matching | **PARTIAL** | `src/edr/ioc.rs:22-43` real set-match but **hardcoded test IOCs**, no feed refresh | |
| Ransomware canary/entropy/mass-write | **REAL** | `src/edr/ransomware.rs` + tests | Defaults to Monitor (safe). |
| DLP clipboard overwrite (block) | **REAL** | `src/interceptors/clipboard.rs:110` arboard set_text + integration test | |
| DLP file-upload block (delete) | **REAL** | `src/interceptors/file_upload.rs:232` + integration test | |
| USB | **PARTIAL** | `src/interceptors/usb.rs` detect+emit only | No enforcement/block. Monitoring masquerading as "interception". |
| Policy gating + hot-reload | **REAL** | `src/policy/mod.rs` + integration test | Real HTTP fetch + disk cache + version swap. |
| Enrollment + signed HMAC heartbeats | **REAL** | `src/main.rs` enroll + HMAC-SHA256 nonce | |

> Note: audit Agent A produced an **uncommitted** fix that (a) verifies actual
> termination before reporting success, (b) adds direct Windows `TerminateProcess`,
> and (c) adds real spawn-and-kill tests — full `cargo test` passed with it applied.
> It was reverted to respect manual mode (your agents own code). Re-create via the
> Agent-A brief if wanted.

---

## Backend (`apps/api/`) — 278 pytest pass / 1 skip (real Postgres)

| Capability | Verdict | Evidence | Notes |
|---|---|---|---|
| Accounts persistence + RBAC + tenant scoping | **REAL** | tables `db.py:1133/1155`; endpoints `main.py:3731-3983`; `test_tenancy.py` (21 tests) | Platform Owner→MSP Partner→Company enforced via `require()`. |
| JWT sessions (HS256) | **REAL (dev-grade)** | `services/jwt_tokens.py` | Code itself flags "swap to RS256 before scale"; needs `AETHERIX_JWT_SECRET` to survive restart. |
| Password hashing (PBKDF2-SHA256 600k) | **REAL** | `services/passwords.py` | |
| TOTP / 2FA | **REAL** | `services/totp.py` (RFC 6238) | Light dedicated test coverage. |
| Impersonation (dual-actor, audited) | **REAL** | `services/impersonation.py`; `test_impersonation.py` | |
| OAuth2 / SSO | **PARTIAL** | tables + CRUD in `tenancy.py:977+`; **no `/oauth2/authorize`/`callback` flow** | "SSO support" is schema-only today. Docs overclaim. |
| Row-Level Security | **PARTIAL** | 12/14 tenant tables have RLS | **`module_actions` & `endpoint_quarantine_inventory` lack RLS** — app-layer `require()` only. Defense-in-depth gap. |
| Correlation (FIM↔EDR, DLP↔EDR, sha256/path/endpoint, uplift) | **REAL** | `services/correlation.py`; `test_correlation_fim_edr.py` (11), `test_correlation_dlp_edr.py` (10), `test_correlation_rollback.py` | Synchronous at write-time. |
| DLP scanning (Presidio + regex + semantic) | **REAL** | `services/dlp.py`, `semantic.py`; multiple tests | Presidio optional; deterministic rules authoritative. |
| Semantic/GenAI risk scoring | **REAL (LLM optional)** | `semantic.py:173+` BYO-key, quota, PII redact, graceful fallback | |
| Agentic AI | **PARTIAL** | `services/agentic.py` case CRUD + visibility | **No LLM orchestration/step execution.** "Agentic" naming overclaims. |
| Policy engine v2 (version/simulate/promote, entitlements) | **REAL** | `policy_v2.py`; `test_policy_v2.py` (12), `test_policy_v2_e2e.py` | Simulation is DB-rule eval, not live fleet rescan. |
| Remote EDR queue (quarantine list/restore, approve/deny, dual-op) | **REAL** | `main.py:1477+`; `test_remote_quarantine_actions.py` (10) | Severity-gated approvals. |
| Compliance engine (catalogue, write-time tagging, attestations, signed + PDF export) | **REAL** | `services/compliance.py`; `test_compliance_*` | HMAC (shared-key) signature, not asymmetric PKI. |
| Schema management | **REAL (bootstrap, not Alembic-run)** | `db.py init_schema()` ~140 idempotent DDL stmts | Alembic dir exists but live schema is bootstrapped; `alembic upgrade head` errored in my run (test DB already bootstrapped). Reconcile before prod rolling upgrades. |

---

## Console (`apps/console/`) — build/lint/tests run & verified by PM (after npm install)

| Area | Verdict | Evidence | Notes |
|---|---|---|---|
| Build | **CLEAN** | `npm run build` 0 errors (verified) | `AntimalwareBehavior.tsx`/`EASMPage.tsx` compile clean. |
| Lint | **0 errors / 153 warnings** | `npm run lint` (verified) | "~165 errors" was a missing-deps artifact. Warnings = real quality debt (see below), classified `warn` by config. |
| Unit tests | **28/28 PASS** | `npm run test` (verified) | But only ~2/38 pages covered (API mocked). |
| Backend wiring | **MOSTLY REAL** | ~22/36 pages use real `apiGet/apiPost`; ~12 MIXED (real fetch + mock fallback) | Dashboard, Policy*, Quarantine, Accounts, Compliance, Companies, Alerts wired. |
| Mock data in components | **RISK (warns)** | ~31 `Date.now()` in component bodies (e.g. `AntimalwareBehavior.tsx:65`, `ExecutiveSummaryPage.tsx:69,197`) | Synthetic timestamps; Exec Summary uses Date.now() in calcs. |
| Raw error leakage to users | **PARTIAL** | The 3 specific items (Exec Summary footer, Compliance raw JSON, Queue "Not Found") are **resolved**; `api.ts` humanizes Pydantic errors. BUT ~91 sites still render `err.message` directly | Worst offenders fixed; broad pattern remains as polish. |
| Nav↔title mismatches | **RESOLVED** | nav labels match page H1s (verified by two audits) | Earlier mismatch list already fixed in a prior sprint. |
| Placeholder add-on pages in nav | **UX** | EmailSecurity/MobileSecurity/Sandbox are static AddOnPage | Nav implies availability. |
| Lint quality debt | **OPEN** | 153 warnings: 62 `any`, 48 unused-vars, 31 setState-in-effect, 6 purity, 4 exhaustive-deps, 2 only-export | Not blocking; worth burning down. |

---

## Top honesty risks to fix before any pilot/demo
1. **Process-kill (Unix) reports success without confirming death; Windows isn't direct TerminateProcess; no spawn-and-kill test.** (agent)
2. **Network isolation is a stub** but returns Executed. (agent)
3. **OAuth2/SSO is schema-only** — no real flow. (backend/docs)
4. **RLS missing on `module_actions` + `endpoint_quarantine_inventory`.** (backend)
5. **"Agentic AI" is case CRUD, not an AI agent.** (backend/docs)
6. **IOC feed is hardcoded test data; YARA ships no rules.** (agent)
7. **Console: ~91 raw `err.message` sites + ~31 mock `Date.now()` timestamps** (the
   3 worst-offender pages are already fixed; this is the broad pattern / 153 lint
   warnings). Build/lint/tests are green. (console)
8. **Possible agent test parallelism flake** (persistence) — reported once, not
   reproduced by PM on committed code; verify on your CI before trusting. (agent)
9. **No signed release shipped yet** (pipeline exists, untriggered). (release)
```
```
