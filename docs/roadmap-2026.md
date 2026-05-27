# Aetherix Roadmap 2026 — From POC to Profitable MSP Platform

Status: planning, May 24, 2026. Companion to
[poc-plan.md](poc-plan.md),
[architecture.md](architecture.md),
[native-security-gap-review.md](native-security-gap-review.md),
[milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md),
[policy-engine.md](policy-engine.md), and
[default-policy-v1.01.md](default-policy-v1.01.md).

This document consolidates the engineering backlog and go-to-market
hierarchy into one prioritized roadmap. It does **not** change the
product direction set in [architecture.md §3.4.2](architecture.md) or the
six native development priorities in
[native-security-gap-review.md](native-security-gap-review.md); it
sequences them against the market plan so the team has one source of
truth for "what next" and the business has a path to revenue.

**Execution Model:** Development is executed using three specialized AI agents coordinated through the process defined in [multi-agent-coordination-protocol.md](multi-agent-coordination-protocol.md). All task assignment, review, and prompt synchronization is handled centrally by the Task Coordinator.

Nothing here invalidates the current POC. Everything is additive on top
of the implemented spine: Rust agent + FastAPI control plane + React MSP
console + Policy Engine v2 + Semantic DLP/GenAI Guardrails + MV3
extension + local bridge + Compliance Evidence Engine v0.

---

## 1. Strategy Recap (one paragraph)

Aetherix is not competing on malware-signature volume against
Bitdefender or Kaspersky. It is competing on three things those vendors
do **not** ship in one platform: (1) auditor-ready Compliance Evidence
mapped at write-time to ISO 27001 / SOC 2 / NIST CSF / GDPR / HIPAA;
(2) Semantic DLP + GenAI guardrails that understand prompts before they
leave the browser; (3) MSP-native multi-tenancy, licensing, white-label,
and Quick Deploy from day one. The market wedge is "BD + Vanta +
Nightfall + a GenAI firewall, in one signed agent, priced for MSPs."

This roadmap protects that wedge while closing the credibility gaps
listed in [native-security-gap-review.md](native-security-gap-review.md)
"What Aetherix Should Not Claim Yet".

---

## 2. Sequencing Principles

Carried over from existing docs, restated so every milestone obeys them:

1. **Deterministic before probabilistic.** Ship rule/signature/IOC
   baselines before any ML/LLM scoring becomes a decision input.
   ([architecture.md §1](architecture.md))
2. **Default monitor, opt-in enforce.** New detectors ship in `monitor`,
   move to `review`/`block` only after simulation evidence and operator
   approval. ([architecture.md §1](architecture.md),
   [policy-engine.md](policy-engine.md))
3. **Evidence by construction.** Every new event type must declare its
   `evidence_controls` mapping before merge. No detector lands without
   a control tag. ([architecture.md §3.4.2](architecture.md))
4. **One signed agent.** All module code lives in the same Rust binary;
   activation is gated by entitlements + policy, not by separate
   installers. ([native-security-gap-review.md](native-security-gap-review.md)
   "Deployment Packaging Notes")
5. **No production claim until production proof.** Auth, signed
   installers, real-site extension validation, kernel-mode hooks, and
   cargo-audit/Clippy in CI must precede any "production-ready"
   marketing. ([milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md)
   "Risks and Open Items")

---

## 3. P0 Backlog — Sellable POC (next 90 days)

Goal: 3 paying design-partner MSPs, signed reference installers, a
production auth surface, and an honest "behaviour + DLP + compliance"
SKU. No new strategic direction; all items already implied by
[native-security-gap-review.md](native-security-gap-review.md) and
[milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md).

### P0-1 Production authentication and session model
- **Why:** Console/API bearer-session auth is now the only auth path.
  Remaining production hardening is SSO and impersonation lifecycle
  completeness.
- **Scope:** Keep signed session tokens as the only path, keep MFA
  enforcement (TOTP), and add SSO/SAML/OIDC behind a feature flag for
  Phase 1.
- **Touches:** `apps/api/app/main.py` scope helpers (`_require_*`),
  new `app/services/sessions.py`, console `apps/console/src/auth/`,
  no schema break — `accounts`, `roles`, `account_roles`,
  `impersonation_sessions` already support it.
- **Exit:** All existing tests pass without the dev header path;
  impersonation start/end writes audit records as designed in
  [architecture.md §3.2.1](architecture.md).

### P0-2 Signed installer pipeline
- **Why:** [native-security-gap-review.md](native-security-gap-review.md)
  flags "signed release pipeline, auto-update, package assembly" as
  required for any future deployment. No MSP will deploy unsigned
  binaries.
- **Scope:** Windows Authenticode signing for the `.msi`, macOS
  notarized `.pkg`, Linux `.deb`/`.rpm` with detached signatures. Reuse
  existing installer build records and signed install profiles
  documented in [installers.md](installers.md).
- **Touches:** `agent/build-all.sh`, new `agent/packaging/`, CI signing
  job (GitHub Actions OIDC to a code-signing key vault), no API change.
- **Exit:** A customer can install on Win/macOS/Linux without OS
  security warnings; install profile + bootstrap token flow from
  [README.md](../README.md) "Current Implemented Flows" still works.

### P0-3 Native AV/EDR v0 (deterministic only)
- **Why:** Priority 4 in
  [native-security-gap-review.md](native-security-gap-review.md)
  "Native Development Priorities", but elevated to P0 because without a
  malware-flavoured detection the platform reads as DLP-only to
  procurement. Ship it deterministic-only; ML comes later.
- **Scope (per `agent/src/`):**
  - `agent/src/edr/process_tree.rs` — process parent/child capture
    (ETW on Windows, ESF on macOS, eBPF where available on Linux, with
    procfs polling fallback).
  - `agent/src/edr/yara.rs` — YARA scan of new executables and
    flagged paths using `yara-x` (pure Rust, no C dependency).
  - `agent/src/edr/ioc.rs` — hash/IP/domain IOC matching against a
    cached feed pulled from the control plane.
  - `agent/src/edr/ransomware.rs` — canary file watcher + entropy
    delta detector + mass-rename throttle, exactly as scoped in
    [native-security-gap-review.md](native-security-gap-review.md).
  - `agent/src/edr/response.rs` — `quarantine` / `kill` / `isolate`
    actions, all policy-gated and evidence-emitting.
- **Control plane:** new `apps/api/app/services/edr.py` ingest +
  `evidence_controls` mapping; new policy package section `edr` in
  the v2 schema (already provisioned for by
  [policy-engine.md](policy-engine.md) "subscription-aware modules").
- **Honesty rule:** market as **"Behavior & Anti-Ransomware"**, not
  "next-gen AV", until AV-Comparatives certification (P1-4).
- **Exit:** EICAR + a YARA rule + a ransomware-canary trigger each
  produce a `security_alerts` row with `evidence_controls` tags and a
  Compliance Evidence Engine export containing them.

### P0-4 Compliance Evidence Engine v0.5
- **Why:** This is the wedge. Priority 1 in
  [native-security-gap-review.md](native-security-gap-review.md). v0
  already exists ([architecture.md §7](architecture.md)); v0.5 is the version
  customers actually export and hand an auditor.
- **Scope:**
  - Control-review workflow (operator can mark an evidence item
    "reviewed", with reviewer + timestamp persisted).
  - Attestation records (CEO/CTO/CISO sign-off rows linked to
    framework + period).
  - PDF export rendered server-side from the existing signed JSON
    bundle; signature visible in the PDF metadata.
  - Object-store reference for large artefacts (filesystem-backed in
    POC, S3/Blob in Phase 1).
- **Touches:** `apps/api/app/services/compliance.py`, new
  `compliance_attestations` and `evidence_reviews` tables (Alembic
  revision), console "Compliance" page (already foundation) wired to
  the new endpoints.
- **Exit:** A demo tenant exports a signed PDF for ISO 27001:2022 +
  SOC 2 TSC 2017 covering a 30-day window with at least one reviewed
  evidence item and one attestation.

### P0-5 Real-site MV3 extension validation
- **Why:** Top open risk in
  [milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md)
  "Risks and Open Items". The GenAI Guardrail SKU cannot be sold
  without this.
- **Scope:** Run the existing extension end-to-end against
  ChatGPT, Claude, Gemini, and Copilot. Capture selectors that drift;
  add resilient DOM observers. No new architecture — the bridge,
  origin allow-list, and 256 KiB cap documented in
  [agent-semantic-dlp-enforcement.md](agent-semantic-dlp-enforcement.md) stay as-is.
- **Touches:** `apps/extension/content.js`, `apps/extension/test/`.
- **Exit:** Each of the four sites produces a `dlp-event` POST hitting
  the bridge with the expected `destination` field and an evidence
  row in the control plane.

### P0-6 CI hardening
- **Why:** [milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md)
  flagged `cargo-audit` and Clippy as not run in current environment.
- **Scope:** Add `cargo-audit`, `cargo clippy -- -D warnings`,
  `npm audit --audit-level=high`, and `pip-audit` to CI. Fix or
  document waivers for findings.
- **Exit:** Green CI badge in [README.md](../README.md); waivers
  tracked in `docs/security-waivers.md`.

### P0-7 Pricing + SKU matrix in the entitlement model
- **Why:** Sales motion requires SKUs. The entitlement plumbing exists
  (`subscriptions.core_features`, `ai_tier`, see
  [development.md](development.md)); SKUs do not.
- **Scope:** Define and seed three SKUs:
  - **Core** — Behavior + DLP deterministic + Compliance Evidence
    export. Price target $4/endpoint/mo wholesale.
  - **+GenAI** (Core add-on) — adds semantic DLP + extension + BYO
    AI. +$2/endpoint/mo.
  - **+CompliancePro** (Core add-on) — adds attestation workflow + PDF + extra
    framework packs (PCI-DSS, NYDFS, HIPAA Pro). +$2/endpoint/mo.
- **Touches:** `apps/api/app/db.py` seed (already idempotent for
  `ai_providers`; follow the same pattern for `subscriptions`),
  Companies + Licensing console page already renders core/add-ons
  ([companies.md](companies.md)).
- **Exit:** A new Company can be created on each SKU; policy package
  features gated correctly; ai_tier already gates BYO (keep that).

**P0 done = first invoice can be issued.**

---

## 4. P1 Backlog — Repeatable MSP Channel (3–9 months)

Goal: 25 MSP partners, ~$500k ARR, SOC 2 Type I on Aetherix itself.

### P1-1 Native SIEM/HIDS v0
Priority 3 in
[native-security-gap-review.md](native-security-gap-review.md):
log collectors (syslog / Event Log / journald), parser packs, FIM,
rootkit checks, software inventory + CVE/EPSS/KEV enrichment, MITRE
ATT&CK mapping, correlation rules. New policy section `siem_hids`.

### P1-2 Partner Portal polish + RMM/PSA integrations
White-label co-branding (Companies + Licensing already exposes the
hook, [companies.md](companies.md)), margin reports, ConnectWise
Manage / N-able / Kaseya / Pax8 marketplace listings, partner-facing
PDF compliance packs.

### P1-3 SOC 2 Type I on Aetherix
Eat-your-own-dogfood: use the Compliance Evidence Engine to gather
evidence for Aetherix's own SOC 2 audit. Publishable trust badge.

### P1-4 AV-Comparatives "Approved Business Product"
Submit Native AV/EDR v0 once IOC + YARA + ransomware canaries are
stable. This is the credential that removes the "AV-Lite" objection.

### P1-5 Threat-intel feed ingest
Ingest AlienVault OTX, Abuse.ch URLhaus, MISP feeds; expose to EDR
IOC matcher and to a tenant-scoped intel browser in the console.
Native module, not a connector, per
[poc-plan.md §1.1](poc-plan.md).

### P1-6 DRP + EASM v0
Move from the schemas/contracts state called out in
[milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md) to
real OSINT/DNS/CT-log collectors + console pages. Aligned with
[Aetherix EASM Implementation Prompt.md](Aetherix%20EASM%20Implementation%20Prompt.md).

### P1-7 Custom Detection Rules UI
Next planned protection module per
[milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md)
"Next Priorities" and
[protection-module-template-guide.md](protection-module-template-guide.md)
implementation guidance. Operator-authored
rules, simulation-gated, evidence-tagged.

---

## 5. P2 Backlog — Vertical SKUs + Managed Tier (9–18 months)

Goal: 100 partners, ~$3M ARR, AV-Comparatives badge live, MDR launched.

- **Vertical bundles:** Healthcare (HIPAA), Finance (PCI-DSS, GLBA,
  NYDFS), Legal (ABA + privilege DLP), AI Builders (GenAI-heavy).
  Pre-built policies + evidence mappings shipped as content packs;
  no schema changes.
- **Aetherix MDR:** managed-service tier at $12–18/endpoint/mo using
  the same console. New `mdr_` tables for shift handover, escalation,
  customer-facing case notes.
- **Agentic IR:** investigation graph + plain-English timeline,
  per [architecture.md §3.3](architecture.md) and
  [poc-plan.md §3.3](poc-plan.md). Strictly human-in-the-loop until
  P3.
- **Host firewall + anti-exploit + patch guidance** modules. Each is
  a separate policy section in the v2 schema, exactly as
  [native-security-gap-review.md](native-security-gap-review.md)
  "Deployment Packaging Notes" prescribes.

---

## 6. P3 Backlog — Platform + Ecosystem (18–36 months)

Goal: $8–15M ARR, EU expansion, optional Series A or bootstrapped.

- **Compliance Evidence API** for third-party GRC consumption.
- **Detection Marketplace** with revenue share on community
  rules/policy packs.
- **Geographic expansion:** EU first (GDPR + Kaspersky-avoidance
  tailwind), ANZ, LATAM. Avoid head-to-head US enterprise vs
  CrowdStrike/SentinelOne.
- **Mobile + cloud-workload modules** only if a paying customer
  drives them; otherwise stay scoped, per
  [native-security-gap-review.md](native-security-gap-review.md)
  "What Aetherix Should Not Claim Yet".

---

## 7. Pricing & Unit Economics (planning numbers)

| SKU | Wholesale $/endpoint/mo | COGS (est.) | Gross margin |
|---|---|---|---|
| Core | 4.00 | 0.40 | ~90% |
| +GenAI | +2.00 | +0.30 (LLM tokens, capped) | ~85% |
| +CompliancePro | +2.00 | +0.10 | ~95% |
| MDR (P2) | +12.00 | +5.00 (analyst time) | ~58% |

Target mix at 80,000 endpoints across 100 MSPs: $320k MRR Core + 30%
GenAI attach + 20% CompliancePro attach + 15% MDR attach ≈ **$8M ARR
at ~75% blended gross margin**.

These are planning numbers, not commitments. Adjust after first 3
design-partner contracts close.

---

## 8. Things Explicitly Out of Scope for 2026

Carried over from
[native-security-gap-review.md](native-security-gap-review.md) "What
Aetherix Should Not Claim Yet" — repeated here so they don't sneak
into a sales deck:

- Kernel-mode AV parity with Bitdefender / Kaspersky.
- Full SOAR orchestration.
- Mobile device management.
- Automated patch deployment (guidance only).
- SSL interception at network gateway.
- Proprietary signature-research network.

---

## 9. How This Roadmap Maps Back to Existing Docs

| Roadmap section | Source of truth in repo |
|---|---|
| P0-1 Production auth | [architecture.md §3.2.1](architecture.md) "Current state" |
| P0-2 Signed installers | [installers.md](installers.md), [native-security-gap-review.md](native-security-gap-review.md) "Single agent" row |
| P0-3 Native AV/EDR v0 | [native-security-gap-review.md](native-security-gap-review.md) Priority 4, [architecture.md §3.4.2](architecture.md) |
| P0-4 Compliance v0.5 | [native-security-gap-review.md](native-security-gap-review.md) Priority 1, [architecture.md §7](architecture.md) |
| P0-5 MV3 real-site | [milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md) "Risks and Open Items" #1 |
| P0-6 CI hardening | [milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md) "Risks and Open Items" #3 |
| P0-7 SKU matrix | [companies.md](companies.md), [policy-engine.md](policy-engine.md) "subscription-aware" |
| P1-1 SIEM/HIDS | [native-security-gap-review.md](native-security-gap-review.md) Priority 3 |
| P1-6 DRP + EASM | [Aetherix EASM Implementation Prompt.md](Aetherix%20EASM%20Implementation%20Prompt.md), [architecture.md §3](architecture.md) |
| P1-7 Custom Detection Rules | [milestone-summary-2026-05-23.md](milestone-summary-2026-05-23.md) "Next Priorities" #2 |
| P2 Agentic IR | [architecture.md §3.3](architecture.md), [poc-plan.md §2](poc-plan.md) pillar 3 |
| Sequencing principles | [architecture.md §1](architecture.md), [policy-engine.md](policy-engine.md) |

If anything in this roadmap conflicts with the linked source, the
source wins and this doc should be updated, not the other way around.
