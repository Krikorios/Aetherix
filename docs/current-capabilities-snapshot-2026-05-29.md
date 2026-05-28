# Aetherix Current Capabilities Snapshot (May 29, 2026)

**Purpose**: Single source of truth for what is *actually delivered and wired* today. Use this alongside (or instead of) older snapshots in roadmap/poc-plan for design partners, investors, and new team members.

This reflects the state after the major May 2026 multi-agent development cycles focused on remote EDR response management.

---

## 1. Core Thesis — Delivered

**One signed agent + one control plane delivering native AV/EDR + DLP (including GenAI guardrails) + operator-controlled response + built-in compliance evidence.**

- **Not an aggregator**: Native collection, detection, response, and evidence (no reliance on Wazuh/GravityZone/Defender connectors for runtime operation).
- **Deterministic-first + evidence-by-construction**: All actions (autonomous or operator-driven) are policy-promoted, produce rich `ResponseEvidence`, and emit compliance controls at write time.

---

## 2. Endpoint Agent (Rust) — Strong "First Slice"

**Mature areas**:
- **EDR Detection**: Full YARA-x (with caching, metadata, limits), ransomware canaries + entropy + mass-write throttling, process tree monitoring (sysinfo + rules), FIM (notify-based + hashing), basic IOC.
- **Response Actions** (local + remote via `/agent/actions` queue):
  - Quarantine: AES-256-GCM + per-artifact Argon2id (unique salt + KDF metadata in manifest), chained manifests, reversible restore with integrity checks.
  - Kill: Cross-platform (Unix permission-checked SIGTERM + fallback; Windows TerminateProcess). Self-kill protection.
  - List (`quarantine_list`): Returns `QuarantineListItem[]` with `can_restore`, `severity_hint`, `approval_hint`, `restore_requires_approval`, hashes, etc.
  - Restore (`quarantine_restore`): Full lifecycle with evidence.
  - Isolate: Auditable intent + evidence (firewall enforcement still planned).
  - Rollback (`rollback` / `rollback_restore` / `rollback_simulate`): Full remote action dispatch with `RollbackProvider` trait, `NoopRollbackProvider`/`SimulationRollbackProvider`, intent verification (endpoint/tenant binding, expiry, field validation), idempotency guard with cached-evidence re-report, and `RollbackEvidence` return with per-path outcomes, provider details, and correlation links.
- **Policy Gating**: `RuntimePolicy` (hot-reloadable) maps detectors to actions (Monitor/Review default; enforcement only on promotion). Remote actions respect the same gates.
- **Other**: Real browser bridge (HTTP + native messaging), DLP enforcement (clipboard overwrite, file save blocking), inventory, basic CIS checks.

**Current marketing posture**: "Behavior & Anti-Ransomware" + strong remote containment (accurate). Not claiming full kernel AV or broad signature coverage yet.

**Gaps (explicitly still planned)**: Richer signatures/reputation, ML scoring (server-side), VSS rollback simulate/restore implementation, APFS/Btrfs providers (future), kernel-level telemetry, network isolation enforcement. (Note: Windows VSS provider probe/readiness and recovery-point listing paths are implemented.)

---

## 3. Control Plane — Remote EDR Management (Major 2026 Milestone)

**Fully delivered and wired** (May 27–29, 2026 cycles):
- Operator endpoints for remote quarantine control:
  - `POST /endpoints/{id}/quarantine-list`
  - `POST /endpoints/{id}/quarantine-restore` (severity-gated: high/critical → `awaiting_approval`; low/medium → `queued` based on tenant `quarantine_restore_approval` toggle)
  - Approve / Deny flows with distinct-operator enforcement and reason capture
  - `GET /endpoints/{id}/quarantine-inventory` (cached snapshot from agent)
  - `GET /endpoints/{id}/response-actions` (full history with agent `ResponseEvidence`)
  - Tenant-wide `/quarantine-restores/pending` inbox
- `module_actions` + `endpoint_quarantine_inventory` tables with proper upserts on agent acks/heartbeats.
- Full compliance evidence differentiation (operator request/approve/deny vs. agent execution paths) mapped to ISO/SOC2/NIST controls.
- Policy v2 EDR module support (detectors, responses, destructive gating).

This is **production-intent** operator-controlled remote response (not just agent-autonomous).

---

## 4. Console (React) — Protection Module Pattern + Real Wiring

**Established pattern** (used across Quarantine, Antimalware & Behavior, Web Protection, Device Control, Blocklist, Custom Rules, Risk, etc.):
- Consistent three-panel workspace (DetectionTable + DetailPanel + ActionStagingPanel)
- `StagedActionBadge` with states: queued / awaiting_approval / executed / failed / denied (server-driven)
- Shared `permissions.ts` helper + `hasPermission`
- Simulation + staging with destructive guards + confirmation modals

**Quarantine-specific (fully wired to live backend)**:
- Live remote inventory snapshots per endpoint
- Global "Approvals Inbox" tab using real pending restores endpoint
- Interactive Approve/Deny with self-approval warnings and mandatory denial reasons
- Restore staging enforces the exact locked severity-based approval model
- Response history wired to `StagedActionBadge` (executed/denied states from server)

**Other pages**: Use the same pattern with domain-specific remediation (behavior, web-protection, etc.). Many now pull real `/endpoints/{id}/response-actions`.

**Correlation-aware (May 30)**: Alert list now shows uplift badges and expandable correlation detail panel for FIM↔EDR cross-module joins. Severity auto-uplift events (low→medium, medium→high, high→critical) are surfaced to operators with supporting evidence grouped by match type (file_path, sha256).

**Gaps**: Correlation not yet wired into AntimalwareBehavior DetailPanel; some sidebar destinations still lighter; full impersonation UX and white-label still maturing; deeper MDM packaging deferred.

---

## 5. Compliance Evidence Engine — v0 Strong, v0.5 In Progress

**Delivered**:
- Control catalogue (ISO 27001:2022 Annex A, SOC 2 TSC 2017, NIST CSF 2.0, GDPR, HIPAA)
- Write-time `evidence_controls` tagging on audit, alerts, policy documents, *and all operator + agent response actions* (including the new remote quarantine paths)
- Signed JSON export (`/compliance/export`)
- Recent extension of mappings to cover the full operator lifecycle (list_requested, restore_requested, restore_approved, restore_denied, agent.response_action)

**In progress / planned (v0.5)**:
- Evidence review workflow
- Attestations
- PDF export
- Object-store references for large artifacts

---

## 6. Multi-Tenancy & Auth

**Strong application-layer isolation**:
- MSP hierarchy (Platform Owner → MSP Partner → Company roles)
- JWT bearer sessions (production path)
- Explicit per-endpoint customer scoping + permission checks on all new remote EDR routes
- Dual-operator enforcement for high/critical restores

**Known hardening item**: RLS policies on the newest tables (`module_actions`, `endpoint_quarantine_inventory`) rely more on app-layer checks than full row-level security (defense-in-depth gap noted in architecture).

---

## 7. What We Still Do Not Claim (Accurate as of May 29, 2026)

- Kernel-mode AV / minifilter / ETW depth
- Full automated ransomware rollback (Windows VSS provider probe/readiness and recovery-point listing paths implemented; VSS simulate/restore and APFS snapshot integration are planned)
- Production signed release pipeline (in active development)
- Complete DRP/EASM collectors (control plane surface exists; collectors scoped for next priority)
- Full DLP↔EDR correlation engine (FIM+EDR sha256 joins delivered; DLP events table created; DLP↔EDR wiring next)
- PDF evidence exports + formal attestation workflow (JSON + evidence events are strong)
- Mobile / cloud workload modules

These remain correctly listed in `native-security-gap-review.md` "What Aetherix Should Not Claim Yet".

---

## 8. How to Use This Snapshot

- **External readers** (design partners, investors): Start here + `architecture.md` + latest coordination brief.
- **Team / future agents**: This + `multi-agent-coordination-protocol.md` + the most recent `coordination-brief-cycle-*.md` give the true current state.
- **Sales / marketing**: "Behavior + Anti-Ransomware + Remote Operator-Controlled Containment with full audit trail and console approvals" is accurate and differentiated.

**Last major update**: May 30, 2026 (post correlation console consumption + sha256 deepening).

For the absolute latest cycle-by-cycle detail, see the living coordination briefs and `console-wiring-remote-edr.md`.
