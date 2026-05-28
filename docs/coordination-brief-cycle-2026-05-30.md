# Aetherix Coordination Brief – Cycle 2026-05-30

**Cycle Focus:** Correlation consumption in console + sha256 deepening + rollback planning  
**Date:** May 30, 2026  
**Author:** Central Task Coordinator (Grok)

---

## 1. What landed this cycle

### Agent 2 — Console now surfaces correlation evidence

The alert list view (`AlertsPage.tsx`) has been augmented with two correlation affordances:

1. **Uplift badge**: Every alert row with `severity_uplifted_from` now renders a small "↑ {original_severity}" label next to the severity badge, giving operators immediate visual feedback that the alert was auto-uplifted by the correlation engine.
2. **Expandable correlation detail**: Clicking an alert row expands an inline detail panel that:
   - Fetches `GET /security-alerts/{id}/correlations` on expand.
   - Displays the before/after severity with an "auto-uplifted" callout.
   - Groups supporting signals by correlation type (file_path_match, sha256_match, process_path_match).
   - Shows file paths, event types, SHA-256 hashes, and relative timestamps for each supporting signal.
3. **New types**: `CorrelationLink`, `CorrelationResponse`, and `severity_uplifted_from` field added to the `Alert` type in `api.ts`.

### Agent 3 — Correlation engine deepened with sha256_hash matching

The correlation engine (`app/services/correlation.py`) now matches on **both** file_path **and** sha256_hash in both directions:

- `correlate_new_edr_alert()`: Queries `fim_events` by file_path_norm AND sha256_hash (deduplicating by FIM event id). When both path and hash match, uses `sha256_match` as the correlation type.
- `correlate_new_fim_event()`: Accepts an optional `sha256_hash` parameter. Checks each candidate `security_alert` payload for `file_sha256` or `sha256_hash` and creates `sha256_match` links when hashes align.
- **DLP groundwork**: New `dlp_events` table created in `db.py` with indexes on `(customer_id, observed_at)` and `sha256_hash`. DLP scan results are now persisted via `persist_dlp_event()` in `state.py`. The `related_kind` check constraint on `correlation_links` extended to include `'dlp_event'`. `dlp_events` added to `_CUSTOMER_CHILD_TABLES` for transactional hard-delete.
- **Tests**: 2 new test cases covering sha256_match (forward and reverse directions). **199 tests pass** (was 197).

### Agent 1 — Rollback planning advanced

`docs/edr-ransomware-rollback-interface.md` extended with a concrete 3-phase implementation sequence:

- **Phase 1 (this cycle)**: `RollbackProvider` trait scaffolding, no-op fallback provider, canary-driven recovery-point hints, `rollback_readiness` signal in heartbeat.
- **Phase 2 (next cycle)**: Handle `rollback` action in `response.rs`, validation of approved intents, idempotency enforcement via consumed-IDs file.
- **Phase 3 (next+1)**: `simulate_restore()` implementations per OS provider, `FimHint` emission for correlation-fast-path.

---

## 2. Integration points

| Track | Delivers | Consumed By | Status |
|-------|----------|-------------|--------|
| Agent 3: sha256 correlation | `sha256_match` links + `dlp_events` table | Agent 2 console detail panel | Delivered |
| Agent 2: correlation console UI | Uplift badge + expandable correlation detail | Operators (human) | Delivered |
| Agent 3: DLP events persistence | `dlp_events` rows on every scan | Future DLP↔EDR correlation | Delivered (foundation) |
| Agent 1: rollback phases | Planning doc with phased implementation | Agent 1 next cycle | Planning complete |

---

## 3. Non-negotiable constraints reaffirmed

- Deterministic before probabilistic — maintained (sha256 matching is exact, SQL-only).
- Evidence by construction — new sha256 correlation links carry `correlation.severity_uplift` evidence events.
- Default monitor / opt-in enforce — rollback planning explicitly keeps monitor/review default.
- Tenant isolation — `_CUSTOMER_CHILD_TABLES` updated for `dlp_events`.
- No weakening of audit spine — DLP events table is additive, does not replace evidence_events.

---

## 4. Next cycle recommendation

1. **Agent 2**: Wire correlation detail into the AntimalwareBehavior detail panel (`DetailPanel.tsx`) for the protection module workspace pattern, so operators see correlation evidence alongside detection telemetry in the three-panel layout.
2. **Agent 3**: Wire actual DLP↔EDR correlation (`correlate_new_edr_alert` checking `dlp_events` by endpoint_id + observed_at proximity, and `correlate_dlp_event` for the reverse). Add process_path_hash matching as a third correlation type.
3. **Agent 1**: Begin Phase 1 implementation — `RollbackProvider` trait + `NoopRollbackProvider` + canary-driven recovery point hints.

Reference: `multi-agent-coordination-protocol.md`, `current-capabilities-snapshot-2026-05-29.md`, `console-ui-audit-2026-05-28.md`.

> **Console UI note for Agent 2**: A full 34-item UI consistency audit was completed on 2026-05-28 (`docs/console-ui-audit-2026-05-28.md`). Two parse errors (AntimalwareBehavior.tsx, EASMPage.tsx) are P0 blockers for demos. Seven nav↔page-title mismatches and three instances of raw backend content visible to users are P1. Address P0 and P1 items alongside the correlation wiring work this cycle.
