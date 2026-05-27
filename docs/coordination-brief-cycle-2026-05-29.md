# Aetherix Coordination Brief – Cycle 2026-05-29 (Agent 3 update)

**Cycle Focus:** Cross-module correlation (FIM ↔ EDR) — automatic severity uplift
**Date:** May 29, 2026
**Author:** Agent 3 (Control Plane + Console Foundations)

---

## 1. What landed this cycle

The control plane now correlates FIM and EDR signals at write time, so a YARA/IOC detection on a file path that the integrity monitor *also* touched inside the correlation window stops being two unrelated alerts and becomes one supported, uplifted alert with an auditable trail.

**Schema (db.py):**
- `fim_events(id, customer_id, agent_id, event_type, file_path, file_path_norm, sha256_hash, observed_at, created_at)` + index `(agent_id, file_path_norm, observed_at desc)`.
- `correlation_links(id, customer_id, security_alert_id→security_alerts ON DELETE CASCADE, related_kind, related_id, correlation_type, score, window_seconds, evidence jsonb, created_at)` + indexes on `(security_alert_id)` and `(related_kind, related_id)`.
- `security_alerts.severity_uplifted_from text` so the console can render "uplifted from high" badges and auditors can see the before/after.
- Both new tables added to `_CUSTOMER_CHILD_TABLES` so company hard-delete remains transactional.

**Engine (`app/services/correlation.py`):**
- `_normalize_path` lowercases and converts `\\`→`/` so Windows and POSIX agents join cleanly.
- `_SEVERITY_UPLIFT`: low→medium, medium→high, high→critical, critical stays.
- Window: `AETHERIX_CORRELATION_WINDOW_SECONDS`, default 600s.
- `persist_fim_event` writes the FIM row; `correlate_new_fim_event` reverse-uplifts any open EDR `security_alerts` within the window that share the path.
- `correlate_new_edr_alert` is read-only over `fim_events`, returns *planned* links + uplifted severity/payload/controls. The caller inserts the alert at the uplifted severity, then `record_planned_links` persists the edges (FK requires the alert row to exist first).

**Wiring (`app/services/state.upsert_heartbeat`):**
- FIM block now persists each event into `fim_events` and runs the FIM→EDR reverse correlation.
- EDR block runs EDR→FIM correlation *before* inserting `security_alerts` so the row lands at the uplifted severity in a single round-trip, then writes the planned links. Response-action events (`is_response_action`) are skipped — they already carry their own response evidence.

**Compliance:**
- New mapping `correlation.severity_uplift` → ISO 27001 A.5.25, A.8.16; SOC 2 CC7.2, CC7.3; NIST CSF DE.AE, RS.AN.
- `_emit_uplift_event` writes `evidence_events` (best-effort, wrapped in try/except so it can never break the heartbeat path).

**API:**
- `GET /security-alerts/{id}/correlations` (`incidents:view` scope, tenant-checked via `_require_customer_access`) returns `{alert_id, severity, severity_uplifted_from, correlations: [...]}` for the console alert detail view.

**Tests:**
- New file `apps/api/tests/test_correlation_fim_edr.py` — 5 cases covering FIM→EDR uplift, EDR→FIM reverse uplift, no-match (different paths), out-of-window, and the new GET endpoint.
- Full API suite green: **197 passed**.

## 2. What this unblocks

- Console can now render an "uplifted from {original_severity} — supported by {N} FIM events" affordance on the alert detail view (Agent 2 — small consumer change, contract is the GET endpoint above).
- Auditor exports gain a concrete event-aggregation/analysis artefact (DE.AE / RS.AN) instead of relying on dashboards.
- Provides the read-side primitive (`correlation_links` + GET endpoint) for the next correlation pairs (DLP↔EDR on sha256, DRP/EASM exposure ↔ endpoint incidents).

## 3. What's deliberately NOT in this slice

- DLP↔EDR sha256 correlation. The schema is shaped for it (`correlation_type ∈ {file_path_match, process_path_match, sha256_match}`) — wiring is straightforward in the next cycle.
- DRP/EASM ↔ endpoint incident edges. Still deferred until the new correlation primitive proves out on real telemetry.
- Process-tree correlation (parent_pid joins). Schema-ready but wiring not in scope.
- Console UI consumption — single new endpoint, small follow-up for Agent 2.

## 4. Compliance evidence trail for new operator paths

The previous cycle's quarantine list/restore/approve/deny paths already emit `endpoint.quarantine.*` evidence events with the dual-control control set. This cycle adds `correlation.severity_uplift` so the *system*-driven severity change is just as auditable as the operator-driven response. The trail for a typical incident now reads:

1. `agent.fim_event` (path X modified) → A.8.12, CC7.1
2. `agent.edr_event` (yara_match on path X) → A.8.16, CC7.2, DE.CM
3. `correlation.severity_uplift` (high → critical) → A.5.25, A.8.16, CC7.2/CC7.3, DE.AE, RS.AN
4. `endpoint.quarantine.list_requested` → A.5.26, A.8.16, CC7.2
5. `endpoint.quarantine.restore_requested` → A.5.26, A.5.30, A.8.13, CC7.4/CC7.5
6. `endpoint.quarantine.restore_approved` (separate approver) → A.5.16, A.5.18, CC6.3
7. `agent.response_action` (executed) → A.5.26, A.5.30, A.8.13, CC7.4/CC7.5, RS.MI, RC.RP

## 5. Next cycle recommendation

- Extend the engine to DLP↔EDR sha256 correlation (smallest next step — same engine, new lookup keys on `sha256_hash`).
- Then DRP/EASM exposure → endpoint incident graph (writes `security_alert` → `correlation_links` rows where `related_kind='security_alert'` to draw cross-module incidents).
- Keep current restraint on net-new EASM/DRP *collectors* until the correlation surface is exercised on real data.

Reference: `docs/architecture.md` §8 item 11, `docs/coordination-brief-cycle-2026-05-28.md`, `multi-agent-coordination-protocol.md`.
