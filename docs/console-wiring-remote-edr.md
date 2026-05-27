# Console Wiring Contract — Remote EDR Quarantine Management

**Cycle:** 2026-05-28 (Agent 3)
**Audience:** Agent 2 (console wiring), Agent 1 (agent serialization reference)
**Status:** Locked for cycle 2026-05-28 — additive changes only.

This document is the authoritative description of the control-plane surface
the console (`QuarantinePage.tsx`, `AntimalwareBehavior.tsx`, global
approval inbox) consumes for the remote EDR quarantine management feature.
Schemas live in `apps/api/app/schemas.py`; routes in `apps/api/app/main.py`;
agent serialization in `agent/src/edr/{mod,response}.rs`.

---

## 1. Authentication & scoping

All operator routes require `X-Aetherix-Account: <account_id>`. Permission
checks resolve the customer that owns the endpoint via
`enrolled_agents.customer_id` and call `_require_customer_access(
customer_id, account, "incidents", "view"|"edit")`. Endpoints that haven't
reported a heartbeat yet are still addressable — actions queue against
`enrolled_agents` rows.

| Resource           | Read scope            | Write scope            |
|--------------------|-----------------------|------------------------|
| quarantine list    | `incidents:view`      | `incidents:edit`       |
| quarantine restore | `incidents:view`      | `incidents:edit`       |
| approve / deny     | n/a                   | `incidents:edit` + distinct operator |

Errors are returned as `{"detail": "<message>"}` with conventional codes:
`400` validation, `403` forbidden (incl. self-approve), `404` not found,
`409` conflicting state (e.g. action no longer awaiting approval).

---

## 2. Routes

### 2.1 Refresh quarantine inventory (operator → agent)

```
POST /endpoints/{endpoint_id}/quarantine-list
Body: { "reason": "<optional, ≤1000 chars>" }
→ 200 ModuleActionResult  (status="queued", action="quarantine_list")
```

The agent picks the queued action up via `GET /agent/actions` and replies
with `POST /agent/actions/{id}/ack` carrying
`result.quarantine_items: QuarantineListItem[]`. The control plane upserts
that into `endpoint_quarantine_inventory` keyed by `endpoint_id` so the
console can render last-known inventory without round-tripping the agent.

### 2.2 Read cached inventory

```
GET /endpoints/{endpoint_id}/quarantine-inventory
→ 200 QuarantineInventoryResponse
{
  "endpoint_id": str,
  "customer_id": uuid | null,
  "items": QuarantineInventoryItem[],
  "source_action_id": str | null,
  "refreshed_at": iso8601 | null
}
```

When no agent ack has been received yet the response is shaped with
`items=[]`, `source_action_id=null`, `refreshed_at=null` (not 404). The
console should render an empty state and offer the refresh action.

### 2.3 Request a restore (severity-gated)

```
POST /endpoints/{endpoint_id}/quarantine-restore
Body: {
  "quarantine_id": str,                       # required
  "target_path":   str | null,                # optional override
  "severity_hint": "low"|"medium"|"high"|"critical" | null,
  "reason":        str (≤1000)
}
→ 200 ModuleActionResult
```

Severity drives status:

- `low` / `medium` → `status="queued"` (executes on next agent poll).
- `high` / `critical` → `status="awaiting_approval"`,
  `approval_required=true`. A distinct operator must approve.

### 2.4 Approve / deny

```
POST /endpoints/{endpoint_id}/quarantine-restore/{action_id}/approve
POST /endpoints/{endpoint_id}/quarantine-restore/{action_id}/deny
Body: { "reason": str (≤1000, optional) }   # QuarantineRestoreDecision
→ 200 ModuleActionResult
```

- Self-approval by the original requester returns **403**.
- Approve transitions `awaiting_approval → queued`; the action is then
  picked up by the agent on the next poll.
- Deny transitions `awaiting_approval → denied` and writes
  `denial_reason` / `denied_by` into `payload`. The agent never sees a
  denied action.
- Either route returns **409** if the action is not currently
  `awaiting_approval`.

The reason text is persisted on `module_actions.payload`
(`approval_reason` / `denial_reason`) and surfaced via compliance evidence.

### 2.5 Per-endpoint response action history

```
GET /endpoints/{endpoint_id}/response-actions
    ?action=quarantine_list|quarantine_restore|...
    &status=queued|awaiting_approval|completed|failed|denied
    &limit=1..500   (default 100)
→ 200 ModuleActionResult[]
```

Console patterns:

- Approval inbox row for one endpoint:
  `?action=quarantine_restore&status=awaiting_approval`.
- StagedActionBadge / executed history:
  `?action=quarantine_restore` (covers `queued/completed/failed/denied`).

Invalid `status` returns **400** with the allowed set.

### 2.6 Tenant-wide pending restore inbox

```
GET /quarantine-restores/pending
    ?customer_id=<uuid>     # optional; requires incidents:view if set
    &limit=1..500           # default 100
→ 200 PendingQuarantineRestore[]
{
  "action":      ModuleActionResult,
  "endpoint_id": str,
  "hostname":    str | null,
  "customer_id": uuid | null
}
```

When `customer_id` is omitted, the response is automatically scoped to the
caller via `tenancy.compute_scope`:

- Platform owners → every awaiting-approval restore.
- MSP partners → restores for endpoints whose customer's `partner_id` is
  in scope.
- Company admins → restores for their own `customer_id`(s).
- No applicable scope → empty list (not 403), so the global page is safe
  to render unconditionally for any authenticated account.

---

## 3. Canonical payloads

### 3.1 `ModuleActionResult`

```ts
{
  id: string;                  // uuid
  endpoint_id: string;
  customer_id: string | null;  // uuid
  action: "quarantine_list" | "quarantine_restore" | string;
  status: "queued" | "awaiting_approval" | "completed" | "failed" | "denied";
  approval_required: boolean;
  evidence_controls: string[]; // e.g. "iso27001-2022:A.8.16"
  payload: Record<string, unknown>;   // request input + approval/denial reason
  result: Record<string, unknown> | null; // agent ack body
  requested_by: string | null;        // account id
  approved_by:  string | null;
  approved_at:  string | null;        // iso8601
  processed_by: string | null;        // agent_id or endpoint_id
  processed_at: string | null;
  created_at:   string;
}
```

`"denied"` is the new terminal state added this cycle. Treat it as
mutually exclusive with `completed` / `failed` when reconciling badges.

### 3.2 `QuarantineInventoryItem`

Field names mirror the agent's `QuarantineListItem` serialization
(`agent/src/edr/mod.rs`). Legacy field names (`sha256`, `size_bytes`) are
still accepted on write via Pydantic alias choices, but every read
exposes the canonical names below.

```ts
{
  quarantine_id: string;            // stable id used by restore requests
  original_path: string | null;
  quarantined_at: string | null;    // iso8601
  sha256_hash: string | null;       // hex
  rule_id: string | null;           // matching detection rule
  file_size: number | null;         // bytes, ≥0
  severity_hint: "low"|"medium"|"high"|"critical" | null;
  can_restore: boolean;             // default true; false → render disabled
  restore_requires_approval: boolean;
  approval_hint: string | null;     // human-readable hint from agent
  encrypted: boolean;               // quarantine container encryption
  manifest_hash: string | null;
  stored_path: string | null;       // some agent builds
  reason: string | null;            // some agent builds
  // forward-compat: extra agent fields pass through unchanged
}
```

Agent 1's cycle 2026-05-28 polish added `decision_trace` enrichments
(`restore_approval_state`, `restore_policy_denial_reason`,
`restore_rate_limit_state`) on the **agent** side; these arrive on the
`module_actions.result` from the agent ack rather than as inventory item
fields. Surface them on the executed-history row, not on the inventory
row.

### 3.3 `QuarantineRestoreDecision`

```ts
{ "reason": string }   // ≤1000 chars, defaults to ""
```

### 3.4 `PendingQuarantineRestore`

```ts
{
  action:      ModuleActionResult;
  endpoint_id: string;
  hostname:    string | null;   // joined from enrolled_agents
  customer_id: string | null;   // coalesce(action.customer_id, enrolled_agents.customer_id)
}
```

---

## 4. Compliance evidence emitted

The control plane writes `evidence_events` rows for every operator-side
action so auditor exports show the full chain
*request → approve/deny → execute*.

| Action key                              | Controls (highlights)                                  |
|-----------------------------------------|--------------------------------------------------------|
| `endpoint.quarantine.list_requested`    | ISO A.5.26, A.8.16; SOC2 CC7.2; NIST DE.CM, RS.AN      |
| `endpoint.quarantine.restore_requested` | ISO A.5.26, A.5.30, A.8.13; SOC2 CC7.4/CC7.5; RS.MI/RC.RP |
| `endpoint.quarantine.restore_approved`  | ISO A.5.16, A.5.18; SOC2 CC6.3 (separation of duties)  |
| `endpoint.quarantine.restore_denied`    | ISO A.5.16, A.5.26; SOC2 CC7.4; NIST RS.AN             |

Failures emitting evidence never break the operator path
(`_emit_quarantine_compliance` swallows + logs).

Agent execution evidence (success or failure) is emitted from the
heartbeat correlation path (`state.py`) under `agent.response_action`
once the agent reports the action status. The console does not need to
emit anything itself.

---

## 5. Console wiring map

| Console surface                              | Endpoint(s)                                                                 |
|----------------------------------------------|-----------------------------------------------------------------------------|
| `QuarantinePage` — list                      | `GET /endpoints/{id}/quarantine-inventory`                                  |
| `QuarantinePage` — refresh button            | `POST /endpoints/{id}/quarantine-list`                                      |
| `QuarantinePage` — restore button            | `POST /endpoints/{id}/quarantine-restore`                                   |
| `QuarantinePage` — StagedActionBadge         | `GET /endpoints/{id}/response-actions?action=quarantine_restore`            |
| `AntimalwareBehavior` — per-endpoint inbox   | `GET /endpoints/{id}/response-actions?action=quarantine_restore&status=awaiting_approval` |
| Global approval inbox page                   | `GET /quarantine-restores/pending`                                          |
| Approval inbox — Approve / Deny buttons      | `POST .../{action_id}/approve` / `.../deny` with `{reason}` body            |

UI invariants:

1. Use server `status` for the badge — never derive `executed/denied` on
   the client from approval clicks. After a successful approve/deny,
   the returned `ModuleActionResult` is the source of truth.
2. `can_restore=false` on an inventory item disables the restore button.
   Hover should surface `approval_hint` when present.
3. When `severity_hint ∈ {high, critical}` the restore confirm dialog
   should note "this restore will require approval by another operator"
   before submission.
4. Treat `"denied"` as a terminal red badge; do not let the operator
   re-approve a denied action (the API returns 409 anyway).
5. `customer_id` may be `null` on legacy actions; fall back to the
   endpoint's `customer_id` from `enrolled_agents`.

---

## 6. Backwards-compatibility notes for Agent 2 mocks

- `QuarantineInventoryItem` accepts both `{sha256, size_bytes}` and
  `{sha256_hash, file_size}` on write; reads always normalize to the
  canonical names. Mocks may use either, but tests should assert against
  canonical names.
- `status="denied"` is new in this cycle. Older console builds treating
  unknown statuses as `failed` will degrade gracefully.
- The `deny` route and `/quarantine-restores/pending` were added this
  cycle; the rest of the surface is unchanged from cycle 2026-05-27.

---

*Owner: Agent 3 (Control Plane + Console Foundations). Refer to
`docs/coordination-brief-cycle-2026-05-28.md` for cycle objectives.*
