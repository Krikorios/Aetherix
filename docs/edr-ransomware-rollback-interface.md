# EDR Ransomware Rollback Interface Sketch

Status: planning only. This document intentionally does not add an executable
remote action or endpoint-agent rollback implementation.

## Scope

Ransomware rollback is the next EDR recovery capability after policy-gated
quarantine, kill, isolate intent, and quarantine restore. The first increment
must stay deterministic, evidence-first, and default-safe:

- Detectors produce affected-path evidence and a candidate restore set.
- The agent reports local snapshot-provider capability and recovery-point
  metadata.
- The control plane requires simulation evidence and operator approval before
  queueing rollback intent.
- The endpoint performs restore only through a provider that can verify the
  recovery point and report per-path results.

## Non-Goals

- No new executable remote action until console and control-plane quarantine
  management are stable.
- No broad filesystem rollback without a simulation result and approved action
  id.
- No ML-only rollback decisions. ML can rank candidates later, but evidence
  must cite deterministic detector facts and snapshot metadata.
- No custom backup store in the agent. The first phase should integrate with OS
  snapshot facilities where available.

## Data Model Sketch

```rust
pub struct RollbackScope {
    pub incident_id: String,
    pub detector_rule_id: String,
    pub affected_paths: Vec<String>,
    pub observed_at: String,
}

pub struct RecoveryPoint {
    pub id: String,
    pub provider: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub protected_roots: Vec<String>,
    pub read_only: bool,
    pub verified: bool,
}

pub struct RollbackCandidateSet {
    pub scope: RollbackScope,
    pub recovery_point_id: String,
    pub paths: Vec<String>,
    pub total_bytes_estimate: u64,
    pub max_depth: u8,
    pub candidate_set_hash: String,
}

pub struct RollbackSimulation {
    pub simulation_id: String,
    pub candidate_set_hash: String,
    pub candidate_count: usize,
    pub restorable_count: usize,
    pub skipped_paths: Vec<RollbackPathDecision>,
    pub destructive: bool,
    pub valid_until: String,
    pub decision_trace: Vec<String>,
}

pub struct RollbackPathDecision {
    pub path: String,
    pub decision: String,
    pub reason: String,
}

pub struct RollbackEvidence {
    pub approved_action_id: String,
    pub simulation_id: String,
    pub candidate_set_hash: String,
    pub provider: String,
    pub recovery_point_id: String,
    pub restored_paths: Vec<RollbackPathDecision>,
    pub failed_paths: Vec<RollbackPathDecision>,
    pub skipped_paths: Vec<RollbackPathDecision>,
    pub decision_trace: Vec<String>,
}
```

## Provider Boundary

```rust
pub trait RollbackProvider {
    fn capabilities(&self) -> RollbackCapabilities;
    fn list_recovery_points(&self, scope: &RollbackScope) -> anyhow::Result<Vec<RecoveryPoint>>;
    fn simulate_restore(&self, candidates: &RollbackCandidateSet) -> anyhow::Result<RollbackSimulation>;
    fn restore(
        &self,
        candidates: &RollbackCandidateSet,
        approved_action_id: &str,
    ) -> anyhow::Result<RollbackEvidence>;
}
```

Provider candidates:

- Windows: VSS, subject to service availability and least-privilege testing.
- macOS: APFS snapshots where available.
- Linux: filesystem or volume snapshots when configured by the customer.

Provider refusal states should be explicit and operator-safe:

- `provider_unavailable`: snapshot service, mount tooling, or required OS API is
  absent, disabled, or outside the agent entitlement.
- `recovery_point_unverified`: provider cannot prove the selected recovery point
  still exists, is read-only, and covers every candidate path root.
- `candidate_scope_mismatch`: requested paths do not match the simulation hash or
  include paths outside the detector-emitted scope.
- `unsafe_target_state`: the live path changed after simulation in a way that
  would overwrite newer clean data without an explicit future policy override.
- `privilege_boundary`: restore requires privileges not granted to the signed
  agent service or would cross tenant/user profile boundaries.

### OS-Specific Candidate Notes

Windows VSS:

- Candidate paths must map to a volume with a matching shadow copy. UNC paths,
  removable drives, and cloud-sync placeholders should be `not_applicable` until
  separately tested.
- The provider should prefer copy-out from a mounted shadow view over whole-volume
  rollback. Whole-volume restore is out of scope for endpoint EDR response.
- Restore should preserve ownership, ACLs, timestamps, and alternate data stream
  metadata where the provider can read it; missing metadata must be reported.

macOS APFS:

- Candidate paths must reside on an APFS volume with snapshots enabled and visible
  to the agent's entitlement context.
- Time Machine snapshots may be listed only as recovery points; the first phase
  should still restore individual files from a verified read-only snapshot view.
- Sealed system volume paths, TCC-protected user data, and external volumes should
  be skipped unless the provider can prove safe per-path access.

Linux filesystem or volume snapshots:

- Candidate paths must identify the mounted filesystem, subvolume, or logical
  volume that owns the path. Mixed-root candidate sets should be split by
  provider and recovery point.
- Supported candidates should initially be configured snapshots such as Btrfs
  subvolumes, ZFS snapshots, or LVM thin snapshots. Ad hoc backup directories are
  not a rollback provider.
- Overlay/container filesystems, network filesystems, encrypted home directories,
  and bind mounts require explicit `skipped` decisions until tested.

## Safety Gates

- Rollback remains monitor/review by default in policy.
- Promotion to executable rollback requires policy simulation and operator
  approval.
- High/Critical ransomware incidents should require dual-operator approval by
  default, matching the quarantine restore model.
- Self-approval is refused. The requester cannot be the sole approver, and dual
  approval must require two distinct operators with current `incidents:edit`
  authority for the tenant.
- The approved action must reference `simulation_id`, `candidate_set_hash`,
  `recovery_point_id`, endpoint id, tenant id, and `valid_until`; the agent must
  refuse expired or mismatched approvals.
- The candidate set must have a bounded blast radius: maximum path count, maximum
  estimated bytes, maximum directory depth, and protected-root allow-list are all
  policy-controlled before execution exists.
- Each restore must include `approved_action_id` so evidence links back to the
  control-plane action and audit record.
- The agent must refuse restore if the provider cannot verify recovery-point
  metadata or if the candidate set contains paths outside the simulated scope.
- The agent must treat rollback as idempotent per `approved_action_id`. Retries
  can resume/report status, but must not widen the path set or select a newer
  recovery point.
- Rollback should not delete quarantined artifacts or forensic evidence. If a
  restored file conflicts with an existing quarantine item, evidence must link the
  quarantine id and leave final disposition to the operator.

## Evidence Requirements

Rollback evidence should follow the same shape and quality bar as current
`ResponseEvidence`:

- `status`: staged, executed, failed, or not_applicable.
- `decision_trace`: ordered provider selection, simulation hash, approval id,
  recovery point verification, and per-path outcome summary.
- `simulation_id`, `candidate_set_hash`, `approved_action_id`, `requester_id`,
  approver ids, policy version, endpoint id, tenant id, and provider version.
- `evidence_controls`: recovery and incident-response controls, including NIST
  CSF RS.MI and SOC 2 CC7.5 where mapped by the control plane.
- Per-path results must distinguish restored, skipped, failed-integrity-check,
  and refused-out-of-scope.
- Provider facts: recovery point creation time, expiry if known, protected roots,
  read-only verification, metadata preservation result, and any privilege or OS
  refusal state.

The agent should emit failed evidence for malformed, expired, out-of-scope, or
provider-refused rollback intents rather than silently acknowledging them. That
keeps rollback aligned with the current quarantine management evidence model.

## Control-Plane Contract Sketch

No endpoint routes are being added by this document. When promoted later, the
workflow should mirror quarantine restore but keep simulation as a required
precondition:

1. Agent heartbeat or detection evidence reports rollback capability and affected
   paths for a ransomware incident.
2. Control plane requests or receives a simulation result and stores the immutable
   `simulation_id` + `candidate_set_hash`.
3. Operator requests rollback against that simulation. High/Critical incidents
   require dual approval; self-approval is refused.
4. Agent receives only the approved intent and must re-verify the recovery point,
   candidate hash, endpoint/tenant binding, and expiry before restoring paths.
5. Agent emits `rollback_restore` evidence with per-path decisions and provider
   refusal states.

Approval and simulation records should be immutable once created. If the detector
adds new affected paths, the control plane should create a new simulation instead
of mutating the old candidate set.

## Expanded Safety Gates

The initial sketch defined twelve safety gates. This section decomposes the most
critical ones into enforceable policy parameters, blast-radius constraints, and
idempotency guarantees.

### Policy-Controlled Blast-Radius Limits

Each of the following must be configurable per tenant (with safe defaults) and
must be checked by the control plane before queuing rollback intent:

| Parameter | Default | Unit | Enforcement Point |
|-----------|---------|------|-------------------|
| `max_paths_per_restore` | 500 | paths | Control plane (reject before staging) |
| `max_bytes_per_restore` | 10 GiB | bytes | Control plane + agent (agent enforces ceiling) |
| `max_directory_depth` | 8 | levels | Agent (simulation enumerates depth) |
| `protected_root_allowlist` | OS roots | glob patterns | Agent (provider checks each path root) |
| `min_recovery_point_age` | 300 | seconds | Agent (prevents racing snapshot creation) |
| `max_recovery_point_age` | 7 | days | Agent (expired points require re-simulation) |
| `require_verified_point` | true | boolean | Agent (provider must prove point exists) |
| `require_distinct_approver` | true | boolean | Control plane (dual-operator enforcement) |

The control plane should reject any stage request that exceeds tenant policy
limits before creating the `module_actions` row, so the operator sees the
rejection immediately rather than waiting for agent enforcement.

### Blast-Radius Escalation Path

If a rollback intent exceeds tenant policy limits, the control plane must not
silently truncate the candidate set. Instead:

1. Return a structured `limit_exceeded` error listing which parameter was
   exceeded, the requested value, and the tenant cap.
2. The console displays a "Scope Exceeded" warning with an option to either
   narrow the candidate set or request a policy override (which itself requires
   elevated approval, e.g. `incidents:manage`).
3. Policy overrides are recorded as a distinct compliance event with the
   operator id, override reason, and previous limit value.

### Idempotency Enforcement

- Each `approved_action_id` may be executed at most once per endpoint.
- The agent persists a set of consumed action ids in its local state directory
  (`<data_dir>/rollback/consumed_ids`). On restart it re-reads this set.
- If the agent receives a rollback intent with an already-consumed `id`, it
  returns the stored `RollbackEvidence` from the original execution instead of
  re-running the restore. This is safe because rollback is inherently
  idempotent per recovery point—re-applying from the same snapshot produces
  the same file state.
- The agent must verify that the recovery point still exists before returning
  cached evidence; if the point has expired or been deleted, it emits
  `rollback_evidence` with status `not_applicable` and a `provider_refused`
  decision trace.
- The control plane must not re-queue a rollback action that already has
  `executed` or `failed` status in `module_actions`. Retries are allowed only
  for `queued` or `awaiting_approval` actions.

### Simulation Freshness Window

- Simulation results are valid for a policy-configurable window (default:
  1 hour from `simulation.created_at`).
- The control plane rejects stage requests that reference an expired
  `simulation_id`. The console shows a "Simulation Expired — Re-run Required"
  message and disables the stage button.
- When a detector emits new affected paths for the same incident, the control
  plane creates a fresh simulation rather than mutating the old candidate set.
  Both simulation records remain in the database for audit trail continuity.
- The agent side refuses rollback if the `valid_until` in the approved intent
  has passed, even if the control plane accepted it. This is a defence-in-depth
  layer against clock skew or delayed queue processing.

---

## Candidate Selection Logic

### Step 1: Detector-to-Scope Mapping

When a ransomware detector fires (e.g. entropy spike + mass-rename + canary
trigger), it emits a `RollbackScope` containing:

- `incident_id`: links back to the `security_alerts` row that triggered the
  rollback-eligible incident.
- `detector_rule_id`: identifies which detector rule(s) produced the path set.
- `affected_paths`: deduplicated list of paths the detector observed being
  modified, created, or encrypted during the detection window.
- `observed_at`: timestamp of the first affected-path observation.

The agent's response-action service splits these paths by filesystem boundary:

```
affected_paths = [
  "/home/user/docs/report.docx",
  "/var/lib/postgresql/14/main/base/12345/6789",
  "/home/user/docs/budget.xlsx",
  "/mnt/backup/encrypted.bak",
]
```
→
```
scope_by_root = {
  "/": ["/home/user/docs/report.docx", "/home/user/docs/budget.xlsx"],
  "/var": ["/var/lib/postgresql/14/main/base/12345/6789"],
  "/mnt": ["/mnt/backup/encrypted.bak"],
}
```

### Step 2: Provider Resolution

For each root, the agent consults the registered `RollbackProvider`
implementations:

1. Each provider advertises a `capabilities()` response listing supported OS
   families, filesystem types, volume roots, and privilege requirements.
2. The agent selects the first provider whose `can_handle(root, metadata)`
   returns `Ok`. Selection order is deterministic: OS-native provider first
   (VSS on Windows, APFS on macOS, LVM/Btrfs/ZFS on Linux), then any
   third-party provider registered at build time.
3. If no provider covers a root, the agent emits a `not_applicable` decision
   for that path group. The simulation result must report this so the operator
   understands partial coverage.

### Step 3: Recovery Point Selection

For each provider-root pair, the agent calls
`provider.list_recovery_points(scope)` and selects the most recent recovery
point that:

- Was created **before** `observed_at` (no point-after-infection).
- Has `verified == true` (provider can prove it exists and is readable).
- Has `protected_roots` covering all paths in the root group.
- Has `read_only == true` (the provider can mount it without mutation risk).
- Has not expired (`expires_at` is null or in the future).

If no qualifying point exists, the simulation result records
`recovery_point_unverified` for that group. The agent does not fall back to
an unverified point.

### Step 4: Candidate Set Assembly

For each provider-root-point triple:

1. The agent enumerates all paths under each affected path entry (up to
   `max_directory_depth`) that exist in the recovery point view.
2. For each path, it records metadata: size, hash (if available from provider),
   permissions, owner, and whether the path also exists in the live filesystem
   (to determine if restore would overwrite newer data).
3. The assembled `RollbackCandidateSet` includes:
   - A `candidate_set_hash` computed over `(scope.id + recovery_point_id +
     sorted(paths) + total_bytes_estimate)`.
   - Per-path decisions: `restorable`, `not_found_in_point`, or `unsafe_overwrite`.
4. Paths marked `unsafe_overwrite` (live version is newer than the recovery
   point version) require explicit operator confirmation. The simulation must
   flag these.

### Cross-Provider Splitting

A single ransomware incident may affect paths on multiple volumes. The agent
produces one `RollbackCandidateSet` per provider-root-point triple. The control
plane treats each as a separate simulation record linked to the same
`incident_id`. The operator can approve/reject each set independently, which
prevents a failure on one volume from blocking recovery on others.

---

## Evidence Requirements

Rollback evidence inherits the existing `ResponseEvidence` shape and adds
rollback-specific fields. Below is the detailed schema:

### Agent-Emitted Evidence Shape

```rust
pub struct RollbackEvidence {
    // --- Standard ResponseEvidence fields ---
    pub status: String,
    // "staged" | "executed" | "failed" | "not_applicable"
    pub decision_trace: Vec<String>,
    pub evidence_controls: Vec<String>,
    pub endpoint_id: String,
    pub customer_id: Option<String>,
    pub policy_version: String,
    pub requester_id: String,
    pub approver_ids: Vec<String>,

    // --- Rollback-specific fields ---
    pub simulation_id: String,
    pub candidate_set_hash: String,
    pub approved_action_id: String,
    pub provider: String,
    pub recovery_point_id: String,
    pub recovery_point_created_at: String,
    pub recovery_point_expires_at: Option<String>,
    pub recovery_point_verified: bool,
    pub metadata_preserved: Option<bool>,
    pub provider_refusal: Option<String>,

    // --- Per-path results ---
    pub restored_paths: Vec<RollbackPathDecision>,
    pub failed_paths: Vec<RollbackPathDecision>,
    pub skipped_paths: Vec<RollbackPathDecision>,

    // --- Provider facts ---
    pub provider_version: String,
    pub os_platform: String,
    pub privilege_context: String,
}

pub struct RollbackPathDecision {
    pub path: String,
    pub outcome: String,
    // "restored" | "skipped" | "failed_integrity" | "refused_out_of_scope"
    pub reason: String,
    pub bytes_affected: u64,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
    pub metadata_diff: Option<Vec<String>>,
}
```

### Evidence Compliance Controls

| Evidence Field | ISO 27001:2022 | SOC 2 TSC 2017 | NIST CSF 2.0 |
|----------------|----------------|-----------------|--------------|
| `decision_trace` | A.12.4.1, A.12.4.2 | CC7.2 | PR.PT, DE.DP |
| `approved_action_id` | A.9.2.1, A.9.2.5 | CC6.1 | PR.AC |
| `simulation_id + candidate_set_hash` | A.12.4.3 | CC7.5 | DE.CM |
| `per-path outcomes` | A.12.6.1 | CC7.3 | PR.DS |
| `provider_refusal` | A.12.6.1 | CC7.4 | RS.MI |
| `approver_ids` | A.9.2.1, A.9.2.5 | CC6.2 | PR.AC |

### Evidence Emission Guarantees

The agent **must** emit evidence for every rollback attempt, including refusals:

- **Malformed intent**: If the approved action's payload is missing required
  fields, the agent emits evidence with `status: "failed"` and a decision trace
  entry `"malformed_intent: missing <field>"`. It does NOT silently ack.
- **Expired intent**: If `valid_until` has passed, evidence is emitted with
  `status: "not_applicable"` and a trace entry `"intent_expired: valid_until
  <timestamp>"`.
- **Provider refusal**: If the provider returns an error (e.g., VSS writers
  failed, APFS snapshot not found), the agent emits evidence with
  `provider_refusal` populated and `status: "failed"`.
- **Partial success**: If some paths restore and others fail, the agent emits
  evidence with `status: "executed"` but populates `failed_paths` and
  `skipped_paths`. The console must badge this as "EXECUTED (PARTIAL)" — see
  the integration section below.

### Control-Plane Evidence Recording

The control plane records the agent's `RollbackEvidence` in the `module_actions`
row (as `result`) and emits the following audit events:

| Event | Trigger | Compliance Controls |
|-------|---------|---------------------|
| `rollback.simulation_created` | Simulation completes | ISO A.12.4.1, SOC2 CC7.5 |
| `rollback.intent_staged` | Operator stages rollback | ISO A.12.4.2, SOC2 CC7.2 |
| `rollback.intent_approved` | Operator approves | ISO A.9.2.5, SOC2 CC6.2 |
| `rollback.intent_denied` | Operator denies | ISO A.9.2.5, SOC2 CC6.2 |
| `rollback.agent_executed` | Agent ack with evidence | ISO A.12.4.1, SOC2 CC7.3 |
| `rollback.agent_failed` | Agent ack with error | ISO A.12.6.1, SOC2 CC7.4 |
| `rollback.agent_refused` | Agent ack as not_applicable | ISO A.12.6.1, SOC2 CC7.4 |

---

## Integration with Existing Response Action + Approval Flow

Ransomware rollback reuses the same control-plane plumbing as quarantine
restore. This section maps each step to the existing data model, routes, and
console surfaces.

### Data Model Mapping

The existing `module_actions` table already models the lifecycle:

```
module_actions (
  id              UUID PRIMARY KEY,   -- action_id
  endpoint_id     TEXT NOT NULL,
  module          TEXT NOT NULL,       -- "ransomware_rollback"
  action          TEXT NOT NULL,       -- "rollback"
  status          TEXT NOT NULL,       -- queued → awaiting_approval → executed / failed / denied
  approval_required BOOLEAN NOT NULL,
  payload         JSONB,              -- { simulation_id, candidate_set_hash, recovery_point_id, ... }
  evidence_controls TEXT[],
  created_at      TIMESTAMPTZ,
  processed_at    TIMESTAMPTZ,
  result          JSONB,              -- agent RollbackEvidence
  requested_by    TEXT,
  approved_by     TEXT,
  approved_at     TIMESTAMPTZ
)
```

Key reuse points:
- `module = "ransomware_rollback"` and `action = "rollback"` for all rollback
  actions.
- `status` uses the same lifecycle as quarantine restore: `queued` →
  `awaiting_approval` (for high/critical) → `executed` | `failed` | `denied`.
- `payload` contains the simulation reference, candidate set, and recovery
  point metadata instead of quarantine-specific fields.
- `result` stores the agent's `RollbackEvidence` (same shape as
  `ResponseEvidence` but with rollback-specific fields).
- The existing `/endpoints/{id}/response-actions` endpoint already returns
  rollback actions alongside quarantine, kill, and isolate actions. No new
  history route required.

### Route Integration

No new routes are required for the initial rollback integration. The existing
routes are reused with new `module`/`action` values:

| Existing Route | Rollback Usage |
|----------------|----------------|
| `POST /endpoints/{id}/quarantine-list` | N/A — rollback does not need a separate list action |
| `GET /endpoints/{id}/quarantine-inventory` | N/A — rollback provider data is ephemeral |
| `POST /endpoints/{id}/quarantine-restore` | **Replaced by** `POST /endpoints/{id}/rollback-restore` (see below) |
| `POST .../{action_id}/approve` | Reused as-is — same dual-operator enforcement |
| `POST .../{action_id}/deny` | Reused as-is — same reason capture |
| `GET /endpoints/{id}/response-actions` | Reused as-is — rollback actions appear in history |
| `GET /quarantine-restores/pending` | **Extended** — also returns pending rollback actions |
| `POST /behavior/simulate` | **Extended** — accepts `module: "ransomware_rollback"` |

The new route required (one additional, matching the existing pattern):

```
POST /endpoints/{id}/rollback-restore
Payload: {
  simulation_id: String,
  incident_id: String,
  reason: String,
}
Response: ModuleActionResult
```

This parallels `POST /endpoints/{id}/quarantine-restore` but requires
`simulation_id` as a precondition. The control plane validates that the
simulation exists, has not expired, and belongs to the same endpoint + tenant
before creating the `module_actions` row.

### Approval Flow Integration

High/Critical ransomware incidents follow the same dual-operator approval model:

1. **Operator A** selects the rollback simulation result from the simulation
   panel and clicks "Stage Rollback."
2. The control plane checks severity from the linked `security_alerts` row:
   - Low/Medium → status `queued` (auto-approved, goes straight to agent).
   - High/Critical → status `awaiting_approval` (requires distinct approver).
3. **Operator B** sees the pending rollback in the Approvals Inbox (extended to
   show rollback actions alongside quarantine restores).
4. Operator B clicks Approve (or Deny with reason). Self-approval is refused.
5. The agent receives the approved intent, re-verifies the recovery point, and
   executes the restore.
6. The action status transitions to `executed` (or `failed`/`denied`) and is
   reflected in `StagedActionBadge` via the existing response-actions polling.

### Console Surface Integration

The rollback action already exists in `ANTIMALWARE_BEHAVIOR_ACTIONS`:

```typescript
{ value: "rollback", label: "Ransomware Mitigation Rollback", destructive: true }
```

When an operator selects "rollback" and runs simulation, the console should:

1. Display the simulation result with:
   - A per-provider breakdown showing which recovery points were found, how
     many paths are restorable, and any `not_applicable` path groups.
   - A blast-radius summary: total bytes, max depth, path count.
   - A warning banner if any paths are `unsafe_overwrite` (live version newer).
2. **Disable the stage button** if simulation is missing, expired, or has zero
   restorable paths.
3. On stage, show the severity-gated approval badge:
   - `AWAITING APPROVAL` (orange) for high/critical incidents.
   - `STAGED` (default-green) for low/medium.
4. After approval/execution, `StagedActionBadge` renders the same four terminal
   states as quarantine restore:
   - `EXECUTED` (green) when agent confirms full restore.
   - `DENIED` (red) when operator denies.
   - `FAILED` (red) when agent reports error.
   - A **new composite state**: `EXECUTED (PARTIAL)` (yellow badge with
     partial-success icon) when `failed_paths` or `skipped_paths` is non-empty
     but `restored_paths` is also non-empty. The console can derive this from
     the agent evidence in `result`.

### StagedActionBadge Partial Execution Enhancement

To support the partial rollback case, the badge gains one additional visual
state:

```
if (evidence.restored_paths.length > 0 &&
    (evidence.failed_paths.length > 0 || evidence.skipped_paths.length > 0)) {
  // Render amber "EXECUTED (PARTIAL)" badge with AlertTriangle icon
}
```

This does not require a new server status string — the console derives it from
the agent evidence already present in `result`. The server continues to report
`status: "executed"`; the console enhances the badge client-side.

### Sidebar and Navigation Integration

- The existing "Antimalware & Behavior" page surfaces rollback in the action
  panel, so no new sidebar entry is required for v1.
- A future "Ransomware Recovery" dedicated page (or tab within Quarantine)
  could surface rollback candidates, simulation history, and restore evidence
  in a focused view. This is deferred to a future cycle.

---

## Open Questions (Updated)

- Whether snapshot capability is reported in heartbeat inventory or only during
  rollback simulation.
  - **Current leaning**: Report as part of `quarantine_list` response and
    agent inventory heartbeat, so the control plane can pre-filter endpoints
    that lack rollback providers before the operator reaches the action panel.
- Whether the console should show rollback candidates inside the ransomware
  incident timeline or a separate recovery workflow.
  - **Current leaning**: Start inside the Antimalware action panel (no new
    page), then add a dedicated recovery tab once usage data validates the
    investment.
- How long simulation results remain valid before the control plane must require
  a fresh candidate set.
  - **Resolution above**: Policy-configurable window, default 1 hour, checked
    by both control plane and agent.
- Whether policy should default to a tenant-level byte/path cap or derive caps
  from endpoint criticality and incident severity.
  - **Resolution above**: Tenant-level caps with endpoint
    criticality-based multipliers. Default caps as specified in the safety
    gates table.
- Which OS providers should be destructively tested first; Windows VSS is likely
  the most customer-visible, while Linux support depends heavily on customer
  filesystem choices.
  - **Recommendation**: Windows VSS first (widest deployment base), then macOS
    APFS, then Linux LVM/Btrfs. Each provider should be independently
    testable so rollout can be staggered.
- Should `not_applicable` evidence for provider-refused paths still count toward
  SLA/coverage metrics?
  - **Open**: This depends on how the platform defines rollback coverage.
    Proposal: exclude `not_applicable` from coverage calculations but include
    in audit trail.
- How should the console handle cross-provider splits where one provider
  succeeds and another fails?
  - **Open**: The per-candidate-set approval model allows independent
    accept/reject, but the console needs a clear way to show partial
    incident recovery. Initial approach: group by incident and show per-set
    badges.

---

## Cycle 2026-05-27 Additions

The following sections deepen the planning in three areas specifically requested
for this cycle: candidate presentation UX, correlation-informed safety controls,
and the closed audit loop through the correlation engine. A separate design note
covers lightweight heartbeat correlation hints.

---

### Candidate Presentation UX Contract

The existing candidate-selection logic produces a `RollbackCandidateSet` with
ranked `RollbackPathDecision[]` entries. This section translates that data into a
concrete console interaction model.

#### Candidate ranking for operator review

Paths within a candidate set are surfaced to the operator in priority order:

| Priority | Condition | Badge |
|---|---|---|
| 1 (highest) | Path has a `sha256_match` correlation link *and* a verified pre-attack hash from the recovery point | `CORROBORATED — FIM + hash` |
| 2 | Path has a `file_path_match` or `process_path_match` correlation link but no hash match | `CORROBORATED — path` |
| 3 | Path appears in the detector evidence only; recovery point is verified and within `max_recovery_point_age` | `DETECTOR — verified point` |
| 4 (lowest) | Path appears in detector evidence; recovery point is unverified, near expiry, or age exceeds threshold | `DETECTOR — unverified point` |

Priority-4 paths **default to deselected** in the UI. The operator must
explicitly check them to include them in the staged candidate set. This is the
primary UI-level blast-radius control: it keeps the default restore scope to
paths the platform has the highest confidence in.

A count summary at the top of the candidate list reads, for example:

> **23 candidate paths** — 8 corroborated by FIM, 11 detector-only (verified),
> 4 unverified (deselected by default) — estimated 1.2 GB

#### Candidate deselection and operator scope narrowing

Operators can deselect any individual path, or deselect all paths of a given
priority tier. Deselection is tracked on the control plane as a
`scope_narrowed_by_operator` annotation on the `module_actions.payload`. The
agent receives only the narrowed path set; the `candidate_set_hash` is
recomputed over the narrowed set and stored alongside the original hash for
audit trail continuity. This means an operator can reduce blast radius without
needing a new simulation, as long as all retained paths are a subset of the
original simulated set.

Widening beyond the simulated set is not allowed without a fresh simulation. The
stage button is disabled and an inline message reads: "Paths outside the current
simulation cannot be added — re-run simulation to include new scope."

#### Unsafe-overwrite paths

Paths flagged as `unsafe_overwrite` (live version mtime is after the ransomware
detection time) appear in a separate collapsible "Caution" section below the main
candidate list. Each entry shows:
- The live file's last-modified timestamp and size.
- The recovery point file's timestamp and size.
- The computed time delta between the detection event and the live file's mtime.

These paths are always deselected by default. Including them requires checking a
per-path "I understand this will overwrite a file modified after the attack"
confirmation checkbox before the stage button becomes active. This confirmation
is stored in the `module_actions.payload` as a list of
`{path, operator_confirmed_at}` entries.

#### Recovery point metadata display

The console shows the following for the selected recovery point above the
candidate list:

- **Provider**: e.g., "Windows VSS v1.0", "APFS snapshot", "LVM thin snapshot"
- **Created**: absolute timestamp + relative (e.g., "4h before detection")
- **Verified**: green checkmark or red warning
- **Expires**: countdown or "no expiry"
- **Protected roots**: the volume roots the provider confirmed are covered
- **Simulation valid until**: countdown with "Re-simulate required" state
  (disables stage button when expired)

#### Cross-provider candidate sets

When a single incident spans multiple `RollbackCandidateSet` records (different
providers or volume roots), the console renders a tabbed candidate view:
- One tab per provider-root-point triple.
- Each tab independently stageable and approvable.
- A top-level "Incident Recovery" summary shows total paths, total bytes, and
  per-tab restoration status (staged / pending / executed / failed).
- A tab in `failed` state does not block approval of other tabs.

---

### Correlation-Informed Safety Controls

The correlation engine (`app/services/correlation.py`) already computes
`correlation_links` for FIM ↔ EDR events. Rollback can use these links to
make the default blast radius both tighter and more defensible than the raw
detector path list.

#### Correlation links as scope evidence

When a ransomware alert has `correlation_links` rows, the rollback workflow
should:

1. **Use correlated FIM events as an independent cross-check**: if the FIM event
   for a path records a `sha256_hash` *before* the detection time, that hash is
   compared against the recovery-point hash for the same path during simulation.
   A hash match is the strongest possible confirmation that the recovery point
   contains the pre-attack version of the file.

2. **Surface correlation score in the candidate ranking**: `correlation_links.score`
   (already stored in the schema) maps to priority tiers. A score ≥ 0.9 → tier 1,
   score ≥ 0.5 → tier 2. The exact thresholds are policy-configurable.

3. **Use correlation links to tighten the default path count**: if the operator
   takes no action on the candidate list, the default auto-selected set is the
   union of all corroborated paths (tiers 1 + 2) rather than all
   `affected_paths`. This is a meaningful blast-radius reduction: in a typical
   ransomware event that touched 500 files, only the subset with independent FIM
   corroboration defaults to selected, potentially halving the restore scope on
   first pass.

4. **Treat `process_path_match` links with caution**: if a FIM event correlated
   via `process_path_match` (process executable path, not file path) rather than
   `file_path_match`, the candidate path is still rated tier 2 but flagged with
   an inline note: "Correlated by process path — confirm file-level impact before
   staging." This prevents a common false-positive pattern where a legitimate
   updater process hits many file paths that don't need rollback.

#### Correlation-driven severity as a safety gate

The existing correlation engine already performs severity uplift (e.g., high →
critical) when FIM and EDR signals converge. Rollback inherits this gating:

- An alert uplifted from high → critical triggers the dual-approval gate, not
  just the original high gate.
- The approval prompt shows: "Severity uplifted from **high** to **critical**
  due to FIM correlation — dual approval required."
- The `severity_uplifted_from` field on `security_alerts` is used to compute
  the approval requirement, so the gate is consistent whether the operator views
  the alert before or after uplift.

---

### Closed Audit Loop Through the Correlation Model

A key gap in the existing evidence plan was the explicit chain from the FIM event
that elevated the alert through to the per-path restore outcome. This section
defines that chain concretely so the compliance export produces a coherent
incident narrative.

#### The full evidence chain for a corroborated rollback

```
1. fim_events.id  (agent FIM write event on path X)
        ↓
2. correlation_links.id  (correlated to security_alert via file_path_match)
        ↓
3. security_alerts.id  (ransomware alert, severity uplifted from high → critical)
        ↓  evidence_events: correlation.severity_uplift → A.5.25, CC7.2
4. module_actions.id  (rollback_restore staged with simulation_id + candidate_set_hash)
        ↓  evidence_events: endpoint.rollback.rollback_requested → A.5.25, CC6.3
5. module_actions (status: awaiting_approval, two distinct approvers required)
        ↓  evidence_events: endpoint.rollback.rollback_approved → A.5.16, A.5.18, CC6.3, RS.MI
6. RollbackEvidence.restored_paths  (per-path: path X → "restored", hash_before/after)
        ↓  evidence_events: endpoint.rollback.rollback_executed → CC7.5, RS.MI, RC.RP
```

This chain is fully traversable from a single `security_alert.id`. The compliance
export service (`/compliance/export`) already assembles evidence from
`evidence_events` grouped by compliance framework; rollback adds the new action
types to the `endpoint.rollback.*` namespace which `compliance.py` will map to
controls.

#### Back-pointer from RollbackEvidence to correlation_links

To close the loop at the agent level, `RollbackEvidence.decision_trace` should
include the `correlation_link.id` values whose correlated paths are in the
candidate set. Concretely, the decision_trace entry should read:

```
"corroborated_by_correlation_link:<uuid> (file_path_match, score:0.93, fim_event:<uuid>)"
```

The control plane, when recording the agent ack, can cross-check these UUIDs
against `correlation_links` for the linked `security_alert_id`. A mismatch (agent
cites a link not belonging to the alert's tenant) is a consistency error and
should be flagged in the evidence record without failing the ack.

#### Evidence event namespace for rollback

The following action strings extend the existing `endpoint.*` namespace used by
quarantine:

```
endpoint.rollback.simulation_requested   → ISO A.8.16, CC7.2, NIST RS.AN
endpoint.rollback.rollback_requested     → ISO A.5.25, CC6.3
endpoint.rollback.rollback_approved      → ISO A.5.16, A.5.18, CC6.3, NIST RS.MI
endpoint.rollback.rollback_denied        → ISO A.5.25, CC6.3
endpoint.rollback.rollback_executed      → ISO A.12.4.1, CC7.5, NIST RS.MI, RC.RP
endpoint.rollback.rollback_failed        → ISO A.12.6.1, CC7.4, NIST RS.AN
endpoint.rollback.rollback_refused       → ISO A.12.6.1, CC7.4
endpoint.rollback.scope_narrowed         → ISO A.12.4.2, CC7.3  (operator deselected paths)
endpoint.rollback.unsafe_overwrite_confirmed → ISO A.5.25, CC6.3  (explicit operator override)
```

These strings will be added to `compliance.py`'s action-to-controls map when the
rollback routes are implemented. For now they serve as the contract between the
agent evidence schema and the compliance service.

---

### Design Note: Lightweight Correlation Hints in Heartbeats

*This is a forward-looking design note only. No implementation is implied for
this cycle.*

#### Problem statement

The control plane's correlation engine joins `FimEvent[]` and `EdrEvent[]`
post-receipt using path and time-window lookups against the `fim_events` table.
This works at current telemetry volumes. As incident cardinality scales, the
per-heartbeat path lookup over a 10-minute correlation window on a busy endpoint
with hundreds of FIM events becomes a non-trivial DB query load.

Additionally, for rollback candidate ranking, the control plane needs to know
whether a correlated FIM event recorded a hash *before* the attack. Today it must
join `fim_events` to retrieve this; if the agent had already computed this
locally it could be forwarded directly, reducing query complexity at ingestion
time.

#### Proposed hint structure

```rust
// sketch only — not a committed interface
pub struct EdrEventHint {
    /// FIM events the agent observed for the same path within the last K seconds
    pub recent_fim_events_for_path: Vec<FimHint>,
    /// Process accesses to this path the agent observed (if process monitor is active)
    pub recent_process_accesses: Vec<ProcessHint>,
}

pub struct FimHint {
    pub event_type: String,         // "write" | "rename" | "delete" | "create"
    pub observed_at: String,        // ISO-8601
    pub sha256_before: Option<String>,  // pre-modification hash if available
    pub sha256_after: Option<String>,   // post-modification hash if available
}

pub struct ProcessHint {
    pub pid: u32,
    pub executable_path: String,
    pub last_access: String,        // ISO-8601
}
```

The existing `EdrEvent` struct gains an optional `hints: Option<EdrEventHint>`
field. The field is omitted (serialised as `null` / skipped) unless a new
policy flag `emit_correlation_hints: bool` is true.

#### What this would enable

- **Rollback candidate pre-hashing**: A `FimHint` with `sha256_before` lets
  the control plane confirm the pre-attack hash of a candidate file without
  querying `fim_events` separately. This is the single most valuable hint for
  rollback simulation confirmation.
- **Correlation fast-path**: The correlation engine can use agent-supplied hints
  to fast-confirm a path match before running the full `fim_events` lookup,
  reducing median correlation latency on high-event-rate endpoints.
- **Process attribution without a separate query**: `ProcessHint` associates the
  modifying process with the encrypted file in a single heartbeat payload, useful
  for process-tree attribution in the incident timeline.

#### Constraints that must hold

1. **Advisory only**: Hints are a latency optimisation and an enrichment shortcut.
   The control plane must never substitute hints for the authoritative `fim_events`
   table as the source of truth for compliance evidence.
2. **No filtering**: The agent must forward the full `FimEvent[]` array through
   the normal heartbeat path regardless of whether hints are enabled. Hints are
   an *additive supplement*, not a replacement.
3. **Policy-gated**: The `emit_correlation_hints` flag defaults to `false`. Hints
   add payload bytes per EDR event and should only be enabled once benchmarked on
   a representative endpoint. The flag is per-tenant, configurable in
   `policy_documents_v2`.
4. **No new persistence**: The control plane uses hints in-flight during the
   current heartbeat processing round. Hints are not stored in a new table;
   if the processing round fails, the engine falls back to the normal
   `fim_events` query on the next heartbeat.
5. **Window bounds**: The agent only includes FIM hints for the same path within
   the last `correlation_hints_window_seconds` (default: 120s, configurable, must
   be ≤ the server-side `AETHERIX_CORRELATION_WINDOW_SECONDS`). Beyond that
   window, the server-side query is authoritative.

#### Recommendation

Keep as a design note until FIM/EDR correlation volume on real deployments
justifies the complexity. The first trigger to revisit this is if the
`correlate_new_edr_alert` query in `correlation.py` shows up as a meaningful
contributor to heartbeat endpoint latency (P95 > 200ms on the `POST /agent/heartbeat`
path) in production metrics.

---

## Next Planning Phase: Agent-Side Rollback Scaffolding

The following items are the next logical increment for Agent 1, sequenced from
most-valuable to most-complex:

### Phase 1 — Provider Trait + Canary-Driven Recovery Points (This Cycle)

1. **Implement `RollbackProvider` trait** in `agent/src/edr/rollback.rs`:
   - Define the trait with `capabilities()`, `list_recovery_points()`, `simulate_restore()`, `restore()`.
   - Implement a no-op fallback provider (`NoopRollbackProvider`) that reports `provider_unavailable` for all operations.
   - Register the provider in the EDR module's response pipeline so it can be called generically.
2. **Canary-driven recovery-point hints**:
   - When the ransomware canary detector fires, the agent should snapshot the
     current recovery point from the available provider (e.g. VSS/APFS) and
     include `RecoveryPoint` metadata in the heartbeat payload.
   - This gives the control plane visibility into rollback readiness *before*
     a restore is needed.
3. **Extend `EdrEvent` or add a `rollback_readiness` signal**:
   - Add an optional `rollback_readiness: RollbackReadiness | None` field to the
     heartbeat or EDR event payload so the agent can advertise what snapshot
     capabilities and recovery points are available per mount.

### Phase 2 — Rollback Action Handling (Next Cycle)

1. **Handle `rollback` action in `agent/src/edr/response.rs`**:
   - Parse incoming `module_actions` with `action = "rollback"`.
   - Validate the approved intent (action_id, simulation_id, candidate_set_hash,
     recovery_point_id, endpoint binding, expiry).
   - Dispatch to the `RollbackProvider::restore()`.
   - Emit `RollbackEvidence` as a response event.
2. **Idempotency enforcement**:
   - Persist consumed action IDs to `<data_dir>/rollback/consumed_ids`.
   - Re-read on restart; return cached evidence for duplicate intents.

### Phase 3 — Simulation + Candidate Set Enrichment (Next+1 Cycle)

1. **Implement `RollbackProvider::simulate_restore()` for each OS provider**:
   - Enumerate candidate paths from the scope.
   - Verify recovery point existence and coverage.
   - Return `RollbackSimulation` with per-path decisions.
   - Wire into the heartbeat so the control plane can request simulation results
     via an action or on-demand endpoint.
2. **Implement `FimHint` emission**:
   - When `emit_correlation_hints` is true in the effective policy, include
     FIM hints alongside EDR events for the same path within the hint window.
   - See §FimHint above for constraints.

---

*This document is planning-only. No executable remote action exists until the
quarantine management, correlation pipelines, and console approval workflows are stable.
The phases above are the implementation sequence for when the signal is given.*
