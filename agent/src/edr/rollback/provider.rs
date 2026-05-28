use super::types::{
    ProbeResult, RecoveryPoint, RollbackCandidateSet, RollbackCapabilities, RollbackEvidence,
    RollbackPathDecision, RollbackPathOutcome, RollbackRefusal, RollbackScope, RollbackSimulation,
};

/// Interface for snapshot-based ransomware rollback.
///
/// Every method returns deterministic results. Providers that are not
/// available (NoopRollbackProvider, uninitialised OS providers) return
/// empty/refusal results rather than erroring.
///
/// ## What a real OS provider (VSS / APFS / Btrfs) must do differently
///
/// The `SimulationRollbackProvider` returns synthetic results and does not
/// touch the host. A real provider must:
///
/// 1. **`probe()` at startup** — Return a `ProbeResult` with all fields
///    populated from actual OS interrogation (not just `capabilities()`):
///
///    **`volume_capabilities`** — Enumerate volumes that have snapshot
///    support:
///    - *Windows VSS*: query `IWbemServices` for `Win32_ShadowCopy` to
///      list volumes with shadow-copy support. Populate as `"vss:C:"`,
///      `"vss:D:"`.
///    - *macOS APFS*: run `tmutil listlocalsnapshots /` or parse
///      `diskutil apfs list` to identify APFS volumes. The root volume
///      group may have different snapshot semantics from data volumes.
///      Populate as `"apfs:/"`, `"apfs:/System/Volumes/Data"`.
///    - *Linux Btrfs*: read `/sys/fs/btrfs/<UUID>/` subvolumes. Populate
///      as `"btrfs:/@home"`, `"btrfs:/@"`.
///
///    **`snapshot_service_info`** — Human-readable status of the
///    underlying snapshot service. Examples:
///    - `"VSS v1.6, Writers: 3/5 ready (2 stalled: SqlWriter, FsWriter)"`
///    - `"APFS snapshots enabled on 2 of 3 volumes"`  
///    - `"Btrfs: no snapshots exist on any subvolume"`
///    - `None` when the provider has no service-layer to report
///
///    **`privilege_boundary`** — Describe the exact privilege boundary
///    the probe detected:
///    - *Windows VSS*: check `SeBackupPrivilege` and `SeRestorePrivilege`.
///      Return `"requires SeBackupPrivilege (detected)"` or
///      `"missing SeBackupPrivilege (agent runs as {username})"`.
///    - *macOS APFS*: check root / entitlement. Return
///      `"root required (process euid=0)"` or
///      `"com.apple.private.apfs.snapshot entitlement missing"`.
///    - *Linux*: check if the agent can execute the snapshot CLI without
///      password / sudo. Return `"cap_dac_read_search=1, cap_sys_admin=0"`.
///
///    **`functional`** — `true` only when ALL of:
///    - The snapshot service is installed and running
///    - At least one volume reports snapshot capability
///    - The agent has sufficient privilege for all probe steps
///    - `diagnosis` must explain which check failed when `functional=false`
///
/// 2. **`list_recovery_points()`** — Enumerate OS snapshots rather than
///    returning a pre-configured list. Must report `verified=false` for
///    any point whose on-disk existence cannot be proven (e.g. VSS shadow
///    copy that was deleted out of band). Must respect `expires_at` from
///    the point metadata, not a hard-coded constant.
///
/// 3. **`simulate_restore()`** — For each candidate path, compare the
///    snapshot copy against the live file:
///    - If the live file does not exist → `Restored` (file was deleted
///      by ransomware).
///    - If the live file exists and its mtime / hash matches the snapshot
///      → `Skipped` with reason `"no_change_needed"`.
///    - If the live file is newer than the snapshot → `RefusedOutOfScope`
///      with reason `"unsafe_overwrite"`.
///    - If the snapshot path does not exist → `RefusedOutOfScope` with
///      reason `"not_found_in_point"`.
///
/// 4. **`restore()`** — Perform the actual file copy from the snapshot
///    view (VSS shadow copy device, APFS snapshot mount, Btrfs subvol
///    snapshot) to the live path. Must:
///    - Preserve ownership, ACLs, and timestamps where the OS API allows.
///    - Report each path's `hash_before` (from the snapshot) and
///      `hash_after` (after copy).
///    - Use a temporary mount / snapshot-access technique that does NOT
///      mutate the snapshot itself.
///
/// 5. **Safety invariants** — Never fall back to a non-verified point
///    (`verified == false`). Never restore to a path that isn't covered
///    by `protected_roots`. Never delete the snapshot after restoring
///    (expiry is controlled by the OS, not the agent).
pub trait RollbackProvider: Send + Sync {
    /// Advertise what this provider supports.
    fn capabilities(&self) -> RollbackCapabilities;

    /// List recovery points that could cover paths in the given scope.
    fn list_recovery_points(&self, scope: &RollbackScope) -> anyhow::Result<Vec<RecoveryPoint>>;

    /// Simulate a restore from the given candidate set without mutating the host.
    fn simulate_restore(&self, candidates: &RollbackCandidateSet) -> anyhow::Result<RollbackSimulation>;

    /// Execute a restore after operator approval.
    fn restore(
        &self,
        candidates: &RollbackCandidateSet,
        approved_action_id: &str,
    ) -> anyhow::Result<RollbackEvidence>;

    /// Run a startup probe to determine what the provider can actually do
    /// on the current host. The default implementation returns a best-effort
    /// estimate from `capabilities()`. Real providers should override to
    /// perform actual OS-level checks.
    fn probe(&self) -> ProbeResult {
        let caps = self.capabilities();
        ProbeResult {
            functional: caps.available,
            diagnosis: if caps.available {
                format!("{} provider is available", caps.provider_name)
            } else {
                format!("{} provider is not available", caps.provider_name)
            },
            recovery_point_count: 0,
            available_filesystems: caps.supported_filesystems.clone(),
            service_available: caps.available,
            sufficient_privilege: caps.available,
            volume_capabilities: vec![],
            snapshot_service_info: None,
            privilege_boundary: Some(caps.privilege_context.clone()),
        }
    }
}

/// ---------------------------------------------------------------------------
/// NoopRollbackProvider — context-aware refusal fallback
/// ---------------------------------------------------------------------------

/// No-op fallback that always reports `available = false`.
///
/// Returns distinct refusal states depending on invocation context:
/// - `provider_unavailable` — default state; no snapshot provider configured
/// - `candidate_scope_mismatch` — called with empty/no paths
/// - `recovery_point_unverified` — called without a verified recovery point
pub struct NoopRollbackProvider;

impl NoopRollbackProvider {
    fn decision_trace_base(refusal: &RollbackRefusal) -> Vec<String> {
        vec![
            format!("noop provider: {}", refusal.as_str()),
            "noop provider has no snapshot capability".to_string(),
            format!("provider_refusal={}", refusal.as_str()),
        ]
    }
}

impl NoopRollbackProvider {
    fn probe_impl(&self) -> ProbeResult {
        ProbeResult {
            functional: false,
            diagnosis: "noop provider: no snapshot capability configured".to_string(),
            recovery_point_count: 0,
            available_filesystems: vec![],
            service_available: false,
            sufficient_privilege: false,
            volume_capabilities: vec![],
            snapshot_service_info: None,
            privilege_boundary: Some("noop: no privilege context".to_string()),
        }
    }
}

impl RollbackProvider for NoopRollbackProvider {
    fn probe(&self) -> ProbeResult {
        self.probe_impl()
    }

    fn capabilities(&self) -> RollbackCapabilities {
        RollbackCapabilities {
            provider_name: "noop".to_string(),
            provider_version: "0.1.0".to_string(),
            available: false,
            supported_os: vec![],
            supported_filesystems: vec![],
            privilege_context: "none".to_string(),
        }
    }

    fn list_recovery_points(&self, _scope: &RollbackScope) -> anyhow::Result<Vec<RecoveryPoint>> {
        Ok(Vec::new())
    }

    fn simulate_restore(&self, candidates: &RollbackCandidateSet) -> anyhow::Result<RollbackSimulation> {
        let refusal = if candidates.paths.is_empty() && candidates.candidate_set_hash.is_empty() {
            RollbackRefusal::CandidateScopeMismatch
        } else {
            RollbackRefusal::ProviderUnavailable
        };

        Ok(RollbackSimulation {
            simulation_id: uuid::Uuid::new_v4().to_string(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            candidate_count: 0,
            restorable_count: 0,
            skipped_paths: vec![],
            destructive: false,
            valid_until: chrono::Utc::now().to_rfc3339(),
            decision_trace: Self::decision_trace_base(&refusal),
        })
    }

    fn restore(
        &self,
        candidates: &RollbackCandidateSet,
        approved_action_id: &str,
    ) -> anyhow::Result<RollbackEvidence> {
        let refusal = if candidates.paths.is_empty() && candidates.candidate_set_hash.is_empty() {
            RollbackRefusal::CandidateScopeMismatch
        } else if candidates.recovery_point_id.is_empty() {
            RollbackRefusal::RecoveryPointUnverified
        } else {
            RollbackRefusal::ProviderUnavailable
        };

        Ok(RollbackEvidence {
            status: "not_applicable".to_string(),
            decision_trace: Self::decision_trace_base(&refusal),
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            approved_action_id: approved_action_id.to_string(),
            provider: "noop".to_string(),
            recovery_point_id: candidates.recovery_point_id.clone(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: Some(format!(
                "{}: noop provider has no snapshot capability",
                refusal.as_str()
            )),
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "0.1.0".to_string(),
            os_platform: std::env::consts::OS.to_string(),
            privilege_context: "none".to_string(),
        })
    }
}

/// ---------------------------------------------------------------------------
/// SimulationRollbackProvider — configurable stub for testing restore flows
/// ---------------------------------------------------------------------------

/// A configurable provider stub that advertises availability and returns
/// synthetic recovery points and restore results.
///
/// This provider:
/// - Can be configured as `available` or not
/// - Returns pre-configured recovery points
/// - In `simulate_restore()`, maps candidate paths to synthetic outcomes
/// - In `restore()`, produces realistic RollbackEvidence without host mutation
///
/// Use in development and integration tests where no real OS snapshot provider
/// is available.
const DEFAULT_MAX_BYTES_PER_RESTORE: u64 = 10_737_418_240; // 10 GiB
const DEFAULT_MIN_RECOVERY_POINT_AGE_SECS: u64 = 300;      // 5 min
const DEFAULT_MAX_RECOVERY_POINT_AGE_SECS: u64 = 604_800;  // 7 days

pub struct SimulationRollbackProvider {
    available: bool,
    provider_name: String,
    provider_version: String,
    supported_os: Vec<String>,
    recovery_points: Vec<RecoveryPoint>,
    privilege_context: String,
    fail_rate: f64,
    max_paths_per_restore: usize,
    max_bytes_per_restore: u64,
    min_recovery_point_age_secs: u64,
    max_recovery_point_age_secs: u64,
}

impl SimulationRollbackProvider {
    pub fn new(available: bool) -> Self {
        Self {
            available,
            provider_name: "simulation".to_string(),
            provider_version: "0.3.0".to_string(),
            supported_os: vec![std::env::consts::OS.to_string()],
            recovery_points: vec![],
            privilege_context: "user".to_string(),
            fail_rate: 0.0,
            max_paths_per_restore: 500,
            max_bytes_per_restore: DEFAULT_MAX_BYTES_PER_RESTORE,
            min_recovery_point_age_secs: DEFAULT_MIN_RECOVERY_POINT_AGE_SECS,
            max_recovery_point_age_secs: DEFAULT_MAX_RECOVERY_POINT_AGE_SECS,
        }
    }

    pub fn with_recovery_points(mut self, points: Vec<RecoveryPoint>) -> Self {
        self.recovery_points = points;
        self
    }

    pub fn with_provider_name(mut self, name: &str) -> Self {
        self.provider_name = name.to_string();
        self
    }

    pub fn with_fail_rate(mut self, rate: f64) -> Self {
        self.fail_rate = rate.clamp(0.0, 1.0);
        self
    }

    pub fn with_privilege_context(mut self, context: &str) -> Self {
        self.privilege_context = context.to_string();
        self
    }

    pub fn with_max_paths_per_restore(mut self, max: usize) -> Self {
        self.max_paths_per_restore = max;
        self
    }

    pub fn with_max_bytes_per_restore(mut self, max: u64) -> Self {
        self.max_bytes_per_restore = max;
        self
    }

    pub fn with_min_recovery_point_age_secs(mut self, secs: u64) -> Self {
        self.min_recovery_point_age_secs = secs;
        self
    }

    pub fn with_max_recovery_point_age_secs(mut self, secs: u64) -> Self {
        self.max_recovery_point_age_secs = secs;
        self
    }

    fn matching_recovery_points(&self, scope: &RollbackScope) -> Vec<RecoveryPoint> {
        if self.recovery_points.is_empty() {
            return vec![];
        }
        let now = chrono::Utc::now();

        let mut matched: Vec<RecoveryPoint> = self
            .recovery_points
            .iter()
            .filter(|rp| {
                // --- Verified and read-only ---
                if !rp.verified || !rp.read_only {
                    return false;
                }

                // --- Protected-roots coverage ---
                if !scope
                    .affected_paths
                    .iter()
                    .any(|p| rp.protected_roots.iter().any(|root| p.starts_with(root)))
                {
                    return false;
                }

                // --- min_recovery_point_age: snapshot must be at least N seconds old ---
                if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&rp.created_at) {
                    let created_utc = created.with_timezone(&chrono::Utc);
                    let age_secs = (now - created_utc).num_seconds();
                    if age_secs < self.min_recovery_point_age_secs as i64 {
                        return false;
                    }
                    if age_secs > self.max_recovery_point_age_secs as i64 {
                        return false;
                    }
                }

                // --- expires_at: point must not have expired ---
                if let Some(ref expires) = rp.expires_at {
                    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires) {
                        let expiry_utc = expiry.with_timezone(&chrono::Utc);
                        if now > expiry_utc {
                            return false;
                        }
                    }
                }

                true
            })
            .cloned()
            .collect();
        matched.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        matched
    }

    fn evaluate_paths(&self, candidates: &RollbackCandidateSet) -> Vec<RollbackPathDecision> {
        let mut decisions = Vec::with_capacity(candidates.paths.len());

        // --- Blast-radius: max_paths_per_restore ---
        if candidates.paths.len() > self.max_paths_per_restore {
            decisions.push(RollbackPathDecision {
                path: format!(
                    "{} paths requested (limit {})",
                    candidates.paths.len(),
                    self.max_paths_per_restore
                ),
                outcome: RollbackPathOutcome::RefusedOutOfScope,
                reason: format!(
                    "path count {} exceeds max_paths_per_restore={}",
                    candidates.paths.len(),
                    self.max_paths_per_restore
                ),
                bytes_affected: 0,
                hash_before: None,
                hash_after: None,
                metadata_diff: None,
            });
            return decisions;
        }

        // --- Blast-radius: max_bytes_per_restore ---
        if candidates.total_bytes_estimate > self.max_bytes_per_restore {
            decisions.push(RollbackPathDecision {
                path: format!(
                    "{} bytes requested (limit {})",
                    candidates.total_bytes_estimate, self.max_bytes_per_restore
                ),
                outcome: RollbackPathOutcome::RefusedOutOfScope,
                reason: format!(
                    "byte estimate {} exceeds max_bytes_per_restore={}",
                    candidates.total_bytes_estimate, self.max_bytes_per_restore
                ),
                bytes_affected: 0,
                hash_before: None,
                hash_after: None,
                metadata_diff: None,
            });
            return decisions;
        }

        // --- Protected-root allowlist ---
        let protected_roots: Vec<String> = self
            .matching_recovery_points(&candidates.scope)
            .first()
            .map(|rp| rp.protected_roots.clone())
            .unwrap_or_default();

        for p in &candidates.paths {
            // --- Blast-radius: max_directory_depth ---
            let depth = p.matches('/').count() as u8;
            if depth > candidates.max_depth {
                decisions.push(RollbackPathDecision {
                    path: p.clone(),
                    outcome: RollbackPathOutcome::RefusedOutOfScope,
                    reason: format!("depth {depth} exceeds max_depth={}", candidates.max_depth),
                    bytes_affected: 0,
                    hash_before: None,
                    hash_after: None,
                    metadata_diff: None,
                });
                continue;
            }

            // --- Protected-root allowlist enforcement ---
            if !protected_roots.is_empty()
                && !protected_roots.iter().any(|root| p.starts_with(root))
            {
                decisions.push(RollbackPathDecision {
                    path: p.clone(),
                    outcome: RollbackPathOutcome::RefusedOutOfScope,
                    reason: format!(
                        "path not under any protected root: {:?}",
                        protected_roots
                    ),
                    bytes_affected: 0,
                    hash_before: None,
                    hash_after: None,
                    metadata_diff: None,
                });
                continue;
            }

            decisions.push(RollbackPathDecision {
                path: p.clone(),
                outcome: RollbackPathOutcome::Restored,
                reason: "in_point_and_not_overwritten".to_string(),
                bytes_affected: 4096,
                hash_before: Some("pre_restore_hash".to_string()),
                hash_after: None,
                metadata_diff: None,
            });
        }

        decisions
    }
}

impl SimulationRollbackProvider {
    fn probe_impl(&self) -> ProbeResult {
        let volume_caps: Vec<String> = self
            .recovery_points
            .iter()
            .flat_map(|rp| &rp.protected_roots)
            .map(|root| format!("simulation:{}", root))
            .collect();
        let snapshot_info = if self.available {
            Some(format!(
                "simulation provider: {} recovery point(s) configured, privilege_context={}, fail_rate={}",
                self.recovery_points.len(),
                self.privilege_context,
                self.fail_rate,
            ))
        } else {
            None
        };
        ProbeResult {
            functional: self.available,
            diagnosis: if self.available {
                format!(
                    "{} v{}: simulation provider configured, {} recovery point(s)",
                    self.provider_name,
                    self.provider_version,
                    self.recovery_points.len(),
                )
            } else {
                format!("{}: simulation provider marked unavailable", self.provider_name)
            },
            recovery_point_count: self.recovery_points.len(),
            available_filesystems: vec!["apfs".to_string(), "ntfs".to_string(), "ext4".to_string()],
            service_available: self.available,
            sufficient_privilege: self.available,
            volume_capabilities: volume_caps,
            snapshot_service_info: snapshot_info,
            privilege_boundary: Some(format!("simulated: {}", self.privilege_context)),
        }
    }
}

impl RollbackProvider for SimulationRollbackProvider {
    fn probe(&self) -> ProbeResult {
        self.probe_impl()
    }

    fn capabilities(&self) -> RollbackCapabilities {
        RollbackCapabilities {
            provider_name: self.provider_name.clone(),
            provider_version: self.provider_version.clone(),
            available: self.available,
            supported_os: self.supported_os.clone(),
            supported_filesystems: vec!["apfs".to_string(), "ntfs".to_string(), "ext4".to_string()],
            privilege_context: self.privilege_context.clone(),
        }
    }

    fn list_recovery_points(&self, scope: &RollbackScope) -> anyhow::Result<Vec<RecoveryPoint>> {
        if !self.available {
            return Ok(vec![]);
        }
        Ok(self.matching_recovery_points(scope))
    }

    fn simulate_restore(&self, candidates: &RollbackCandidateSet) -> anyhow::Result<RollbackSimulation> {
        if !self.available {
            return Ok(RollbackSimulation {
                simulation_id: uuid::Uuid::new_v4().to_string(),
                candidate_set_hash: candidates.candidate_set_hash.clone(),
                candidate_count: 0,
                restorable_count: 0,
                skipped_paths: vec![],
                destructive: false,
                valid_until: chrono::Utc::now().to_rfc3339(),
                decision_trace: vec![format!(
                    "simulation provider unavailable ({}: simulation)",
                    self.provider_name
                )],
            });
        }

        let decisions = self.evaluate_paths(candidates);
        let restorable = decisions
            .iter()
            .filter(|d| d.outcome == RollbackPathOutcome::Restored)
            .count();
        let skipped: Vec<RollbackPathDecision> = decisions
            .into_iter()
            .filter(|d| d.outcome != RollbackPathOutcome::Restored)
            .collect();

        Ok(RollbackSimulation {
            simulation_id: uuid::Uuid::new_v4().to_string(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            candidate_count: candidates.paths.len(),
            restorable_count: restorable,
            skipped_paths: skipped,
            destructive: false,
            valid_until: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            decision_trace: vec![
                format!("simulation provider: {} candidate(s), {} restorable", candidates.paths.len(), restorable),
                format!("recovery_point_id={}", candidates.recovery_point_id),
            ],
        })
    }

    fn restore(
        &self,
        candidates: &RollbackCandidateSet,
        approved_action_id: &str,
    ) -> anyhow::Result<RollbackEvidence> {
        if !self.available {
            return Ok(RollbackEvidence {
                status: "not_applicable".to_string(),
                decision_trace: vec![format!(
                    "simulation provider not available ({}: simulation)",
                    self.provider_name
                )],
                evidence_controls: vec![],
                endpoint_id: String::new(),
                customer_id: None,
                policy_version: String::new(),
                requester_id: String::new(),
                approver_ids: vec![],
                simulation_id: String::new(),
                candidate_set_hash: candidates.candidate_set_hash.clone(),
                approved_action_id: approved_action_id.to_string(),
                provider: self.provider_name.clone(),
                recovery_point_id: candidates.recovery_point_id.clone(),
                recovery_point_created_at: String::new(),
                recovery_point_expires_at: None,
                recovery_point_verified: false,
                metadata_preserved: None,
                provider_refusal: Some("provider_unavailable: simulation provider not available".to_string()),
                restored_paths: vec![],
                failed_paths: vec![],
                skipped_paths: vec![],
                provider_version: self.provider_version.clone(),
                os_platform: std::env::consts::OS.to_string(),
                privilege_context: self.privilege_context.clone(),
            });
        }

        let decisions = self.evaluate_paths(candidates);
        let mut restored = Vec::new();
        let mut failed = Vec::new();
        let mut skipped = Vec::new();

        for d in decisions {
            match d.outcome {
                RollbackPathOutcome::Restored => {
                    restored.push(RollbackPathDecision {
                        path: d.path,
                        outcome: RollbackPathOutcome::Restored,
                        reason: "ok".to_string(),
                        bytes_affected: d.bytes_affected,
                        hash_before: d.hash_before,
                        hash_after: Some("post_restore_hash".to_string()),
                        metadata_diff: Some(vec!["atime_updated".to_string()]),
                    });
                }
                RollbackPathOutcome::FailedIntegrity => {
                    failed.push(d);
                }
                RollbackPathOutcome::Skipped | RollbackPathOutcome::RefusedOutOfScope => {
                    skipped.push(d);
                }
            }
        }

        Ok(RollbackEvidence {
            status: if restored.is_empty() && failed.is_empty() {
                "not_applicable".to_string()
            } else if !failed.is_empty() && restored.is_empty() {
                "failed".to_string()
            } else if !failed.is_empty() {
                "executed".to_string()
            } else {
                "executed".to_string()
            },
            decision_trace: vec![
                format!(
                    "simulation restore: restored={}, failed={}, skipped={}",
                    restored.len(),
                    failed.len(),
                    skipped.len()
                ),
                format!("approved_action_id={}", approved_action_id),
            ],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            approved_action_id: approved_action_id.to_string(),
            provider: self.provider_name.clone(),
            recovery_point_id: candidates.recovery_point_id.clone(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: true,
            metadata_preserved: Some(true),
            provider_refusal: None,
            restored_paths: restored,
            failed_paths: failed,
            skipped_paths: skipped,
            provider_version: self.provider_version.clone(),
            os_platform: std::env::consts::OS.to_string(),
            privilege_context: self.privilege_context.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::rollback::types::{RollbackPathOutcome, RollbackScope};

    // -----------------------------------------------------------------------
    // Noop provider tests
    // -----------------------------------------------------------------------

    #[test]
    fn noop_capabilities_reports_unavailable() {
        let provider = NoopRollbackProvider;
        let caps = provider.capabilities();
        assert!(!caps.available);
        assert_eq!(caps.provider_name, "noop");
        assert_eq!(caps.privilege_context, "none");
    }

    #[test]
    fn noop_list_recovery_points_is_empty() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/docs".to_string()],
            observed_at: "2026-05-28T12:00:00Z".to_string(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert!(points.is_empty());
    }

    #[test]
    fn noop_simulate_restore_refuses_with_provider_unavailable_when_paths_given() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-1".to_string(),
            paths: vec!["/a".to_string()],
            total_bytes_estimate: 100,
            max_depth: 8,
            candidate_set_hash: "hash-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 0);
        assert!(sim
            .decision_trace
            .iter()
            .any(|d| d.contains("provider_unavailable")));
    }

    #[test]
    fn noop_simulate_restore_refuses_with_scope_mismatch_when_empty() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: String::new(),
            detector_rule_id: String::new(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: String::new(),
            paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: String::new(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert!(sim
            .decision_trace
            .iter()
            .any(|d| d.contains("candidate_scope_mismatch")));
    }

    #[test]
    fn noop_restore_returns_not_applicable() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-1".to_string(),
            paths: vec!["/a".to_string()],
            total_bytes_estimate: 100,
            max_depth: 8,
            candidate_set_hash: "hash-1".to_string(),
        };
        let evidence = provider.restore(&candidates, "action-1").unwrap();
        assert_eq!(evidence.status, "not_applicable");
        assert!(evidence.provider_refusal.is_some());
        assert!(evidence
            .provider_refusal
            .as_ref()
            .unwrap()
            .contains("provider_unavailable"));
    }

    #[test]
    fn noop_restore_refuses_with_recovery_point_unverified_when_no_point_id() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: String::new(),
            paths: vec!["/a".to_string()],
            total_bytes_estimate: 100,
            max_depth: 8,
            candidate_set_hash: "hash-1".to_string(),
        };
        let evidence = provider.restore(&candidates, "action-1").unwrap();
        assert!(evidence.provider_refusal.unwrap().contains("recovery_point_unverified"));
    }

    #[test]
    fn noop_restore_refuses_with_scope_mismatch_when_empty_paths() {
        let provider = NoopRollbackProvider;
        let scope = RollbackScope {
            incident_id: String::new(),
            detector_rule_id: String::new(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: String::new(),
            paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: String::new(),
        };
        let evidence = provider.restore(&candidates, "action-1").unwrap();
        assert!(evidence
            .provider_refusal
            .unwrap()
            .contains("candidate_scope_mismatch"));
    }

    // -----------------------------------------------------------------------
    // Simulation provider tests
    // -----------------------------------------------------------------------

    fn sample_recovery_point() -> RecoveryPoint {
        let now = chrono::Utc::now();
        RecoveryPoint {
            id: "rp-sim-1".to_string(),
            provider: "simulation".to_string(),
            created_at: (now - chrono::Duration::hours(4)).to_rfc3339(),
            expires_at: Some((now + chrono::Duration::days(7)).to_rfc3339()),
            protected_roots: vec!["/home".to_string(), "/etc".to_string()],
            read_only: true,
            verified: true,
        }
    }

    #[test]
    fn simulation_provider_advertises_availability_when_configured() {
        let provider = SimulationRollbackProvider::new(true)
            .with_provider_name("simulation-test");
        let caps = provider.capabilities();
        assert!(caps.available);
        assert_eq!(caps.provider_name, "simulation-test");
    }

    #[test]
    fn simulation_provider_lists_recovery_points_for_matching_scope() {
        let rp = sample_recovery_point();
        let provider = SimulationRollbackProvider::new(true)
            .with_min_recovery_point_age_secs(0)
            .with_recovery_points(vec![rp]);

        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/docs/file.txt".to_string()],
            observed_at: "2026-05-28T12:00:00Z".to_string(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].id, "rp-sim-1");
    }

    #[test]
    fn simulation_provider_returns_empty_points_when_not_available() {
        let rp = sample_recovery_point();
        let provider = SimulationRollbackProvider::new(false)
            .with_recovery_points(vec![rp]);

        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/docs".to_string()],
            observed_at: "2026-05-28T12:00:00Z".to_string(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert!(points.is_empty());
    }

    #[test]
    fn simulation_provider_simulate_restore_returns_restorable_count() {
        let provider = SimulationRollbackProvider::new(true);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home".to_string()],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/home/a.txt".to_string(), "/home/b.txt".to_string()],
            total_bytes_estimate: 8192,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 2);
        assert_eq!(sim.restorable_count, 2);
    }

    #[test]
    fn simulation_provider_simulate_respects_max_depth() {
        let provider = SimulationRollbackProvider::new(true);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/a/b/c/d/e/f/g/h/i/j/k.txt".to_string()],
            total_bytes_estimate: 0,
            max_depth: 3,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 1);
        assert_eq!(sim.restorable_count, 0);
        assert_eq!(sim.skipped_paths.len(), 1);
        assert_eq!(
            sim.skipped_paths[0].outcome,
            RollbackPathOutcome::RefusedOutOfScope
        );
    }

    #[test]
    fn simulation_provider_restore_produces_restored_paths() {
        let provider = SimulationRollbackProvider::new(true);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/home/doc.txt".to_string()],
            total_bytes_estimate: 4096,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let evidence = provider.restore(&candidates, "action-sim-1").unwrap();
        assert_eq!(evidence.status, "executed");
        assert_eq!(evidence.restored_paths.len(), 1);
        assert_eq!(evidence.restored_paths[0].outcome, RollbackPathOutcome::Restored);
        assert_eq!(evidence.approved_action_id, "action-sim-1");
    }

    #[test]
    fn simulation_provider_simulate_enforces_max_paths_per_restore() {
        let provider = SimulationRollbackProvider::new(true).with_max_paths_per_restore(2);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/a".to_string(), "/b".to_string(), "/c".to_string()],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 3);
        assert_eq!(sim.restorable_count, 0);
        assert_eq!(sim.skipped_paths.len(), 1);
        assert_eq!(
            sim.skipped_paths[0].outcome,
            RollbackPathOutcome::RefusedOutOfScope
        );
        assert!(sim.skipped_paths[0].reason.contains("max_paths_per_restore"));
    }

    #[test]
    fn simulation_provider_restore_enforces_max_paths_per_restore() {
        let provider = SimulationRollbackProvider::new(true).with_max_paths_per_restore(1);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/a".to_string(), "/b".to_string()],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let evidence = provider.restore(&candidates, "action-sim-br-1").unwrap();
        assert_eq!(evidence.restored_paths.len(), 0);
        assert_eq!(evidence.skipped_paths.len(), 1);
    }

    #[test]
    fn simulation_provider_restore_enforces_protected_root_allowlist() {
        let now = chrono::Utc::now();
        let rp = RecoveryPoint {
            id: "rp-sim-prot".to_string(),
            provider: "simulation".to_string(),
            created_at: (now - chrono::Duration::hours(4)).to_rfc3339(),
            expires_at: Some((now + chrono::Duration::days(7)).to_rfc3339()),
            protected_roots: vec!["/home".to_string(), "/etc".to_string()],
            read_only: true,
            verified: true,
        };
        let provider = SimulationRollbackProvider::new(true)
            .with_min_recovery_point_age_secs(0)
            .with_recovery_points(vec![rp]);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home".to_string(), "/var".to_string()],
            observed_at: "2026-05-28T12:00:00Z".to_string(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-prot".to_string(),
            paths: vec!["/home/user/doc.txt".to_string(), "/var/log/syslog".to_string()],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 2);
        assert_eq!(sim.restorable_count, 1);
        assert_eq!(sim.skipped_paths.len(), 1);
        assert_eq!(
            sim.skipped_paths[0].outcome,
            RollbackPathOutcome::RefusedOutOfScope
        );
        assert!(sim.skipped_paths[0].reason.contains("protected root"));
    }

    #[test]
    fn simulation_provider_simulate_enforces_max_bytes_per_restore() {
        let provider = SimulationRollbackProvider::new(true)
            .with_max_bytes_per_restore(4096);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/home/a.txt".to_string()],
            total_bytes_estimate: 8192,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let sim = provider.simulate_restore(&candidates).unwrap();
        assert_eq!(sim.candidate_count, 1);
        assert_eq!(sim.restorable_count, 0);
        assert_eq!(sim.skipped_paths.len(), 1);
        assert_eq!(
            sim.skipped_paths[0].outcome,
            RollbackPathOutcome::RefusedOutOfScope
        );
        assert!(sim.skipped_paths[0].reason.contains("max_bytes_per_restore"));
    }

    #[test]
    fn simulation_provider_restore_enforces_max_bytes_per_restore() {
        let provider = SimulationRollbackProvider::new(true)
            .with_max_bytes_per_restore(1024);
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-sim-1".to_string(),
            paths: vec!["/home/big.bin".to_string()],
            total_bytes_estimate: 999_999,
            max_depth: 8,
            candidate_set_hash: "hash-sim-1".to_string(),
        };
        let evidence = provider.restore(&candidates, "action-bytes-1").unwrap();
        assert_eq!(evidence.restored_paths.len(), 0);
        assert_eq!(evidence.skipped_paths.len(), 1);
    }

    #[test]
    fn simulation_provider_filters_recovery_points_by_min_age() {
        let now = chrono::Utc::now();
        let too_fresh = now - chrono::Duration::seconds(30); // only 30s old
        let old_enough = now - chrono::Duration::seconds(600); // 10 min old

        let rp_too_fresh = RecoveryPoint {
            id: "rp-too-fresh".to_string(),
            provider: "simulation".to_string(),
            created_at: too_fresh.to_rfc3339(),
            expires_at: None,
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };
        let rp_old_enough = RecoveryPoint {
            id: "rp-old-enough".to_string(),
            provider: "simulation".to_string(),
            created_at: old_enough.to_rfc3339(),
            expires_at: None,
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };

        let provider = SimulationRollbackProvider::new(true)
            .with_min_recovery_point_age_secs(300) // 5 min
            .with_recovery_points(vec![rp_too_fresh, rp_old_enough]);

        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/file.txt".to_string()],
            observed_at: now.to_rfc3339(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert_eq!(points.len(), 1, "only the old-enough point should match");
        assert_eq!(points[0].id, "rp-old-enough");
    }

    #[test]
    fn simulation_provider_filters_recovery_points_by_max_age() {
        let now = chrono::Utc::now();
        let too_old = now - chrono::Duration::days(30);
        let recent = now - chrono::Duration::hours(6);

        let rp_too_old = RecoveryPoint {
            id: "rp-too-old".to_string(),
            provider: "simulation".to_string(),
            created_at: too_old.to_rfc3339(),
            expires_at: None,
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };
        let rp_recent = RecoveryPoint {
            id: "rp-recent".to_string(),
            provider: "simulation".to_string(),
            created_at: recent.to_rfc3339(),
            expires_at: None,
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };

        let provider = SimulationRollbackProvider::new(true)
            .with_max_recovery_point_age_secs(604_800) // 7 days
            .with_recovery_points(vec![rp_too_old, rp_recent]);

        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/file.txt".to_string()],
            observed_at: now.to_rfc3339(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert_eq!(points.len(), 1, "only the recent point should match");
        assert_eq!(points[0].id, "rp-recent");
    }

    #[test]
    fn simulation_provider_filters_recovery_points_by_expiry() {
        let now = chrono::Utc::now();
        let expired = now - chrono::Duration::days(1);
        let valid = now + chrono::Duration::days(7);

        let rp_expired = RecoveryPoint {
            id: "rp-expired".to_string(),
            provider: "simulation".to_string(),
            created_at: (now - chrono::Duration::hours(2)).to_rfc3339(),
            expires_at: Some(expired.to_rfc3339()),
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };
        let rp_valid = RecoveryPoint {
            id: "rp-valid".to_string(),
            provider: "simulation".to_string(),
            created_at: (now - chrono::Duration::hours(1)).to_rfc3339(),
            expires_at: Some(valid.to_rfc3339()),
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };

        let provider = SimulationRollbackProvider::new(true)
            .with_recovery_points(vec![rp_expired, rp_valid]);

        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/home/user/file.txt".to_string()],
            observed_at: now.to_rfc3339(),
        };
        let points = provider.list_recovery_points(&scope).unwrap();
        assert_eq!(points.len(), 1, "only the valid point should match");
        assert_eq!(points[0].id, "rp-valid");
    }

    #[test]
    fn simulation_provider_restore_refuses_when_not_available() {
        let provider = SimulationRollbackProvider::new(false);
        let scope = RollbackScope {
            incident_id: String::new(),
            detector_rule_id: String::new(),
            affected_paths: vec![],
            observed_at: String::new(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: String::new(),
            paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
            candidate_set_hash: String::new(),
        };
        let evidence = provider.restore(&candidates, "action-sim-2").unwrap();
        assert_eq!(evidence.status, "not_applicable");
        assert!(evidence.provider_refusal.is_some());
    }

    // -----------------------------------------------------------------------
    // Probe tests
    // -----------------------------------------------------------------------

    #[test]
    fn noop_probe_reports_not_functional() {
        let provider = NoopRollbackProvider;
        let result = provider.probe();
        assert!(!result.functional);
        assert!(result.diagnosis.contains("noop"));
        assert_eq!(result.recovery_point_count, 0);
        assert!(!result.service_available);
        assert!(!result.sufficient_privilege);
    }

    #[test]
    fn simulation_probe_reports_functional_when_available() {
        let rp = RecoveryPoint {
            id: "rp-probe-1".to_string(),
            provider: "simulation".to_string(),
            created_at: "2026-05-28T08:00:00Z".to_string(),
            expires_at: None,
            protected_roots: vec![],
            read_only: true,
            verified: true,
        };
        let provider = SimulationRollbackProvider::new(true)
            .with_recovery_points(vec![rp]);
        let result = provider.probe();
        assert!(result.functional);
        assert!(result.diagnosis.contains("simulation"));
        assert!(result.diagnosis.contains("1 recovery point(s)"));
        assert_eq!(result.recovery_point_count, 1);
        assert!(result.service_available);
        assert!(result.sufficient_privilege);
    }

    #[test]
    fn simulation_probe_reports_not_functional_when_not_available() {
        let provider = SimulationRollbackProvider::new(false);
        let result = provider.probe();
        assert!(!result.functional);
        assert!(result.diagnosis.contains("unavailable"));
    }
}
