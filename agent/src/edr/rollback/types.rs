use serde::{Deserialize, Serialize};

/// What a RollbackProvider advertises to the agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackCapabilities {
    pub provider_name: String,
    pub provider_version: String,
    pub available: bool,
    pub supported_os: Vec<String>,
    pub supported_filesystems: Vec<String>,
    pub privilege_context: String,
}

/// Detector-emitted scope that triggers recovery-point lookup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackScope {
    pub incident_id: String,
    pub detector_rule_id: String,
    pub affected_paths: Vec<String>,
    pub observed_at: String,
}

/// A single recovery point from a provider (VSS snapshot, APFS snapshot, etc.).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPoint {
    pub id: String,
    pub provider: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub protected_roots: Vec<String>,
    pub read_only: bool,
    pub verified: bool,
}

/// Lightweight summary of a recovery point for heartbeat telemetry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPointSummary {
    pub id: String,
    pub provider: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub protected_root: String,
    pub verified: bool,
}

/// Assembled candidate set for a single provider-root-point triple.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackCandidateSet {
    pub scope: RollbackScope,
    pub recovery_point_id: String,
    pub paths: Vec<String>,
    pub total_bytes_estimate: u64,
    pub max_depth: u8,
    pub candidate_set_hash: String,
}

/// Simulation result — produced before any host-mutating restore.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

/// Typed outcome for a per-path rollback decision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RollbackPathOutcome {
    #[serde(rename = "restored")]
    Restored,
    #[serde(rename = "skipped")]
    Skipped,
    #[serde(rename = "failed_integrity")]
    FailedIntegrity,
    #[serde(rename = "refused_out_of_scope")]
    RefusedOutOfScope,
}

/// Per-path decision within a simulation or restore result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackPathDecision {
    pub path: String,
    pub outcome: RollbackPathOutcome,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason_code: Option<String>,
    pub bytes_affected: u64,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
    pub metadata_diff: Option<Vec<String>>,
}

/// Rich evidence emitted by a restore attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackEvidence {
    pub status: String,
    pub decision_trace: Vec<String>,
    pub evidence_controls: Vec<String>,
    pub endpoint_id: String,
    pub customer_id: Option<String>,
    pub policy_version: String,
    pub requester_id: String,
    pub approver_ids: Vec<String>,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason_code: Option<String>,

    pub restored_paths: Vec<RollbackPathDecision>,
    pub failed_paths: Vec<RollbackPathDecision>,
    pub skipped_paths: Vec<RollbackPathDecision>,

    pub provider_version: String,
    pub os_platform: String,
    pub privilege_context: String,
}

/// In-band recovery point hint carried on an EdrEvent when a ransomware
/// detector fires and a rollback provider has available recovery points.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPointHint {
    pub provider: String,
    pub recovery_points: Vec<RecoveryPointSummary>,
    pub incident_id: Option<String>,
}

/// Rollback readiness summary reported in heartbeats.
///
/// Combines static capability capability metadata with a startup probe result so the
/// control plane knows not only *whether* a provider is present, but *why*
/// it may be non-functional (service down, insufficient privilege, etc.).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackReadiness {
    pub provider_available: bool,
    pub provider_name: String,
    pub provider_version: String,
    pub recovery_points: Vec<RecoveryPointSummary>,
    pub os_platform: String,

    // --- Probe-derived fields -------------------------------------------------

    /// Whether the provider passed its startup health check.
    pub functional: bool,
    /// Human-readable diagnosis when not functional.
    pub diagnosis: String,
    /// Number of recovery points visible at probe time (independent of
    /// the scope-filtered `recovery_points` list above).
    pub recovery_point_count: usize,
    /// Filesystems the provider can service (e.g. "apfs", "ntfs", "btrfs").
    pub available_filesystems: Vec<String>,
    /// Whether the required OS service / daemon is running.
    pub service_available: bool,
    /// Whether the agent process has sufficient privilege for snapshot access.
    pub sufficient_privilege: bool,

    // --- Provider-hardening fields (v0.4) ------------------------------------
    //
    // Real OS providers (VSS / APFS / Btrfs) populate these with OS-level
    // capability and service detail beyond the boolean probe.

    /// Per-volume snapshot capability (e.g. "apfs:/System/Volumes/Data",
    /// "vss:C:", "btrfs:/@home").
    pub volume_capabilities: Vec<String>,
    /// Human-readable snapshot service status (e.g. "VSS v1.6, Writers: 3/5
    /// ready", "APFS snapshots enabled on 2 of 3 volumes").
    pub snapshot_service_info: Option<String>,
    /// Specific privilege boundary the provider operates under (e.g.
    /// "requires SeBackupPrivilege", "root required", "com.apple.private.apfs.snapshot").
    pub privilege_boundary: Option<String>,

    // --- Correlation-friendly data (v0.4) ------------------------------------
    //
    // File paths from recent FIM events (canary trips, modified tracked files)
    // that the control-plane correlation engine could use for FimHint-style
    // hints without an extra lookup.

    /// File paths observed by FIM since last heartbeat (most recent first,
    /// capped at 64 entries). Empty when no recent FIM activity.
    pub recent_fim_paths: Vec<String>,
}

/// Startup-time probe result from a real provider, indicating what is
/// actually available on the host (not just what the provider advertises).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeResult {
    /// Whether the provider is functional on this host.
    pub functional: bool,
    /// Human-readable diagnosis if not functional.
    pub diagnosis: String,
    /// Number of recovery points currently visible.
    pub recovery_point_count: usize,
    /// Names of filesystems the provider can handle (e.g. "apfs", "ntfs", "btrfs").
    pub available_filesystems: Vec<String>,
    /// Whether the required OS service/daemon is running (e.g. VSS writer, APFS).
    pub service_available: bool,
    /// Whether the agent process has sufficient privilege for snapshot access.
    pub sufficient_privilege: bool,

    // --- Probe-derived fields (v0.4) ------------------------------------

    /// Per-volume snapshot capability (e.g. "apfs:/System/Volumes/Data",
    /// "vss:C:", "btrfs:/@home").
    pub volume_capabilities: Vec<String>,
    /// Human-readable snapshot service status (e.g. "VSS v1.6, Writers: 3/5
    /// ready", "APFS snapshots enabled on 2 of 3 volumes").
    pub snapshot_service_info: Option<String>,
    /// Specific privilege boundary the provider operates under (e.g.
    /// "requires SeBackupPrivilege", "root required", "com.apple.private.apfs.snapshot").
    pub privilege_boundary: Option<String>,
}

/// Refusal states as typed enum.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RollbackRefusal {
    ProviderUnavailable,
    RecoveryPointUnverified,
    CandidateScopeMismatch,
    UnsafeTargetState,
    PrivilegeBoundary,
}

impl RollbackRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::RecoveryPointUnverified => "recovery_point_unverified",
            Self::CandidateScopeMismatch => "candidate_scope_mismatch",
            Self::UnsafeTargetState => "unsafe_target_state",
            Self::PrivilegeBoundary => "privilege_boundary",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_evidence_serialization_roundtrip() {
        let evidence = RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec!["trace-1".to_string()],
            evidence_controls: vec!["nist-csf-2.0:RS.MI".to_string()],
            endpoint_id: "ep-1".to_string(),
            customer_id: Some("cust-1".to_string()),
            policy_version: "pol-v1".to_string(),
            requester_id: "req-1".to_string(),
            approver_ids: vec!["approver-1".to_string()],
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            approved_action_id: "action-1".to_string(),
            provider: "vss".to_string(),
            recovery_point_id: "rp-1".to_string(),
            recovery_point_created_at: "2026-05-28T10:00:00Z".to_string(),
            recovery_point_expires_at: Some("2026-06-04T10:00:00Z".to_string()),
            recovery_point_verified: true,
            metadata_preserved: Some(true),
            provider_refusal: None,
            refusal_reason_code: Some("point_expired".to_string()),
            restored_paths: vec![RollbackPathDecision {
                path: "/a".to_string(),
                outcome: RollbackPathOutcome::Restored,
                reason: "ok".to_string(),
                refusal_reason_code: None,
                bytes_affected: 1024,
                hash_before: Some("abc".to_string()),
                hash_after: Some("def".to_string()),
                metadata_diff: None,
            }],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "1.0.0".to_string(),
            os_platform: "windows".to_string(),
            privilege_context: "system".to_string(),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: RollbackEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, deserialized);
    }

    #[test]
    fn rollback_scope_serialization_roundtrip() {
        let scope = RollbackScope {
            incident_id: "inc-1".to_string(),
            detector_rule_id: "rule-1".to_string(),
            affected_paths: vec!["/a".to_string(), "/b".to_string()],
            observed_at: "2026-05-28T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: RollbackScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, deserialized);
    }

    #[test]
    fn refusal_enum_as_str_matches_expected() {
        assert_eq!(RollbackRefusal::ProviderUnavailable.as_str(), "provider_unavailable");
        assert_eq!(RollbackRefusal::RecoveryPointUnverified.as_str(), "recovery_point_unverified");
        assert_eq!(RollbackRefusal::CandidateScopeMismatch.as_str(), "candidate_scope_mismatch");
        assert_eq!(RollbackRefusal::UnsafeTargetState.as_str(), "unsafe_target_state");
        assert_eq!(RollbackRefusal::PrivilegeBoundary.as_str(), "privilege_boundary");
    }
}
