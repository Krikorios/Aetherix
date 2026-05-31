use super::types::{
    RollbackCandidateSet, RollbackEvidence, RollbackScope,
};
use serde::{Deserialize, Serialize};

/// Parsed rollback intent from a control-plane `module_actions` payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackIntent {
    pub approved_action_id: String,
    pub simulation_id: String,
    pub candidate_set_hash: String,
    pub recovery_point_id: String,
    pub valid_until: String,
    pub observed_at: String,
    pub affected_paths: Vec<String>,
    pub total_bytes_estimate: u64,
    pub max_depth: u8,
}

/// Parse a `RollbackIntent` from a JSON `serde_json::Value` payload.
///
/// Returns `None` if any required field is missing or malformed.
pub fn parse_rollback_intent(action_id: &str, payload: &serde_json::Value) -> Option<RollbackIntent> {
    let simulation_id = payload.get("simulation_id")?.as_str()?.to_string();
    let candidate_set_hash = payload.get("candidate_set_hash")?.as_str()?.to_string();
    let recovery_point_id = payload.get("recovery_point_id")?.as_str()?.to_string();
    let valid_until = payload.get("valid_until")?.as_str()?.to_string();
    let observed_at = payload
        .get("observed_at")
        .or_else(|| payload.get("detected_at"))
        .or_else(|| payload.get("created_at"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let affected_paths: Vec<String> = payload
        .get("affected_paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let total_bytes_estimate = payload
        .get("total_bytes_estimate")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let max_depth = payload
        .get("max_depth")
        .and_then(|v| v.as_u64())
        .map(|d| d as u8)
        .unwrap_or(8);

    Some(RollbackIntent {
        approved_action_id: action_id.to_string(),
        simulation_id,
        candidate_set_hash,
        recovery_point_id,
        valid_until,
        observed_at,
        affected_paths,
        total_bytes_estimate,
        max_depth,
    })
}

/// Validate that a rollback intent is still within its validity window.
pub fn validate_intent_expiry(intent: &RollbackIntent) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let valid_until = chrono::DateTime::parse_from_rfc3339(&intent.valid_until)
        .map_err(|_| anyhow::anyhow!("malformed valid_until timestamp: {}", intent.valid_until))?;
    if now > valid_until {
        anyhow::bail!(
            "rollback intent expired: valid_until={} is in the past",
            intent.valid_until
        );
    }
    Ok(())
}

/// Construct a `RollbackCandidateSet` from an approved intent.
pub fn intent_to_candidate_set(intent: &RollbackIntent) -> RollbackCandidateSet {
    RollbackCandidateSet {
        scope: RollbackScope {
            incident_id: intent.approved_action_id.clone(),
            detector_rule_id: intent.simulation_id.clone(),
            affected_paths: intent.affected_paths.clone(),
            observed_at: intent.observed_at.clone(),
        },
        recovery_point_id: intent.recovery_point_id.clone(),
        paths: intent.affected_paths.clone(),
        total_bytes_estimate: intent.total_bytes_estimate,
        max_depth: intent.max_depth,
        candidate_set_hash: intent.candidate_set_hash.clone(),
    }
}

/// Convert a `RollbackEvidence` into a standard `ResponseEvidence` for
/// the existing event pipeline.
pub fn convert_rollback_evidence_to_response(
    rollback_evidence: &RollbackEvidence,
) -> super::super::ResponseEvidence {
    let status = match rollback_evidence.status.as_str() {
        "executed" => super::super::ResponseStatus::Executed,
        "failed" => super::super::ResponseStatus::Failed,
        "not_applicable" => super::super::ResponseStatus::NotApplicable,
        _ => super::super::ResponseStatus::Staged,
    };

    let mut decision_trace = Vec::with_capacity(
        rollback_evidence.decision_trace.len() + 4,
    );
    decision_trace.push(format!("rollback_provider={}", rollback_evidence.provider));
    decision_trace.push(format!(
        "rollback_provider_version={}",
        rollback_evidence.provider_version
    ));
    decision_trace.push(format!(
        "rollback_provider_refusal={}",
        rollback_evidence
            .provider_refusal
            .as_deref()
            .unwrap_or("none")
    ));
    decision_trace.extend(rollback_evidence.decision_trace.clone());
    decision_trace.push(format!(
        "restored_paths={}, failed_paths={}, skipped_paths={}",
        rollback_evidence.restored_paths.len(),
        rollback_evidence.failed_paths.len(),
        rollback_evidence.skipped_paths.len(),
    ));

    super::super::ResponseEvidence {
        action: super::super::EdrAction::Rollback,
        status,
        attempted_at: chrono::Utc::now().to_rfc3339(),
        policy_version: rollback_evidence.policy_version.clone(),
        rule_id: rollback_evidence.simulation_id.clone(),
        target_pid: None,
        target_path: None,
        file_sha256: None,
        platform: rollback_evidence.os_platform.clone(),
        platform_api: format!(
            "rollback:{}",
            rollback_evidence.provider
        ),
        decision_trace,
        error: rollback_evidence.provider_refusal.clone(),
        quarantine: None,
        quarantine_items: Vec::new(),
        evidence_controls: rollback_evidence.evidence_controls.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::{ResponseStatus, EdrAction};

    #[test]
    fn parse_rollback_intent_extracts_all_fields() {
        let payload = serde_json::json!({
            "simulation_id": "sim-1",
            "candidate_set_hash": "hash-abc",
            "recovery_point_id": "rp-1",
            "valid_until": "2126-05-28T12:00:00Z",
            "affected_paths": ["/a", "/b"],
            "total_bytes_estimate": 4096,
            "max_depth": 8,
        });
        let intent = parse_rollback_intent("action-1", &payload).unwrap();
        assert_eq!(intent.approved_action_id, "action-1");
        assert_eq!(intent.simulation_id, "sim-1");
        assert_eq!(intent.candidate_set_hash, "hash-abc");
        assert_eq!(intent.recovery_point_id, "rp-1");
        assert_eq!(intent.affected_paths, vec!["/a", "/b"]);
        assert_eq!(intent.total_bytes_estimate, 4096);
        assert_eq!(intent.max_depth, 8);
        assert!(!intent.observed_at.is_empty());
    }

    #[test]
    fn parse_rollback_intent_missing_fields_returns_none() {
        let payload = serde_json::json!({
            "simulation_id": "sim-1",
        });
        assert!(parse_rollback_intent("action-1", &payload).is_none());
    }

    #[test]
    fn validate_intent_expiry_accepts_future_timestamp() {
        let intent = RollbackIntent {
            approved_action_id: "action-1".to_string(),
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            recovery_point_id: "rp-1".to_string(),
            valid_until: "2126-05-28T12:00:00Z".to_string(),
            observed_at: "2026-05-28T12:00:00Z".to_string(),
            affected_paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
        };
        assert!(validate_intent_expiry(&intent).is_ok());
    }

    #[test]
    fn validate_intent_expiry_rejects_past_timestamp() {
        let intent = RollbackIntent {
            approved_action_id: "action-1".to_string(),
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            recovery_point_id: "rp-1".to_string(),
            valid_until: "2020-01-01T00:00:00Z".to_string(),
            observed_at: "2026-05-28T12:00:00Z".to_string(),
            affected_paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
        };
        let err = validate_intent_expiry(&intent).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn validate_intent_expiry_rejects_malformed_timestamp() {
        let intent = RollbackIntent {
            approved_action_id: "action-1".to_string(),
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            recovery_point_id: "rp-1".to_string(),
            valid_until: "not-a-timestamp".to_string(),
            observed_at: "2026-05-28T12:00:00Z".to_string(),
            affected_paths: vec![],
            total_bytes_estimate: 0,
            max_depth: 8,
        };
        let err = validate_intent_expiry(&intent).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn intent_to_candidate_set_preserves_intent_fields() {
        let intent = RollbackIntent {
            approved_action_id: "action-1".to_string(),
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            recovery_point_id: "rp-1".to_string(),
            valid_until: "2126-05-28T12:00:00Z".to_string(),
            observed_at: "2026-05-28T12:00:00Z".to_string(),
            affected_paths: vec!["/a".to_string(), "/b".to_string()],
            total_bytes_estimate: 4096,
            max_depth: 8,
        };
        let set = intent_to_candidate_set(&intent);
        assert_eq!(set.recovery_point_id, "rp-1");
        assert_eq!(set.candidate_set_hash, "hash-1");
        assert_eq!(set.paths, vec!["/a", "/b"]);
        assert_eq!(set.scope.observed_at, "2026-05-28T12:00:00Z");
        assert_eq!(set.total_bytes_estimate, 4096);
        assert_eq!(set.max_depth, 8);
    }

    #[test]
    fn convert_rollback_evidence_maps_executed_status() {
        let rbe = RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec!["trace1".to_string()],
            evidence_controls: vec![],
            endpoint_id: "ep-1".to_string(),
            customer_id: None,
            policy_version: "pol-v1".to_string(),
            requester_id: "req-1".to_string(),
            approver_ids: vec![],
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            approved_action_id: "action-1".to_string(),
            provider: "noop".to_string(),
            recovery_point_id: "rp-1".to_string(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: None,
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "0.1.0".to_string(),
            os_platform: "test".to_string(),
            privilege_context: "none".to_string(),
        };
        let resp = convert_rollback_evidence_to_response(&rbe);
        assert_eq!(resp.action, EdrAction::Rollback);
        assert_eq!(resp.status, ResponseStatus::Executed);
        assert!(resp
            .decision_trace
            .iter()
            .any(|d| d.contains("rollback_provider=noop")));
    }

    #[test]
    fn convert_rollback_evidence_maps_failed_status() {
        let rbe = RollbackEvidence {
            status: "failed".to_string(),
            decision_trace: vec![],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: String::new(),
            approved_action_id: String::new(),
            provider: "noop".to_string(),
            recovery_point_id: String::new(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: Some("provider_error".to_string()),
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "0.1.0".to_string(),
            os_platform: "test".to_string(),
            privilege_context: "none".to_string(),
        };
        let resp = convert_rollback_evidence_to_response(&rbe);
        assert_eq!(resp.status, ResponseStatus::Failed);
        assert_eq!(resp.error, Some("provider_error".to_string()));
    }
}
