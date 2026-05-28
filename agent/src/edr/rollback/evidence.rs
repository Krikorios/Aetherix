use super::provider::RollbackProvider;
use super::types::{
    RecoveryPointHint, RecoveryPointSummary, RollbackEvidence, RollbackReadiness, RollbackScope,
};
use crate::edr::{EdrAction, EdrDetectionKind, EdrEvent, ResponseEvidence, ResponseStatus};

/// Build a `RollbackReadiness` from a provider, suitable for heartbeat payload.
///
/// `fim_event_paths` — file paths from recent FIM events (e.g. canary trips,
/// tracked-file modifications) that the control-plane can use for lightweight
/// FimHint-style correlation. Pass an empty slice when no FIM events are
/// available in the current heartbeat.
pub fn compute_rollback_readiness(
    provider: &dyn RollbackProvider,
    fim_event_paths: &[String],
) -> RollbackReadiness {
    let caps = provider.capabilities();
    let probe_scope = RollbackScope {
        incident_id: String::new(),
        detector_rule_id: String::new(),
        affected_paths: vec![],
        observed_at: String::new(),
    };
    let recovery_points = provider
        .list_recovery_points(&probe_scope)
        .unwrap_or_default()
        .into_iter()
        .map(|rp| RecoveryPointSummary {
            id: rp.id,
            provider: rp.provider,
            created_at: rp.created_at,
            expires_at: rp.expires_at,
            protected_root: rp.protected_roots.first().cloned().unwrap_or_default(),
            verified: rp.verified,
        })
        .collect();

    let probe = provider.probe();

    // Cap recent_fim_paths at 64 entries to keep heartbeat payload bounded.
    let mut recent_fim_paths: Vec<String> = fim_event_paths.to_vec();
    recent_fim_paths.truncate(64);

    RollbackReadiness {
        provider_available: caps.available,
        provider_name: caps.provider_name,
        provider_version: caps.provider_version,
        recovery_points,
        os_platform: std::env::consts::OS.to_string(),
        functional: probe.functional,
        diagnosis: probe.diagnosis,
        recovery_point_count: probe.recovery_point_count,
        available_filesystems: probe.available_filesystems,
        service_available: probe.service_available,
        sufficient_privilege: probe.sufficient_privilege,
        volume_capabilities: probe.volume_capabilities,
        snapshot_service_info: probe.snapshot_service_info,
        privilege_boundary: probe.privilege_boundary,
        recent_fim_paths,
    }
}

/// Enrich ransomware EDR events with recovery point hints from the provider.
pub fn enrich_events_with_recovery_hints(
    events: &mut [EdrEvent],
    provider: &dyn RollbackProvider,
) {
    for event in events {
        if matches!(event.kind, EdrDetectionKind::RansomwareCanary) {
            let scope = RollbackScope {
                incident_id: event.rule_id.clone(),
                detector_rule_id: event.rule_id.clone(),
                affected_paths: event.file_path.clone().into_iter().collect(),
                observed_at: event.collected_at.clone(),
            };
            if let Ok(points) = provider.list_recovery_points(&scope) {
                if !points.is_empty() {
                    event.recovery_hints = Some(RecoveryPointHint {
                        provider: provider.capabilities().provider_name,
                        recovery_points: points
                            .into_iter()
                            .map(|rp| RecoveryPointSummary {
                                id: rp.id,
                                provider: rp.provider,
                                created_at: rp.created_at,
                                expires_at: rp.expires_at,
                                protected_root: rp
                                    .protected_roots
                                    .first()
                                    .cloned()
                                    .unwrap_or_default(),
                                verified: rp.verified,
                            })
                            .collect(),
                        incident_id: Some(scope.incident_id),
                    });
                }
            }
        }
    }
}

/// ---------------------------------------------------------------------------
/// Richer endpoint.rollback.* event builders
/// Matching the quarantine pattern — each produces an EdrEvent with distinct
/// tags so the control plane has distinguishable signals.
/// ---------------------------------------------------------------------------

/// Build an event signalling a rollback action was received/requested.
pub fn build_rollback_requested_event(
    action_id: &str,
    simulation_id: &str,
    policy_version: &str,
    evidence_controls: Vec<String>,
) -> EdrEvent {
    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        simulation_id,
        EdrAction::Rollback,
        policy_version,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push("remote_action:rollback".to_string());
    event.tags.push("rollback_requested".to_string());
    event.matched_indicator = Some(action_id.to_string());
    event
}

/// Build an event signalling a rollback was executed successfully.
pub fn build_rollback_executed_event(
    action_id: &str,
    simulation_id: &str,
    policy_version: &str,
    evidence_controls: Vec<String>,
    rollback_evidence: RollbackEvidence,
) -> EdrEvent {
    let response = super::intent::convert_rollback_evidence_to_response(&rollback_evidence);
    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        simulation_id,
        EdrAction::Rollback,
        policy_version,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push("remote_action:rollback".to_string());
    event.tags.push("rollback_executed".to_string());
    event.matched_indicator = Some(action_id.to_string());
    event.response = Some(response);
    event.rollback_evidence = Some(rollback_evidence);
    event.rollback_file_paths = event
        .rollback_evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .restored_paths
                .iter()
                .map(|path| path.path.clone())
                .collect()
        })
        .unwrap_or_default();
    event
}

/// Build an event signalling a rollback failed.
pub fn build_rollback_failed_event(
    action_id: &str,
    simulation_id: &str,
    policy_version: &str,
    evidence_controls: Vec<String>,
    error_message: &str,
    provider_refusal: Option<String>,
    decision_trace: Vec<String>,
) -> EdrEvent {
    let mut dt = decision_trace.clone();
    dt.push(format!("error: {error_message}"));

    let rollback_evidence = RollbackEvidence {
        status: "failed".to_string(),
        decision_trace: dt,
        evidence_controls: evidence_controls.clone(),
        endpoint_id: String::new(),
        customer_id: None,
        policy_version: policy_version.to_string(),
        requester_id: String::new(),
        approver_ids: vec![],
        simulation_id: simulation_id.to_string(),
        candidate_set_hash: String::new(),
        approved_action_id: action_id.to_string(),
        provider: "noop".to_string(),
        recovery_point_id: String::new(),
        recovery_point_created_at: String::new(),
        recovery_point_expires_at: None,
        recovery_point_verified: false,
        metadata_preserved: None,
        provider_refusal,
        restored_paths: vec![],
        failed_paths: vec![],
        skipped_paths: vec![],
        provider_version: "0.1.0".to_string(),
        os_platform: std::env::consts::OS.to_string(),
        privilege_context: "none".to_string(),
    };

    let response = super::intent::convert_rollback_evidence_to_response(&rollback_evidence);
    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        "rollback",
        EdrAction::Rollback,
        policy_version,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push("remote_action:rollback".to_string());
    event.tags.push("rollback_failed".to_string());
    event.matched_indicator = Some(action_id.to_string());
    event.response = Some(response);
    event.rollback_evidence = Some(rollback_evidence);
    event
}

/// Build an event signalling a rollback was refused (idempotency, policy, etc.).
pub fn build_rollback_refused_event(
    action_id: &str,
    policy_version: &str,
    evidence_controls: Vec<String>,
    refusal_reason: &str,
    decision_trace: Vec<String>,
) -> EdrEvent {
    let rollback_evidence = RollbackEvidence {
        status: "not_applicable".to_string(),
        decision_trace: decision_trace.clone(),
        evidence_controls: evidence_controls.clone(),
        endpoint_id: String::new(),
        customer_id: None,
        policy_version: policy_version.to_string(),
        requester_id: String::new(),
        approver_ids: vec![],
        simulation_id: String::new(),
        candidate_set_hash: String::new(),
        approved_action_id: action_id.to_string(),
        provider: "noop".to_string(),
        recovery_point_id: String::new(),
        recovery_point_created_at: String::new(),
        recovery_point_expires_at: None,
        recovery_point_verified: false,
        metadata_preserved: None,
        provider_refusal: Some(refusal_reason.to_string()),
        restored_paths: vec![],
        failed_paths: vec![],
        skipped_paths: vec![],
        provider_version: "0.1.0".to_string(),
        os_platform: std::env::consts::OS.to_string(),
        privilege_context: "none".to_string(),
    };

    let response = ResponseEvidence {
        action: EdrAction::Review,
        status: ResponseStatus::NotApplicable,
        attempted_at: chrono::Utc::now().to_rfc3339(),
        policy_version: policy_version.to_string(),
        rule_id: "rollback".to_string(),
        target_pid: None,
        target_path: None,
        file_sha256: None,
        platform: std::env::consts::OS.to_string(),
        platform_api: "rollback-provider".to_string(),
        decision_trace: decision_trace.clone(),
        error: Some(refusal_reason.to_string()),
        quarantine: None,
        quarantine_items: vec![],
        evidence_controls: evidence_controls.clone(),
    };

    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        "rollback",
        EdrAction::Rollback,
        policy_version,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push("remote_action:rollback".to_string());
    event.tags.push("rollback_refused".to_string());
    event.matched_indicator = Some(action_id.to_string());
    event.response = Some(response);
    event.rollback_evidence = Some(rollback_evidence);
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::rollback::provider::{NoopRollbackProvider, SimulationRollbackProvider};
    use crate::edr::rollback::types::RecoveryPoint;
    use crate::edr::{EdrDetectionKind, EdrAction};

    #[test]
    fn compute_rollback_readiness_reflects_noop_provider() {
        let provider = NoopRollbackProvider;
        let readiness = compute_rollback_readiness(&provider, &[]);
        assert!(!readiness.provider_available);
        assert_eq!(readiness.provider_name, "noop");
        assert!(readiness.recovery_points.is_empty());
        // probe-derived fields
        assert!(!readiness.functional);
        assert!(readiness.diagnosis.contains("noop"));
        assert_eq!(readiness.recovery_point_count, 0);
        assert!(readiness.available_filesystems.is_empty());
        assert!(!readiness.service_available);
        assert!(!readiness.sufficient_privilege);
        assert!(readiness.volume_capabilities.is_empty());
        assert!(readiness.snapshot_service_info.is_none());
        assert!(readiness.privilege_boundary.is_some());
        assert!(readiness.recent_fim_paths.is_empty());
    }

    #[test]
    fn compute_rollback_readiness_includes_simulation_probe() {
        let now = chrono::Utc::now();
        let rp = RecoveryPoint {
            id: "rp-heartbeat-1".to_string(),
            provider: "simulation".to_string(),
            created_at: (now - chrono::Duration::hours(4)).to_rfc3339(),
            expires_at: None,
            protected_roots: vec!["/home".to_string()],
            read_only: true,
            verified: true,
        };
        let provider = SimulationRollbackProvider::new(true)
            .with_recovery_points(vec![rp]);
        let fim_paths = vec!["/home/user/canary.txt".to_string()];
        let readiness = compute_rollback_readiness(&provider, &fim_paths);
        assert!(readiness.functional);
        assert!(readiness.diagnosis.contains("simulation"));
        assert_eq!(readiness.recovery_point_count, 1);
        assert!(readiness.available_filesystems.contains(&"apfs".to_string()));
        assert!(readiness.service_available);
        assert!(readiness.sufficient_privilege);
        assert!(!readiness.volume_capabilities.is_empty());
        assert!(readiness.snapshot_service_info.is_some());
        assert!(readiness.privilege_boundary.is_some());
        assert_eq!(readiness.recent_fim_paths, vec!["/home/user/canary.txt"]);
    }

    #[test]
    fn compute_rollback_readiness_caps_fim_paths_at_64() {
        let provider = NoopRollbackProvider;
        let many_paths: Vec<String> = (0..100).map(|i| format!("/path/{i}")).collect();
        let readiness = compute_rollback_readiness(&provider, &many_paths);
        assert_eq!(readiness.recent_fim_paths.len(), 64);
    }

    #[test]
    fn enrich_events_does_nothing_for_non_ransomware_events() {
        let provider = NoopRollbackProvider;
        let mut event = EdrEvent::new(
            EdrDetectionKind::YaraMatch,
            "yara_rule_1",
            EdrAction::Monitor,
            "policy-v1",
        );
        let original_hints = event.recovery_hints.clone();
        enrich_events_with_recovery_hints(std::slice::from_mut(&mut event), &provider);
        assert_eq!(event.recovery_hints, original_hints);
        assert!(event.recovery_hints.is_none());
    }

    #[test]
    fn enrich_events_attaches_hints_for_ransomware_canary() {
        let provider = NoopRollbackProvider;
        let mut event = EdrEvent::new(
            EdrDetectionKind::RansomwareCanary,
            "ransomware_canary_tripped",
            EdrAction::Monitor,
            "policy-v1",
        );
        event.file_path = Some("/etc/aetherix/aetherix_canary.txt".to_string());
        enrich_events_with_recovery_hints(std::slice::from_mut(&mut event), &provider);
        assert!(event.recovery_hints.is_none());
    }

    #[test]
    fn build_rollback_requested_event_has_correct_tags() {
        let event = build_rollback_requested_event(
            "action-1",
            "sim-1",
            "pol-v1",
            vec!["nist-csf-2.0:RS.MI".to_string()],
        );
        assert_eq!(event.kind, EdrDetectionKind::ResponseAction);
        assert!(event.tags.contains(&"rollback_requested".to_string()));
        assert!(event.tags.contains(&"remote_action:rollback".to_string()));
        assert_eq!(event.matched_indicator, Some("action-1".to_string()));
    }

    #[test]
    fn build_rollback_executed_event_carries_evidence() {
        let evidence = RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec!["restore ok".to_string()],
            evidence_controls: vec![],
            endpoint_id: "ep-1".to_string(),
            customer_id: None,
            policy_version: "pol-v1".to_string(),
            requester_id: "req-1".to_string(),
            approver_ids: vec![],
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            approved_action_id: "action-1".to_string(),
            provider: "simulation".to_string(),
            recovery_point_id: "rp-1".to_string(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: true,
            metadata_preserved: Some(true),
            provider_refusal: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "1.0".to_string(),
            os_platform: "test".to_string(),
            privilege_context: "user".to_string(),
        };
        let event = build_rollback_executed_event(
            "action-1",
            "sim-1",
            "pol-v1",
            vec![],
            evidence.clone(),
        );
        assert!(event.tags.contains(&"rollback_executed".to_string()));
        assert!(event.response.is_some());
        assert!(event.rollback_evidence.is_some());
        assert_eq!(event.rollback_evidence.unwrap().provider, "simulation");
    }

    #[test]
    fn build_rollback_failed_event_includes_error() {
        let event = build_rollback_failed_event(
            "action-1",
            "sim-1",
            "pol-v1",
            vec![],
            "provider error",
            Some("provider_unavailable".to_string()),
            vec!["decision trace".to_string()],
        );
        assert!(event.tags.contains(&"rollback_failed".to_string()));
        assert!(event.response.unwrap().status == ResponseStatus::Failed);
        // error_message is injected into decision_trace
        let evidence = event.rollback_evidence.unwrap();
        assert!(evidence
            .decision_trace
            .iter()
            .any(|d| d.contains("provider error")));
    }

    #[test]
    fn build_rollback_refused_event_is_not_applicable() {
        let event = build_rollback_refused_event(
            "action-1",
            "pol-v1",
            vec![],
            "action_already_consumed",
            vec!["duplicate".to_string()],
        );
        assert!(event.tags.contains(&"rollback_refused".to_string()));
        let evidence = event.rollback_evidence.unwrap();
        assert_eq!(evidence.status, "not_applicable");
        assert_eq!(
            evidence.provider_refusal,
            Some("action_already_consumed".to_string())
        );
    }
}
