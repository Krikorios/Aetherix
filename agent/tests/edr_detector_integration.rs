use aetherix_agent::edr::{
    ioc, ransomware, response, EdrAction, EdrDetectionKind, ResponseStatus, ioc::Indicator,
};
use aetherix_agent::policy::{runtime_from_response, AgentPolicyDocument, AgentPolicyResponse};
use std::fs;
use std::sync::{Mutex, OnceLock};
use tempfile::{NamedTempFile, TempDir};

fn quarantine_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn test_ransomware_canary_detection() {
    let result = ransomware::on_file_change("some/path/.aetherix_canary.txt", "v1");
    assert!(result.is_some());
    let event = result.unwrap();
    assert_eq!(event.kind, EdrDetectionKind::RansomwareCanary);
    assert_eq!(event.rule_id, "ransomware_canary_tripped");
    assert_eq!(event.action, EdrAction::Monitor);
}

#[test]
fn test_ransomware_high_entropy_detection() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();

    // Create high-entropy pseudo-random bytes
    let mut random_bytes = vec![0u8; 1024];
    for (i, byte) in random_bytes.iter_mut().enumerate() {
        *byte = ((i * 127 + 43) % 256) as u8;
    }
    fs::write(path, &random_bytes).unwrap();

    let result = ransomware::on_file_change(path, "v1");
    assert!(result.is_some());
    let event = result.unwrap();
    assert_eq!(event.kind, EdrDetectionKind::RansomwareCanary);
    assert_eq!(event.rule_id, "high_entropy_file_write");
}

#[test]
fn test_ransomware_mass_write_detection() {
    // Call 5 writes rapidly in the tracking window to trigger mass write detect
    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    
    // Low entropy file so it doesn't trigger entropy alert
    fs::write(path, vec![0u8; 1024]).unwrap();

    let mut event = None;
    for _ in 0..6 {
        event = ransomware::on_file_change(path, "v1");
    }
    
    assert!(event.is_some());
    let final_event = event.unwrap();
    assert_eq!(final_event.kind, EdrDetectionKind::RansomwareCanary);
    assert_eq!(final_event.rule_id, "mass_write_detect");
}

#[test]
fn test_ioc_matching() {
    let bad_hash = Indicator::Sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
    let good_hash = Indicator::Sha256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
    
    let match_bad = ioc::match_indicator(&bad_hash, "v1");
    let match_good = ioc::match_indicator(&good_hash, "v1");
    
    assert!(match_bad.is_some());
    assert_eq!(match_bad.unwrap().rule_id, "ioc_blacklist_match");
    assert!(match_good.is_none());

    let bad_dns = Indicator::Domain("bad-domain-leak.com".to_string());
    let match_dns = ioc::match_indicator(&bad_dns, "v1");
    assert!(match_dns.is_some());
}

#[test]
fn test_quarantine_action() {
    let _guard = quarantine_env_lock().lock().unwrap();
    let quarantine_dir = TempDir::new().unwrap();
    std::env::set_var("AETHERIX_QUARANTINE_DIR", quarantine_dir.path());
    let work_dir = TempDir::new().unwrap();
    let path = work_dir.path().join("malware.bin");
    fs::write(&path, "malicious content").unwrap();
    let path = path.to_string_lossy().to_string();
    let key = response::quarantine_key_material("test-key");
    assert!(std::path::Path::new(&path).exists());

    let res = response::apply(&EdrAction::Quarantine, None, Some(&path), &key);
    assert!(res.is_ok());
    
    // Original path should be gone (encrypted in quarantine)
    assert!(!std::path::Path::new(&path).exists());
    std::env::remove_var("AETHERIX_QUARANTINE_DIR");
}

#[test]
fn test_policy_promoted_quarantine_executes_and_emits_evidence() {
    let _guard = quarantine_env_lock().lock().unwrap();
    let quarantine_dir = TempDir::new().unwrap();
    std::env::set_var("AETHERIX_QUARANTINE_DIR", quarantine_dir.path());
    let work_dir = TempDir::new().unwrap();
    let target = work_dir.path().join("eicar.txt");
    fs::write(&target, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

    let policy = runtime_from_response(AgentPolicyResponse {
        endpoint_id: "agent-1".to_string(),
        policy_version_hash: "policy-quarantine".to_string(),
        evidence_controls: vec!["iso27001-2022:A.8.7".to_string()],
        resolved_policy: AgentPolicyDocument {
            modules: serde_json::json!({
                "antimalware": {"enabled": true, "response": {"action": "quarantine"}}
            }),
        },
    })
    .unwrap();

    let mut event = aetherix_agent::edr::EdrEvent::new(
        EdrDetectionKind::YaraMatch,
        "eicar",
        policy.edr_action_for_kind(&EdrDetectionKind::YaraMatch),
        &policy.policy_version_hash,
    );
    event.file_path = Some(target.to_string_lossy().to_string());
    event.evidence_controls = policy.evidence_controls.clone();

    let key = response::quarantine_key_material("test-key");
    let evidence = response::apply_to_event(&mut event, &key);

    assert_eq!(event.action, EdrAction::Quarantine);
    assert_eq!(evidence.status, ResponseStatus::Executed);
    assert_eq!(evidence.evidence_controls, vec!["iso27001-2022:A.8.7"]);
    assert!(event.response.is_some());
    assert!(!target.exists());
    assert!(evidence.quarantine.unwrap().manifest_hash.starts_with("sha256:"));
    std::env::remove_var("AETHERIX_QUARANTINE_DIR");
}

#[test]
fn test_default_policy_keeps_ransomware_in_review_without_mutation() {
    let policy = runtime_from_response(AgentPolicyResponse {
        endpoint_id: "agent-1".to_string(),
        policy_version_hash: "policy-review".to_string(),
        evidence_controls: vec!["nist-csf-2.0:DE.CM".to_string()],
        resolved_policy: AgentPolicyDocument {
            modules: serde_json::json!({
                "ransomware_mitigation": {"enabled": true, "rollback_approval": "operator_required"}
            }),
        },
    })
    .unwrap();

    assert_eq!(
        policy.edr_action_for_kind(&EdrDetectionKind::RansomwareCanary),
        EdrAction::Review
    );
}

#[test]
fn test_simulation_rollback_provider_simulate_and_restore_happy_path() {
    use aetherix_agent::edr::rollback::{
        SimulationRollbackProvider, RollbackProvider, RollbackScope, RollbackCandidateSet, RecoveryPoint
    };

    // 1. Setup simulation provider with a pre-configured recovery point
    let point = RecoveryPoint {
        id: "rp-happy".to_string(),
        provider: "simulation".to_string(),
        created_at: "2026-05-28T12:00:00Z".to_string(),
        expires_at: None,
        protected_roots: vec!["/home/victim/docs".to_string()],
        read_only: true,
        verified: true,
    };
    let provider = SimulationRollbackProvider::new(true).with_recovery_points(vec![point]);

    // 2. Simulate restore happy path
    let scope = RollbackScope {
        incident_id: "inc-123".to_string(),
        detector_rule_id: "rule-123".to_string(),
        affected_paths: vec!["/home/victim/docs/report.docx".to_string()],
        observed_at: "2026-05-30T12:00:00Z".to_string(),
    };
    let candidates = RollbackCandidateSet {
        scope,
        recovery_point_id: "rp-happy".to_string(),
        paths: vec!["/home/victim/docs/report.docx".to_string()],
        total_bytes_estimate: 4096,
        max_depth: 8,
        candidate_set_hash: "hash-happy".to_string(),
    };

    let sim = provider.simulate_restore(&candidates).unwrap();
    assert_eq!(sim.candidate_count, 1);
    assert_eq!(sim.restorable_count, 1);
    assert!(sim.skipped_paths.is_empty());

    // 3. Perform restore happy path
    let evidence = provider.restore(&candidates, "action-123").unwrap();
    assert_eq!(evidence.status, "executed");
    assert_eq!(evidence.restored_paths.len(), 1);
    assert_eq!(evidence.restored_paths[0].path, "/home/victim/docs/report.docx");
}

#[test]
fn test_simulation_rollback_provider_restore_error_paths() {
    use aetherix_agent::edr::rollback::{
        SimulationRollbackProvider, RollbackProvider, RollbackScope, RollbackCandidateSet, RecoveryPoint
    };

    // 1. Setup simulation provider with an unverified recovery point
    let point = RecoveryPoint {
        id: "rp-unverified".to_string(),
        provider: "simulation".to_string(),
        created_at: "2026-05-28T12:00:00Z".to_string(),
        expires_at: None,
        protected_roots: vec!["/home/victim/docs".to_string()],
        read_only: true,
        verified: false, // Unverified!
    };
    let provider = SimulationRollbackProvider::new(true).with_recovery_points(vec![point]);

    let scope = RollbackScope {
        incident_id: "inc-123".to_string(),
        detector_rule_id: "rule-123".to_string(),
        affected_paths: vec!["/home/victim/docs/report.docx".to_string()],
        observed_at: "2026-05-30T12:00:00Z".to_string(),
    };
    let candidates = RollbackCandidateSet {
        scope,
        recovery_point_id: "rp-unverified".to_string(),
        paths: vec!["/home/victim/docs/report.docx".to_string()],
        total_bytes_estimate: 4096,
        max_depth: 8,
        candidate_set_hash: "hash-unverified".to_string(),
    };

    // 2. Simulation should find 0 restorable count due to unverified point
    let sim = provider.simulate_restore(&candidates).unwrap();
    assert_eq!(sim.restorable_count, 0);

    // 3. Restore should report failure or not_applicable
    let evidence = provider.restore(&candidates, "action-123").unwrap();
    assert_eq!(evidence.status, "not_applicable");
    assert!(evidence.restored_paths.is_empty());
    assert!(!evidence.skipped_paths.is_empty());
}

#[test]
fn test_rollback_refusal_evidence_shape_details() {
    use aetherix_agent::edr::rollback::{
        SimulationRollbackProvider, RollbackProvider, RollbackScope, RollbackCandidateSet, RecoveryPoint
    };

    // Setup simulation provider with an unverified recovery point
    let point = RecoveryPoint {
        id: "rp-unverified".to_string(),
        provider: "simulation".to_string(),
        created_at: "2026-05-28T12:00:00Z".to_string(),
        expires_at: None,
        protected_roots: vec!["/home/victim/docs".to_string()],
        read_only: true,
        verified: false,
    };
    let provider = SimulationRollbackProvider::new(true).with_recovery_points(vec![point]);

    let scope = RollbackScope {
        incident_id: "inc-123".to_string(),
        detector_rule_id: "rule-123".to_string(),
        affected_paths: vec!["/home/victim/docs/report.docx".to_string()],
        observed_at: "2026-05-30T12:00:00Z".to_string(),
    };
    let candidates = RollbackCandidateSet {
        scope,
        recovery_point_id: "rp-unverified".to_string(),
        paths: vec!["/home/victim/docs/report.docx".to_string()],
        total_bytes_estimate: 4096,
        max_depth: 8,
        candidate_set_hash: "hash-unverified".to_string(),
    };

    let evidence = provider.restore(&candidates, "action-123").unwrap();
    assert_eq!(evidence.status, "not_applicable");
    assert_eq!(evidence.recovery_point_verified, false);
    assert_eq!(evidence.refusal_reason_code, Some("recovery_point_unverified".to_string()));
    assert!(evidence.provider_refusal.is_some());
    assert!(evidence.provider_refusal.as_ref().unwrap().contains("recovery_point_unverified"));
    assert_eq!(evidence.skipped_paths.len(), 1);
    assert_eq!(evidence.skipped_paths[0].refusal_reason_code, Some("recovery_point_unverified".to_string()));
}


#[test]
fn test_clipboard_interceptor_sha256_emission() {
    use aetherix_agent::interceptors::clipboard::ClipboardInterceptor;

    struct FakeClipboard {
        text: String,
    }
    impl aetherix_agent::interceptors::clipboard::ClipboardBackend for FakeClipboard {
        fn get_text(&mut self) -> Result<String, anyhow::Error> {
            Ok(self.text.clone())
        }
        fn set_text(&mut self, value: &str) -> Result<(), anyhow::Error> {
            self.text = value.to_string();
            Ok(())
        }
    }

    let backend = FakeClipboard {
        text: "restricted ssn 111-22-3333".to_string(),
    };
    let mut interceptor = ClipboardInterceptor::new(backend);

    let event = interceptor.poll().unwrap();
    assert!(event.sha256_hash.is_some());
    let hash = event.sha256_hash.unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_file_upload_interceptor_sha256_emission() {
    use aetherix_agent::interceptors::file_upload::FileUploadInterceptor;

    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("upload.txt");
    fs::write(&file_path, "restricted upload file content").unwrap();

    let mut interceptor = FileUploadInterceptor::new(vec![dir.path().to_path_buf()], vec!["txt".to_string()]);
    // First scan primes the interceptor (does not emit events for existing files)
    let _ = interceptor.scan();

    // Modify/rewrite file to trigger a scan change event
    fs::write(&file_path, "updated restricted upload file content").unwrap();
    let candidates = interceptor.scan();

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].event.sha256_hash.is_some());
    let hash = candidates[0].event.sha256_hash.as_ref().unwrap();
    assert_eq!(hash.len(), 64);
}
