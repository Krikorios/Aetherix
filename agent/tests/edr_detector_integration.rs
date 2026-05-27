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
fn test_isolation_records_intent_evidence() {
    let key = response::quarantine_key_material("test-key");
    let evidence = response::execute(
        &EdrAction::Isolate,
        None,
        None,
        None,
        "ransomware_canary_tripped",
        "policy-isolate",
        &["nist-csf-2.0:RS.MI".to_string()],
        &key,
    );
    assert_eq!(evidence.status, ResponseStatus::Executed);
    assert_eq!(evidence.platform_api, "isolation-intent");
}
