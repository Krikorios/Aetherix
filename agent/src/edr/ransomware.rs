//! Ransomware mitigation. P0-3 in `docs/roadmap-2026.md`.
//!
//! Implements the design from `docs/native-security-gap-review.md`
//! "Ransomware mitigation and recovery":
//!
//! - Canary files in watched directories.
//! - Entropy delta detector on file writes.
//! - Mass-rename / mass-write throttle.
//!
//! All triggers default to `Monitor` until promoted via Policy
//! Engine v2 simulation + operator approval.

use super::{EdrAction, EdrDetectionKind, EdrEvent};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::Mutex;
use std::time::{Instant, Duration};

static WRITE_HISTORY: OnceLock<Mutex<Vec<(Instant, String)>>> = OnceLock::new();

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Notify the detector that a watched file changed. Returns an
/// `EdrEvent` when a canary or entropy threshold trips.
pub fn on_file_change(path: &str, policy_version: &str) -> Option<EdrEvent> {
    // 1. Canary files checking
    let path_lower = path.to_lowercase();
    if path_lower.contains("aetherix_canary") || path_lower.ends_with(".canary") {
        return Some(EdrEvent {
            kind: EdrDetectionKind::RansomwareCanary,
            rule_id: "ransomware_canary_tripped".to_string(),
            action: EdrAction::Monitor,
            process_path: None,
            process_pid: None,
            parent_pid: None,
            file_path: Some(path.to_string()),
            file_sha256: None,
            matched_indicator: Some("Canary file modified or deleted".to_string()),
            policy_version: policy_version.to_string(),
            collected_at: chrono::Utc::now().to_rfc3339(),
            tags: Vec::new(),
            matched_strings: Vec::new(),
            rule_metadata: HashMap::new(),
            scan_duration_ms: None,
            matched_rules: Vec::new(),
            evidence_controls: Vec::new(),
            response: None,
            recovery_hints: None,
            rollback_evidence: None,
            rollback_file_paths: Vec::new(),
        });
    }

    // 2. Entropy delta detector on file writes
    if let Ok(data) = std::fs::read(path) {
        if data.len() >= 512 {
            let entropy = calculate_entropy(&data);
            if entropy > 7.5 {
                return Some(EdrEvent {
                    kind: EdrDetectionKind::RansomwareCanary,
                    rule_id: "high_entropy_file_write".to_string(),
                    action: EdrAction::Monitor,
                    process_path: None,
                    process_pid: None,
                    parent_pid: None,
                    file_path: Some(path.to_string()),
                    file_sha256: Some(compute_sha256(&data)),
                    matched_indicator: Some(format!("Entropy: {:.4}", entropy)),
                    policy_version: policy_version.to_string(),
                    collected_at: chrono::Utc::now().to_rfc3339(),
                    tags: Vec::new(),
                    matched_strings: Vec::new(),
                    rule_metadata: HashMap::new(),
                    scan_duration_ms: None,
                    matched_rules: Vec::new(),
                    evidence_controls: Vec::new(),
                    response: None,
                    recovery_hints: None,
                    rollback_evidence: None,
                    rollback_file_paths: Vec::new(),
                });
            }
        }
    }

    // 3. Mass-rename / mass-write throttle
    let history_lock = WRITE_HISTORY.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut history) = history_lock.lock() {
        let now = Instant::now();
        // Clean history older than 2 seconds
        history.retain(|(t, _)| now.duration_since(*t) < Duration::from_secs(2));
        history.push((now, path.to_string()));
        
        if history.len() >= 5 {
            return Some(EdrEvent {
                kind: EdrDetectionKind::RansomwareCanary,
                rule_id: "mass_write_detect".to_string(),
                action: EdrAction::Monitor,
                process_path: None,
                process_pid: None,
                parent_pid: None,
                file_path: Some(path.to_string()),
                file_sha256: None,
                matched_indicator: Some(format!("{} writes detected in 2 seconds", history.len())),
                policy_version: policy_version.to_string(),
                collected_at: chrono::Utc::now().to_rfc3339(),
                tags: Vec::new(),
                matched_strings: Vec::new(),
                rule_metadata: HashMap::new(),
                scan_duration_ms: None,
                matched_rules: Vec::new(),
                evidence_controls: Vec::new(),
                response: None,
                recovery_hints: None,
                rollback_evidence: None,
                rollback_file_paths: Vec::new(),
            });
        }
    }

    None
}
