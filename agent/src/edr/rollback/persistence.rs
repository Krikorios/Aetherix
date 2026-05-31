use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use super::types::RollbackEvidence;

/// ---------------------------------------------------------------------------
/// Idempotency guard — consumed action ID tracking
///
/// Uses an in-memory cache (Mutex<HashSet>) for O(1) lookups combined with
/// atomic file writes for crash-safe persistence.
/// ---------------------------------------------------------------------------

/// Maximum number of evidence entries to retain (FIFO eviction).
const EVIDENCE_RETENTION_MAX_COUNT: usize = 100;

/// Maximum age of an evidence entry in days (mtime-based eviction).
const EVIDENCE_RETENTION_MAX_DAYS: u64 = 30;

/// Path to the consumed action IDs directory.
fn consumed_ids_dir() -> PathBuf {
    std::env::var("AETHERIX_ROLLBACK_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".aetherix").join("rollback")
        })
}

fn consumed_ids_path() -> PathBuf {
    consumed_ids_dir().join("consumed_ids")
}

/// Global cache: once loaded from disk, all reads go through this cache.
/// Writes update the cache and persist atomically.
fn cache() -> &'static Mutex<Option<HashSet<String>>> {
    static CACHE: std::sync::OnceLock<Mutex<Option<HashSet<String>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Load the set of already-consumed action IDs from disk into the cache.
fn ensure_cache_loaded() {
    let mut guard = cache().lock().unwrap();
    if guard.is_some() {
        return;
    }
    let path = consumed_ids_path();
    let ids = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .map(|content| {
                content
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| line.trim().to_string())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        HashSet::new()
    };
    *guard = Some(ids);
}

/// Load consumed IDs (from cache or disk).
pub fn load_consumed_ids() -> HashSet<String> {
    ensure_cache_loaded();
    let guard = cache().lock().unwrap();
    guard.clone().unwrap_or_default()
}

/// Persist the current set to disk using atomic write (temp file + rename).
fn atomic_persist(ids: &HashSet<String>) -> Result<(), String> {
    let dir = consumed_ids_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create state dir: {e}"))?;

    let path = consumed_ids_path();
    let tmp_path = dir.join("consumed_ids.tmp");

    let mut content = String::new();
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    for id in &sorted {
        content.push_str(id);
        content.push('\n');
    }

    // Write to temp file
    let mut tmp = std::fs::File::create(&tmp_path)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    tmp.write_all(content.as_bytes())
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    tmp.sync_all()
        .map_err(|e| format!("failed to sync temp file: {e}"))?;

    // Atomically rename into place
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| format!("failed to rename temp file: {e}"))?;

    // Sync the parent directory on Unix
    #[cfg(unix)]
    {
        if let Ok(dir_file) = std::fs::File::open(&dir) {
            let _ = dir_file.sync_all();
        }
    }

    Ok(())
}

/// Mark an action ID as consumed.
///
/// Updates the in-memory cache and persists atomically to disk.
/// Errors during persistence are logged via eprintln but do not
/// prevent the in-memory update.
pub fn mark_action_consumed(action_id: &str) {
    ensure_cache_loaded();
    let mut guard = cache().lock().unwrap();
    let ids = guard.as_mut().unwrap();

    let inserted = ids.insert(action_id.to_string());
    if !inserted {
        // Already present — no need to persist
        return;
    }

    if let Err(e) = atomic_persist(ids) {
        eprintln!("aetherix-agent: failed to persist consumed action id: {e}");
    }
}

/// Check if an action ID has already been consumed (idempotency guard).
pub fn is_action_consumed(action_id: &str) -> bool {
    ensure_cache_loaded();
    let guard = cache().lock().unwrap();
    guard
        .as_ref()
        .map(|ids| ids.contains(action_id))
        .unwrap_or(false)
}

/// Number of consumed action IDs (for diagnostics).
pub fn consumed_count() -> usize {
    ensure_cache_loaded();
    let guard = cache().lock().unwrap();
    guard.as_ref().map(|ids| ids.len()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Evidence store — persisted RollbackEvidence by action_id
// ---------------------------------------------------------------------------

fn evidence_store_dir() -> PathBuf {
    consumed_ids_dir().join("evidence_store")
}

fn evidence_store_path(action_id: &str) -> PathBuf {
    evidence_store_dir().join(format!("{action_id}.json"))
}

/// Persist a `RollbackEvidence` for a given action ID so that subsequent
/// idempotent lookups can return the original evidence instead of a generic
/// refusal.
pub fn store_evidence(action_id: &str, evidence: &RollbackEvidence) {
    let dir = evidence_store_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("aetherix-agent: failed to create evidence store dir: {e}");
        return;
    }

    let json = match serde_json::to_string(evidence) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aetherix-agent: failed to serialize evidence: {e}");
            return;
        }
    };

    let path = evidence_store_path(action_id);
    let tmp_path = dir.join(format!("{action_id}.tmp"));

    if let Err(e) = std::fs::write(&tmp_path, &json) {
        eprintln!("aetherix-agent: failed to write evidence temp file: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        eprintln!("aetherix-agent: failed to rename evidence file: {e}");
    }
}

/// Load a previously stored `RollbackEvidence` for a given action ID.
///
/// Returns `None` if no evidence has been stored for this action.
pub fn load_evidence(action_id: &str) -> Option<RollbackEvidence> {
    let path = evidence_store_path(action_id);
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Evict old evidence entries based on retention policy.
///
/// Removes files older than `EVIDENCE_RETENTION_MAX_DAYS` and, if the
/// count still exceeds `EVIDENCE_RETENTION_MAX_COUNT`, removes the oldest
/// entries (by mtime) until the count is within bounds.
pub fn evict_old_evidence() {
    let dir = evidence_store_dir();
    if !dir.exists() {
        return;
    }

    let dir_entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("aetherix-agent: failed to read evidence store dir: {e}");
            return;
        }
    };

    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = dir_entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "json").unwrap_or(false))
        .filter_map(|e| {
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((e.path(), mtime))
        })
        .collect();

    if entries.is_empty() {
        return;
    }

    // Remove entries older than max days
    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(EVIDENCE_RETENTION_MAX_DAYS * 86400);

    let mut deleted = 0usize;
    entries.retain(|(path, mtime)| {
        if *mtime < cutoff {
            let _ = std::fs::remove_file(path);
            deleted += 1;
            false
        } else {
            true
        }
    });

    // If still over the count limit, remove oldest entries
    if entries.len() > EVIDENCE_RETENTION_MAX_COUNT {
        entries.sort_by(|a, b| a.1.cmp(&b.1)); // oldest first
        let to_remove = entries.len() - EVIDENCE_RETENTION_MAX_COUNT;
        for (path, _) in entries.iter().take(to_remove) {
            let _ = std::fs::remove_file(path);
            deleted += 1;
        }
    }

    if deleted > 0 {
        println!("aetherix-agent: evicted {deleted} old evidence entr(ies)");
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::rollback::{RollbackPathDecision, RollbackPathOutcome};
    use std::sync::Mutex;

    /// Serialize all persistence tests to avoid global-cache interference.
    static TEST_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    fn test_lock() -> &'static Mutex<()> {
        TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn reset_cache() {
        let mut guard = cache().lock().unwrap();
        *guard = None;
    }

    fn clean_file() {
        let path = consumed_ids_path();
        let _ = std::fs::remove_file(&path);
        let dir = consumed_ids_dir();
        let _ = std::fs::remove_file(dir.join("consumed_ids.tmp"));
        let _ = std::fs::remove_dir_all(dir.join("evidence_store"));
    }

    #[test]
    fn mark_and_check_consumed() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();
        assert!(!is_action_consumed("test-action-1"));
        mark_action_consumed("test-action-1");
        assert!(is_action_consumed("test-action-1"));
        clean_file();
    }

    #[test]
    fn is_action_consumed_returns_false_for_unknown() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();
        assert!(!is_action_consumed("nonexistent-action"));
    }

    #[test]
    fn mark_same_action_twice_is_idempotent() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();
        mark_action_consumed("dup-action");
        mark_action_consumed("dup-action");
        assert!(is_action_consumed("dup-action"));
        clean_file();
    }

    #[test]
    fn distinct_actions_are_independent() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();
        mark_action_consumed("action-a");
        mark_action_consumed("action-b");
        assert!(is_action_consumed("action-a"));
        assert!(is_action_consumed("action-b"));
        clean_file();
    }

    #[test]
    fn atomic_persist_and_reload() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        mark_action_consumed("persist-test-1");
        mark_action_consumed("persist-test-2");

        let path = consumed_ids_path();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("persist-test-1"));
        assert!(content.contains("persist-test-2"));

        reset_cache();
        let loaded = load_consumed_ids();
        assert!(loaded.contains("persist-test-1"));
        assert!(loaded.contains("persist-test-2"));
        assert_eq!(loaded.len(), 2);
        clean_file();
    }

    #[test]
    fn consumed_count_increases_after_mark() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();
        let initial = consumed_count();
        mark_action_consumed("count-test");
        assert_eq!(consumed_count(), initial + 1);
        clean_file();
    }

    #[test]
    fn cache_respects_empty_file() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        let ids = load_consumed_ids();
        assert!(ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Evidence store tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_and_load_evidence_roundtrip() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        let evidence = super::RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec!["trace-1".to_string()],
            evidence_controls: vec![],
            endpoint_id: "ep-1".to_string(),
            customer_id: None,
            policy_version: "pol-v1".to_string(),
            requester_id: "req-1".to_string(),
            approver_ids: vec![],
            simulation_id: "sim-1".to_string(),
            candidate_set_hash: "hash-1".to_string(),
            approved_action_id: "action-1".to_string(),
            provider: "vss".to_string(),
            recovery_point_id: "rp-1".to_string(),
            recovery_point_created_at: "now".to_string(),
            recovery_point_expires_at: None,
            recovery_point_verified: true,
            metadata_preserved: Some(true),
            provider_refusal: None,
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "1.0".to_string(),
            os_platform: "test".to_string(),
            privilege_context: "user".to_string(),
        };

        store_evidence("action-1", &evidence);

        let loaded = load_evidence("action-1").expect("should load stored evidence");
        assert_eq!(loaded.status, "executed");
        assert_eq!(loaded.approved_action_id, "action-1");
        assert_eq!(loaded.provider, "vss");

        clear_evidence_store_for_test();
    }

    #[test]
    fn load_evidence_returns_none_for_missing() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        assert!(load_evidence("nonexistent-action").is_none());
    }

    #[test]
    fn store_evidence_overwrites_previous() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        let ev1 = super::RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec!["v1".to_string()],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: String::new(),
            approved_action_id: "ovr-action".to_string(),
            provider: "vss".to_string(),
            recovery_point_id: String::new(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: None,
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: String::new(),
            os_platform: String::new(),
            privilege_context: String::new(),
        };
        let ev2 = super::RollbackEvidence {
            status: "failed".to_string(),
            decision_trace: vec!["v2".to_string()],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: String::new(),
            approved_action_id: "ovr-action".to_string(),
            provider: "apfs".to_string(),
            recovery_point_id: String::new(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: Some("error".to_string()),
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: String::new(),
            os_platform: String::new(),
            privilege_context: String::new(),
        };

        store_evidence("ovr-action", &ev1);
        store_evidence("ovr-action", &ev2);

        let loaded = load_evidence("ovr-action").expect("should load overwritten evidence");
        assert_eq!(loaded.status, "failed");
        assert_eq!(loaded.provider, "apfs");

        clear_evidence_store_for_test();
    }

    #[test]
    fn re_submitting_consumed_action_id_returns_exact_original_evidence() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        let original = super::RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec![
                "simulation restore: restored=2, failed=0, skipped=1".to_string(),
                "approved_action_id=re-submit-test".to_string(),
            ],
            evidence_controls: vec!["nist-csf-2.0:RS.MI".to_string()],
            endpoint_id: "ep-re-submit".to_string(),
            customer_id: Some("cust-42".to_string()),
            policy_version: "pol-v2".to_string(),
            requester_id: "req-alice".to_string(),
            approver_ids: vec!["approver-bob".to_string()],
            simulation_id: "sim-99".to_string(),
            candidate_set_hash: "hash-99".to_string(),
            approved_action_id: "re-submit-test".to_string(),
            provider: "simulation".to_string(),
            recovery_point_id: "rp-sim-1".to_string(),
            recovery_point_created_at: "2026-05-28T10:00:00Z".to_string(),
            recovery_point_expires_at: Some("2026-06-04T10:00:00Z".to_string()),
            recovery_point_verified: true,
            metadata_preserved: Some(true),
            provider_refusal: None,
            refusal_reason_code: Some("not_in_protected_root".to_string()),
            restored_paths: vec![
                RollbackPathDecision {
                    path: "/home/user/docs/report.docx".to_string(),
                    outcome: RollbackPathOutcome::Restored,
                    reason: "ok".to_string(),
                    refusal_reason_code: None,
                    bytes_affected: 4096,
                    hash_before: Some("abc123".to_string()),
                    hash_after: Some("def456".to_string()),
                    metadata_diff: Some(vec!["atime_updated".to_string()]),
                },
                RollbackPathDecision {
                    path: "/home/user/docs/budget.xlsx".to_string(),
                    outcome: RollbackPathOutcome::Restored,
                    reason: "ok".to_string(),
                    refusal_reason_code: None,
                    bytes_affected: 8192,
                    hash_before: Some("aaa111".to_string()),
                    hash_after: Some("bbb222".to_string()),
                    metadata_diff: Some(vec!["owner_restored".to_string()]),
                },
            ],
            failed_paths: vec![],
            skipped_paths: vec![
                RollbackPathDecision {
                    path: "/var/tmp/scratch.bin".to_string(),
                    outcome: RollbackPathOutcome::RefusedOutOfScope,
                    reason: "path not under any protected root".to_string(),
                    refusal_reason_code: Some("not_in_protected_root".to_string()),
                    bytes_affected: 0,
                    hash_before: None,
                    hash_after: None,
                    metadata_diff: None,
                },
            ],
            provider_version: "1.0.0".to_string(),
            os_platform: "windows".to_string(),
            privilege_context: "system".to_string(),
        };

        // Simulate: mark consumed + store evidence
        crate::edr::rollback::persistence::mark_action_consumed("re-submit-test");
        store_evidence("re-submit-test", &original);

        // Verify mark worked
        assert!(crate::edr::rollback::persistence::is_action_consumed("re-submit-test"));

        // Re-load — must be byte-for-byte identical to original
        let loaded = load_evidence("re-submit-test")
            .expect("should load cached evidence for consumed action");
        assert_eq!(loaded, original, "cached evidence must match original exactly");

        // Spot-check per-path outcomes preserved
        assert_eq!(loaded.restored_paths.len(), 2);
        assert_eq!(loaded.skipped_paths.len(), 1);
        assert_eq!(loaded.restored_paths[0].path, "/home/user/docs/report.docx");
        assert_eq!(loaded.restored_paths[0].outcome, RollbackPathOutcome::Restored);
        assert_eq!(loaded.skipped_paths[0].outcome, RollbackPathOutcome::RefusedOutOfScope);

        clear_evidence_store_for_test();
    }

    #[test]
    fn evict_old_evidence_retains_recent_entries() {
        let _lock = test_lock().lock().unwrap();
        reset_cache();
        clean_file();

        let evidence = super::RollbackEvidence {
            status: "executed".to_string(),
            decision_trace: vec![],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: String::new(),
            approved_action_id: "recent".to_string(),
            provider: String::new(),
            recovery_point_id: String::new(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: None,
            refusal_reason_code: None,
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: String::new(),
            os_platform: String::new(),
            privilege_context: String::new(),
        };

        store_evidence("recent-action", &evidence);
        assert!(load_evidence("recent-action").is_some());

        evict_old_evidence();

        // Recent entry should survive
        assert!(load_evidence("recent-action").is_some());

        clear_evidence_store_for_test();
    }

    /// Test helper: remove evidence store files.
    fn clear_evidence_store_for_test() {
        let dir = evidence_store_dir();
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
