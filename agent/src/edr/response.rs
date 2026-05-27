use super::{
    EdrAction, EdrEvent, QuarantineKdf, QuarantineManifest, ResponseEvidence, ResponseStatus,
};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const QUARANTINE_DIR: &str = ".aetherix/quarantine";
const METADATA_EXT: &str = ".meta.json";
const ENCRYPTED_EXT: &str = "encrypted";
const ARGON2_MEMORY_COST_KIB: u32 = 19 * 1024;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const KEY_LEN: usize = 32;

/// Derive an AES-256 key from a passphrase using SHA-256.
///
/// Deprecated compatibility helper for older tests and manifests. New
/// quarantines derive per-artifact keys with Argon2id and store KDF metadata
/// in the manifest.
pub fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hash = Sha256::digest(passphrase.as_bytes());
    key.copy_from_slice(&hash);
    key
}

pub fn quarantine_key_material(passphrase: &str) -> [u8; 32] {
    derive_key(passphrase)
}

pub fn quarantine_secret_from_agent_secret(agent_secret: &str) -> String {
    agent_secret.to_string()
}

/// Get the quarantine directory path.
pub fn quarantine_dir() -> PathBuf {
    quarantine_dir_from_env()
}

fn quarantine_dir_from_env() -> PathBuf {
    if let Ok(path) = std::env::var("AETHERIX_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(&home).join(QUARANTINE_DIR)
}

/// Apply a response action to an EDR event. Monitor/review actions never mutate
/// the host; dangerous actions require the event action to already be promoted
/// by policy and always return auditable evidence.
pub fn apply_to_event(event: &mut EdrEvent, encryption_key: &[u8; 32]) -> ResponseEvidence {
    apply_to_event_with_secret(event, encryption_key)
}

pub fn apply_to_event_with_secret(
    event: &mut EdrEvent,
    quarantine_secret: &[u8],
) -> ResponseEvidence {
    let evidence = execute(
        &event.action,
        event.process_pid,
        event.file_path.as_deref(),
        event.file_sha256.as_deref(),
        &event.rule_id,
        &event.policy_version,
        &event.evidence_controls,
        quarantine_secret,
    );
    event.response = Some(evidence.clone());
    evidence
}

/// Compatibility wrapper for queued control-plane actions and older tests.
pub fn apply(
    action: &EdrAction,
    target_pid: Option<u32>,
    target_path: Option<&str>,
    encryption_key: &[u8; 32],
) -> Result<()> {
    let evidence = execute(
        action,
        target_pid,
        target_path,
        None,
        "manual_response",
        "manual",
        &[],
        encryption_key,
    );
    if evidence.status == ResponseStatus::Failed {
        anyhow::bail!(
            evidence
                .error
                .unwrap_or_else(|| "response action failed".to_string())
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute(
    action: &EdrAction,
    target_pid: Option<u32>,
    target_path: Option<&str>,
    file_sha256: Option<&str>,
    rule_id: &str,
    policy_version: &str,
    evidence_controls: &[String],
    quarantine_secret: &[u8],
) -> ResponseEvidence {
    let mut evidence = ResponseEvidence {
        action: action.clone(),
        status: ResponseStatus::Staged,
        attempted_at: chrono::Utc::now().to_rfc3339(),
        policy_version: policy_version.to_string(),
        rule_id: rule_id.to_string(),
        target_pid,
        target_path: target_path.map(str::to_string),
        file_sha256: file_sha256.map(str::to_string),
        platform: std::env::consts::OS.to_string(),
        platform_api: "none".to_string(),
        decision_trace: Vec::new(),
        error: None,
        quarantine: None,
        evidence_controls: evidence_controls.to_vec(),
    };

    evidence
        .decision_trace
        .push(format!("policy_version={policy_version}"));
    evidence
        .decision_trace
        .push(format!("requested_action={action:?}"));

    match action {
        EdrAction::Monitor | EdrAction::Review => {
            evidence.status = ResponseStatus::Staged;
            evidence
                .decision_trace
                .push("monitor/review mode: no host mutation attempted".to_string());
        }
        EdrAction::Quarantine => match target_path {
            Some(path) => match quarantine_file_with_secret(Path::new(path), rule_id, quarantine_secret) {
                Ok(manifest) => {
                    evidence.status = ResponseStatus::Executed;
                    evidence.platform_api = "filesystem+aes-256-gcm".to_string();
                    evidence.file_sha256 = Some(manifest.sha256_hash.clone());
                    evidence.quarantine = Some(manifest);
                    evidence
                        .decision_trace
                        .push("quarantine executed: encrypted artifact and chained manifest written".to_string());
                }
                Err(err) => fail(&mut evidence, err),
            },
            None => fail_message(&mut evidence, "quarantine requires target_path"),
        },
        EdrAction::QuarantineList => match list_quarantine() {
            Ok(items) => {
                evidence.status = ResponseStatus::Executed;
                evidence.platform_api = "filesystem-quarantine-list".to_string();
                evidence
                    .decision_trace
                    .push(format!("quarantine list completed: {} item(s)", items.len()));
            }
            Err(err) => fail(&mut evidence, err),
        },
        EdrAction::QuarantineRestore => match target_path {
            Some(quarantine_id) => match restore_file_with_secret(quarantine_id, quarantine_secret) {
                Ok(manifest) => {
                    evidence.status = ResponseStatus::Executed;
                    evidence.platform_api = "filesystem+aes-256-gcm-restore".to_string();
                    evidence.target_path = Some(manifest.original_path.clone());
                    evidence.file_sha256 = Some(manifest.sha256_hash.clone());
                    evidence.quarantine = Some(manifest);
                    evidence
                        .decision_trace
                        .push("quarantine restore completed after manifest and hash verification".to_string());
                }
                Err(err) => fail(&mut evidence, err),
            },
            None => fail_message(&mut evidence, "quarantine restore requires quarantine_id as target_path"),
        },
        EdrAction::Kill => match target_pid {
            Some(pid) => match kill_process(pid) {
                Ok(api) => {
                    evidence.status = ResponseStatus::Executed;
                    evidence.platform_api = api;
                    evidence
                        .decision_trace
                        .push("process termination signal sent".to_string());
                }
                Err(err) => fail(&mut evidence, err),
            },
            None => fail_message(&mut evidence, "kill requires target_pid"),
        },
        EdrAction::Isolate => {
            evidence.status = ResponseStatus::Executed;
            evidence.platform_api = "isolation-intent".to_string();
            evidence.decision_trace.push(
                "network isolation intent recorded; firewall backend pending platform implementation"
                    .to_string(),
            );
            // TODO: apply platform firewall rules while preserving control-plane access.
        }
    }

    evidence
}

fn fail(evidence: &mut ResponseEvidence, err: anyhow::Error) {
    evidence.status = ResponseStatus::Failed;
    evidence.error = Some(err.to_string());
    evidence.decision_trace.push("response action failed".to_string());
}

fn fail_message(evidence: &mut ResponseEvidence, message: &str) {
    evidence.status = ResponseStatus::Failed;
    evidence.error = Some(message.to_string());
    evidence.decision_trace.push(message.to_string());
}

/// Quarantine a file: encrypt it with AES-256-GCM, write a manifest, then
/// remove the original only after both artifact and manifest are durable.
pub fn quarantine_file(
    path: &Path,
    rule_id: &str,
    encryption_key: &[u8; 32],
) -> Result<QuarantineManifest> {
    quarantine_file_at(path, rule_id, encryption_key, &quarantine_dir())
}

pub fn quarantine_file_with_secret(
    path: &Path,
    rule_id: &str,
    quarantine_secret: &[u8],
) -> Result<QuarantineManifest> {
    quarantine_file_at(path, rule_id, quarantine_secret, &quarantine_dir())
}

fn quarantine_file_at(
    path: &Path,
    rule_id: &str,
    quarantine_secret: &[u8],
    qdir: &Path,
) -> Result<QuarantineManifest> {
    if !path.exists() || !path.is_file() {
        anyhow::bail!("target is not a regular file: {}", path.display());
    }

    fs::create_dir_all(qdir).context("unable to create quarantine directory")?;

    let quarantine_id = uuid::Uuid::new_v4().to_string();
    let quarantined_path = qdir.join(format!("{quarantine_id}.{ENCRYPTED_EXT}"));
    let metadata_path = qdir.join(format!("{quarantine_id}{METADATA_EXT}"));

    let original_metadata = fs::metadata(path).context("unable to read target metadata")?;
    let original_modified_at = original_metadata
        .modified()
        .ok()
        .map(chrono::DateTime::<chrono::Utc>::from)
        .map(|dt| dt.to_rfc3339());
    let original_permissions = permissions_string(&original_metadata);
    let original_data = fs::read(path).context("unable to read target file")?;
    let file_size = original_data.len() as u64;
    let sha256_hash = format!("{:x}", Sha256::digest(&original_data));

    let (encryption_key, kdf) = derive_new_quarantine_key(quarantine_secret)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| anyhow::anyhow!("invalid encryption key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, original_data.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut encrypted_data = Vec::with_capacity(12 + ciphertext.len());
    encrypted_data.extend_from_slice(&nonce_bytes);
    encrypted_data.extend_from_slice(&ciphertext);
    fs::write(&quarantined_path, &encrypted_data).context("unable to write quarantine artifact")?;

    let previous_manifest_hash = latest_manifest_hash(qdir)?;
    let quarantined_at = chrono::Utc::now().to_rfc3339();
    let mut manifest = QuarantineManifest {
        quarantine_id,
        original_path: path.to_string_lossy().into_owned(),
        original_modified_at,
        original_permissions,
        quarantined_path: quarantined_path.to_string_lossy().into_owned(),
        metadata_path: metadata_path.to_string_lossy().into_owned(),
        quarantined_at,
        sha256_hash,
        rule_id: rule_id.to_string(),
        file_size,
        encrypted: true,
        kdf: Some(kdf),
        previous_manifest_hash,
        manifest_hash: String::new(),
    };
    manifest.manifest_hash = manifest_hash(&manifest)?;
    fs::write(&metadata_path, serde_json::to_string_pretty(&manifest)?)
        .context("unable to write quarantine manifest")?;

    fs::remove_file(path).context("unable to remove original after quarantine")?;
    Ok(manifest)
}

/// Restore a quarantined file to its original location.
pub fn restore_file(quarantine_id: &str, encryption_key: &[u8; 32]) -> Result<()> {
    restore_file_at(quarantine_id, encryption_key, &quarantine_dir()).map(|_| ())
}

pub fn restore_file_with_secret(
    quarantine_id: &str,
    quarantine_secret: &[u8],
) -> Result<QuarantineManifest> {
    restore_file_at(quarantine_id, quarantine_secret, &quarantine_dir())
}

fn restore_file_at(
    quarantine_id: &str,
    quarantine_secret: &[u8],
    qdir: &Path,
) -> Result<QuarantineManifest> {
    let quarantined_path = qdir.join(format!("{quarantine_id}.{ENCRYPTED_EXT}"));
    let metadata_path = qdir.join(format!("{quarantine_id}{METADATA_EXT}"));

    let meta_json = fs::read_to_string(&metadata_path).context("metadata not found")?;
    let manifest: QuarantineManifest = serde_json::from_str(&meta_json)?;
    verify_manifest_hash(&manifest)?;

    let encrypted_data = fs::read(&quarantined_path).context("quarantined file not found")?;
    if encrypted_data.len() < 12 {
        anyhow::bail!("corrupted quarantine file: too short");
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let encryption_key = derive_manifest_key(quarantine_secret, &manifest)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| anyhow::anyhow!("invalid encryption key: {e}"))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    let actual_hash = format!("{:x}", Sha256::digest(&plaintext));
    if actual_hash != manifest.sha256_hash {
        anyhow::bail!(
            "integrity check failed: hash mismatch (expected {}, got {})",
            manifest.sha256_hash,
            actual_hash
        );
    }

    let restore_path = PathBuf::from(&manifest.original_path);
    if let Some(parent) = restore_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&restore_path, &plaintext)?;

    fs::remove_file(&quarantined_path)?;
    fs::remove_file(&metadata_path)?;
    Ok(manifest)
}

/// List all quarantined items with their manifests.
pub fn list_quarantine() -> Result<Vec<(String, QuarantineManifest)>> {
    let qdir = quarantine_dir();
    if !qdir.exists() {
        return Ok(Vec::new());
    }

    let mut items = Vec::new();
    for entry in fs::read_dir(&qdir)? {
        let entry = entry?;
        let path = entry.path();
        if path.to_string_lossy().ends_with(METADATA_EXT) {
            let manifest_json = fs::read_to_string(&path)?;
            let manifest: QuarantineManifest = serde_json::from_str(&manifest_json)?;
            items.push((manifest.quarantine_id.clone(), manifest));
        }
    }
    Ok(items)
}

fn derive_new_quarantine_key(secret: &[u8]) -> Result<([u8; KEY_LEN], QuarantineKdf)> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kdf = QuarantineKdf {
        algorithm: "argon2id".to_string(),
        salt_b64: general_purpose::STANDARD.encode(salt),
        memory_cost_kib: ARGON2_MEMORY_COST_KIB,
        time_cost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        output_len: KEY_LEN as u32,
    };
    let key = derive_argon2id_key(secret, &kdf)?;
    Ok((key, kdf))
}

fn derive_manifest_key(secret: &[u8], manifest: &QuarantineManifest) -> Result<[u8; KEY_LEN]> {
    match manifest.kdf.as_ref() {
        Some(kdf) => derive_argon2id_key(secret, kdf),
        None => {
            let mut key = [0u8; KEY_LEN];
            if secret.len() == KEY_LEN {
                key.copy_from_slice(secret);
                return Ok(key);
            }
            let hash = Sha256::digest(secret);
            key.copy_from_slice(&hash);
            Ok(key)
        }
    }
}

fn derive_argon2id_key(secret: &[u8], kdf: &QuarantineKdf) -> Result<[u8; KEY_LEN]> {
    if kdf.algorithm != "argon2id" {
        anyhow::bail!("unsupported quarantine kdf: {}", kdf.algorithm);
    }
    if kdf.output_len != KEY_LEN as u32 {
        anyhow::bail!("unsupported quarantine key length: {}", kdf.output_len);
    }
    let salt = general_purpose::STANDARD
        .decode(&kdf.salt_b64)
        .context("invalid quarantine kdf salt")?;
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("invalid quarantine kdf parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret, &salt, &mut key)
        .map_err(|e| anyhow::anyhow!("quarantine key derivation failed: {e}"))?;
    Ok(key)
}

fn latest_manifest_hash(qdir: &Path) -> Result<Option<String>> {
    let mut newest: Option<(std::time::SystemTime, String)> = None;
    for entry in fs::read_dir(qdir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.to_string_lossy().ends_with(METADATA_EXT) {
            continue;
        }
        let manifest_json = fs::read_to_string(&path)?;
        if let Ok(manifest) = serde_json::from_str::<QuarantineManifest>(&manifest_json) {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if newest.as_ref().map(|(at, _)| modified > *at).unwrap_or(true) {
                newest = Some((modified, manifest.manifest_hash));
            }
        }
    }
    Ok(newest.map(|(_, hash)| hash))
}

fn manifest_hash(manifest: &QuarantineManifest) -> Result<String> {
    #[derive(Serialize)]
    struct HashableManifest<'a> {
        quarantine_id: &'a str,
        original_path: &'a str,
        original_modified_at: &'a Option<String>,
        original_permissions: &'a Option<String>,
        quarantined_path: &'a str,
        metadata_path: &'a str,
        quarantined_at: &'a str,
        sha256_hash: &'a str,
        rule_id: &'a str,
        file_size: u64,
        encrypted: bool,
        kdf: &'a Option<QuarantineKdf>,
        previous_manifest_hash: &'a Option<String>,
    }

    let hashable = HashableManifest {
        quarantine_id: &manifest.quarantine_id,
        original_path: &manifest.original_path,
        original_modified_at: &manifest.original_modified_at,
        original_permissions: &manifest.original_permissions,
        quarantined_path: &manifest.quarantined_path,
        metadata_path: &manifest.metadata_path,
        quarantined_at: &manifest.quarantined_at,
        sha256_hash: &manifest.sha256_hash,
        rule_id: &manifest.rule_id,
        file_size: manifest.file_size,
        encrypted: manifest.encrypted,
        kdf: &manifest.kdf,
        previous_manifest_hash: &manifest.previous_manifest_hash,
    };
    let bytes = serde_json::to_vec(&hashable)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn verify_manifest_hash(manifest: &QuarantineManifest) -> Result<()> {
    let expected = manifest_hash(manifest)?;
    if expected != manifest.manifest_hash && legacy_manifest_hash(manifest)? != manifest.manifest_hash
    {
        anyhow::bail!(
            "manifest hash mismatch (expected {}, got {})",
            manifest.manifest_hash,
            expected
        );
    }
    Ok(())
}

fn legacy_manifest_hash(manifest: &QuarantineManifest) -> Result<String> {
    #[derive(Serialize)]
    struct LegacyHashableManifest<'a> {
        quarantine_id: &'a str,
        original_path: &'a str,
        original_modified_at: &'a Option<String>,
        original_permissions: &'a Option<String>,
        quarantined_path: &'a str,
        metadata_path: &'a str,
        quarantined_at: &'a str,
        sha256_hash: &'a str,
        rule_id: &'a str,
        file_size: u64,
        encrypted: bool,
        previous_manifest_hash: &'a Option<String>,
    }

    let hashable = LegacyHashableManifest {
        quarantine_id: &manifest.quarantine_id,
        original_path: &manifest.original_path,
        original_modified_at: &manifest.original_modified_at,
        original_permissions: &manifest.original_permissions,
        quarantined_path: &manifest.quarantined_path,
        metadata_path: &manifest.metadata_path,
        quarantined_at: &manifest.quarantined_at,
        sha256_hash: &manifest.sha256_hash,
        rule_id: &manifest.rule_id,
        file_size: manifest.file_size,
        encrypted: manifest.encrypted,
        previous_manifest_hash: &manifest.previous_manifest_hash,
    };
    let bytes = serde_json::to_vec(&hashable)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[cfg(unix)]
fn permissions_string(metadata: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    Some(format!("{:o}", metadata.permissions().mode() & 0o7777))
}

#[cfg(not(unix))]
fn permissions_string(metadata: &fs::Metadata) -> Option<String> {
    Some(format!("readonly={}", metadata.permissions().readonly()))
}

#[cfg(unix)]
fn kill_process(pid: u32) -> Result<String> {
    if pid == std::process::id() {
        anyhow::bail!("refusing to kill current agent process");
    }
    let pid_i32 = i32::try_from(pid).context("pid out of range")?;
    let permission_check = unsafe { libc_kill(pid_i32, 0) };
    if permission_check != 0 {
        anyhow::bail!("process permission/existence check failed for pid {pid}");
    }

    let result = unsafe { libc_kill(pid_i32, 15) };
    if result == 0 {
        return Ok("unix-kill-sigterm".to_string());
    }

    let mut sys = sysinfo::System::new();
    let sys_pid = sysinfo::Pid::from(pid as usize);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sys_pid]), true);
    if let Some(process) = sys.process(sys_pid) {
        if process.kill() {
            return Ok("sysinfo-kill-fallback".to_string());
        }
    }
    anyhow::bail!("failed to terminate pid {pid}")
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(windows)]
fn kill_process(pid: u32) -> Result<String> {
    if pid == std::process::id() {
        anyhow::bail!("refusing to kill current agent process");
    }
    let mut sys = sysinfo::System::new();
    let sys_pid = sysinfo::Pid::from(pid as usize);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sys_pid]), true);
    let process = sys
        .process(sys_pid)
        .ok_or_else(|| anyhow::anyhow!("process not found or inaccessible: {pid}"))?;
    if process.kill() {
        Ok("windows-terminateprocess-via-sysinfo".to_string())
    } else {
        anyhow::bail!("failed to terminate pid {pid}; elevated permissions may be required")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn quarantine_roundtrip_preserves_manifest_hash() {
        let qdir = tempdir().unwrap();
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("malware.exe");
        fs::write(&test_file, "this is malicious content").unwrap();

        let key = derive_key("test-key-123");
        let manifest = quarantine_file_at(&test_file, "yara_eicar", &key, qdir.path()).unwrap();

        assert!(manifest.encrypted);
        assert_eq!(manifest.kdf.as_ref().unwrap().algorithm, "argon2id");
        assert!(manifest.manifest_hash.starts_with("sha256:"));
        assert!(!test_file.exists());
        verify_manifest_hash(&manifest).unwrap();

        restore_file_at(&manifest.quarantine_id, &key, qdir.path()).unwrap();
        assert_eq!(fs::read_to_string(&test_file).unwrap(), "this is malicious content");
    }

    #[test]
    fn quarantine_manifest_chains_to_previous_manifest() {
        let qdir = tempdir().unwrap();
        let dir = tempdir().unwrap();
        let key = derive_key("test-key-123");
        let first_file = dir.path().join("first.bin");
        let second_file = dir.path().join("second.bin");
        fs::write(&first_file, "first").unwrap();
        fs::write(&second_file, "second").unwrap();

        let first = quarantine_file_at(&first_file, "rule_1", &key, qdir.path()).unwrap();
        let second = quarantine_file_at(&second_file, "rule_2", &key, qdir.path()).unwrap();

        assert_eq!(second.previous_manifest_hash, Some(first.manifest_hash));
    }

    #[test]
    fn response_evidence_records_staged_monitor_mode() {
        let key = derive_key("test-key");
        let evidence = execute(
            &EdrAction::Review,
            None,
            None,
            None,
            "rule_1",
            "policy_1",
            &["nist-csf-2.0:DE.CM".to_string()],
            &key,
        );
        assert_eq!(evidence.status, ResponseStatus::Staged);
        assert_eq!(evidence.evidence_controls, vec!["nist-csf-2.0:DE.CM"]);
    }

    #[test]
    fn kill_refuses_current_process() {
        let key = derive_key("test-key");
        let evidence = execute(
            &EdrAction::Kill,
            Some(std::process::id()),
            None,
            None,
            "rule_1",
            "policy_1",
            &[],
            &key,
        );
        assert_eq!(evidence.status, ResponseStatus::Failed);
        assert!(evidence.error.unwrap().contains("refusing to kill current agent process"));
    }

    #[test]
    fn derive_key_is_deterministic() {
        let key1 = derive_key("passphrase");
        let key2 = derive_key("passphrase");
        assert_eq!(key1, key2);
        assert_ne!(key1, derive_key("different"));
    }

    #[test]
    fn quarantine_kdf_uses_unique_salt_per_manifest() {
        let qdir = tempdir().unwrap();
        let dir = tempdir().unwrap();
        let key = derive_key("test-key-123");
        let first_file = dir.path().join("first.bin");
        let second_file = dir.path().join("second.bin");
        fs::write(&first_file, "first").unwrap();
        fs::write(&second_file, "second").unwrap();

        let first = quarantine_file_at(&first_file, "rule_1", &key, qdir.path()).unwrap();
        let second = quarantine_file_at(&second_file, "rule_2", &key, qdir.path()).unwrap();

        assert_ne!(first.kdf.unwrap().salt_b64, second.kdf.unwrap().salt_b64);
    }
}
