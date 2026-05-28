#![cfg(windows)]

use super::provider::RollbackProvider;
use super::types::{
    ProbeResult, RecoveryPoint, RollbackCandidateSet, RollbackCapabilities, RollbackEvidence,
    RollbackPathDecision, RollbackPathOutcome, RollbackScope, RollbackSimulation,
};
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::process::Command;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, LUID_AND_ATTRIBUTES,
    SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW,
};
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_TYPE,
    SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Windows VSS-based rollback provider.
///
/// Uses WMI (Win32_ShadowCopy) to query shadow copies and volume enumeration
/// APIs for real volume capability detection.
pub struct VssRollbackProvider;

impl VssRollbackProvider {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
struct VolumeInfo {
    volume_guid: String, // "\\\\?\\Volume{...}"
    mount_point: String, // "C:\\"
    filesystem: String,  // "NTFS"
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShadowCopyInfo {
    id: String,
    device_object: String,
    volume_name: String,
    created_at: String,
    protected_root: String,
    state: Option<u32>,
    verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CimShadowCopy {
    id: Option<String>,
    device_object: Option<String>,
    install_date: Option<String>,
    volume_name: Option<String>,
    state: Option<u32>,
}

impl VssRollbackProvider {
    fn normalize_windows_root(value: &str) -> String {
        let mut root = value.trim().replace('/', "\\");
        if root.len() == 2 && root.as_bytes()[1] == b':' {
            root.push('\\');
        }
        root.to_ascii_lowercase()
    }

    fn normalize_volume_name(value: &str) -> String {
        value.trim_end_matches('\\').to_ascii_lowercase()
    }

    fn emit_diagnostic(event: &str, payload: serde_json::Value) {
        eprintln!(
            "{}",
            serde_json::json!({
                "component": "aetherix-agent",
                "provider": "vss",
                "event": event,
                "payload": payload,
            })
        );
    }

    fn windows_path_depth(path: &str) -> u8 {
        path.replace('/', "\\")
            .trim_matches('\\')
            .split('\\')
            .filter(|part| !part.is_empty())
            .count()
            .saturating_sub(1)
            .min(u8::MAX as usize) as u8
    }

    fn hash_file(path: &str) -> std::io::Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];

        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn shadow_path_for_live_path(shadow: &ShadowCopyInfo, live_path: &str) -> Option<String> {
        let live_path = live_path.trim().replace('/', "\\");
        let protected_root = shadow.protected_root.trim().replace('/', "\\");
        let mut root = protected_root.clone();
        if root.len() == 2 && root.as_bytes()[1] == b':' {
            root.push('\\');
        }

        let live_lower = live_path.to_ascii_lowercase();
        let root_lower = root.to_ascii_lowercase();
        if live_lower != root_lower && !live_lower.starts_with(&root_lower) {
            return None;
        }

        let suffix = live_path.get(root.len()..).unwrap_or("").trim_start_matches('\\');
        let device = shadow.device_object.trim_end_matches('\\');
        if suffix.is_empty() {
            Some(format!("{}\\", device))
        } else {
            Some(format!("{}\\{}", device, suffix))
        }
    }

    fn parse_wmi_datetime(value: &str) -> Option<String> {
        if value.len() < 14 {
            return None;
        }

        let year = value.get(0..4)?.parse().ok()?;
        let month = value.get(4..6)?.parse().ok()?;
        let day = value.get(6..8)?.parse().ok()?;
        let hour = value.get(8..10)?.parse().ok()?;
        let minute = value.get(10..12)?.parse().ok()?;
        let second = value.get(12..14)?.parse().ok()?;

        let date = NaiveDate::from_ymd_opt(year, month, day)?;
        let time = NaiveTime::from_hms_opt(hour, minute, second)?;
        let naive = date.and_time(time);

        let offset = if value.len() >= 25 {
            let sign = value.as_bytes()[21] as char;
            let minutes: i32 = value.get(22..25)?.parse().ok()?;
            let seconds = minutes * 60;
            match sign {
                '+' => FixedOffset::east_opt(seconds),
                '-' => FixedOffset::west_opt(seconds),
                _ => FixedOffset::east_opt(0),
            }
        } else {
            FixedOffset::east_opt(0)
        }?;

        offset
            .from_local_datetime(&naive)
            .single()
            .map(|dt| dt.with_timezone(&Utc).to_rfc3339())
    }

    fn parse_shadow_copy_json(output: &str) -> Result<Vec<CimShadowCopy>, String> {
        let trimmed = output.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
            return Ok(Vec::new());
        }

        if trimmed.starts_with('[') {
            serde_json::from_str(trimmed)
                .map_err(|e| format!("parse Win32_ShadowCopy array failed: {}", e))
        } else {
            let item: CimShadowCopy = serde_json::from_str(trimmed)
                .map_err(|e| format!("parse Win32_ShadowCopy object failed: {}", e))?;
            Ok(vec![item])
        }
    }

    fn shadow_device_exists(device_object: &str) -> bool {
        if device_object.trim().is_empty() {
            return false;
        }
        [device_object.to_string(), format!("{}\\", device_object.trim_end_matches('\\'))]
            .iter()
            .any(|candidate| std::fs::metadata(candidate).is_ok())
    }

    fn map_shadow_copy(shadow: CimShadowCopy, volumes: &[VolumeInfo]) -> Option<ShadowCopyInfo> {
        Self::map_shadow_copy_with_verifier(shadow, volumes, Self::shadow_device_exists)
    }

    fn map_shadow_copy_with_verifier(
        shadow: CimShadowCopy,
        volumes: &[VolumeInfo],
        verifier: impl Fn(&str) -> bool,
    ) -> Option<ShadowCopyInfo> {
        let id = shadow.id?;
        let device_object = shadow.device_object?;
        let volume_name = shadow.volume_name?;
        let created_at = shadow
            .install_date
            .as_deref()
            .and_then(Self::parse_wmi_datetime)
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        let volume_key = Self::normalize_volume_name(&volume_name);
        let protected_root = volumes
            .iter()
            .find(|volume| Self::normalize_volume_name(&volume.volume_guid) == volume_key)
            .map(|volume| volume.mount_point.clone())
            .unwrap_or(volume_name.clone());
        let verified = verifier(&device_object) && shadow.state.unwrap_or(12) == 12;

        Some(ShadowCopyInfo {
            id,
            device_object,
            volume_name,
            created_at,
            protected_root,
            state: shadow.state,
            verified,
        })
    }

    fn recovery_point_is_non_expired(point: &RecoveryPoint) -> bool {
        match &point.expires_at {
            Some(expires_at) => DateTime::parse_from_rfc3339(expires_at)
                .map(|dt| dt.with_timezone(&Utc) > Utc::now())
                .unwrap_or(false),
            None => true,
        }
    }

    fn recovery_point_matches_scope(point: &RecoveryPoint, scope: &RollbackScope) -> bool {
        if scope.affected_paths.is_empty() {
            return true;
        }

        scope.affected_paths.iter().any(|path| {
            let path = Self::normalize_windows_root(path);
            point.protected_roots.iter().any(|root| {
                let root = Self::normalize_windows_root(root);
                path == root || path.starts_with(&root)
            })
        })
    }

    fn recovery_point_from_shadow(shadow: ShadowCopyInfo) -> RecoveryPoint {
        RecoveryPoint {
            id: shadow.id,
            provider: "vss".to_string(),
            created_at: shadow.created_at,
            expires_at: None,
            protected_roots: vec![shadow.protected_root],
            read_only: true,
            verified: shadow.verified,
        }
    }

    fn filter_recovery_points(
        points: impl IntoIterator<Item = RecoveryPoint>,
        scope: &RollbackScope,
    ) -> Vec<RecoveryPoint> {
        let mut points: Vec<RecoveryPoint> = points
            .into_iter()
            .filter(|point| point.verified)
            .filter(Self::recovery_point_is_non_expired)
            .filter(|point| Self::recovery_point_matches_scope(point, scope))
            .collect();
        points.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        points
    }

    fn simulation_result(
        candidates: &RollbackCandidateSet,
        decisions: Vec<RollbackPathDecision>,
        mut decision_trace: Vec<String>,
    ) -> RollbackSimulation {
        let restorable_count = decisions
            .iter()
            .filter(|decision| decision.outcome == RollbackPathOutcome::Restored)
            .count();
        decision_trace.push(format!(
            "vss simulation: {} candidate(s), {} restorable, {} skipped/refused",
            candidates.paths.len(),
            restorable_count,
            decisions.len().saturating_sub(restorable_count)
        ));

        RollbackSimulation {
            simulation_id: uuid::Uuid::new_v4().to_string(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            candidate_count: candidates.paths.len(),
            restorable_count,
            skipped_paths: decisions
                .into_iter()
                .filter(|decision| decision.outcome != RollbackPathOutcome::Restored)
                .collect(),
            destructive: false,
            valid_until: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            decision_trace,
        }
    }

    fn refusal_decision(path: &str, reason: impl Into<String>) -> RollbackPathDecision {
        RollbackPathDecision {
            path: path.to_string(),
            outcome: RollbackPathOutcome::RefusedOutOfScope,
            reason: reason.into(),
            bytes_affected: 0,
            hash_before: None,
            hash_after: None,
            metadata_diff: None,
        }
    }

    fn assess_candidate_path(
        shadow: &ShadowCopyInfo,
        path: &str,
        max_depth: u8,
    ) -> RollbackPathDecision {
        let depth = Self::windows_path_depth(path);
        if depth > max_depth {
            return Self::refusal_decision(
                path,
                format!("depth {depth} exceeds max_depth={max_depth}"),
            );
        }

        let Some(snapshot_path) = Self::shadow_path_for_live_path(shadow, path) else {
            return Self::refusal_decision(
                path,
                format!("path not under protected root {}", shadow.protected_root),
            );
        };

        let snapshot_metadata = match fs::metadata(&snapshot_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Self::refusal_decision(
                    path,
                    format!("not_found_in_point: {}", snapshot_path),
                );
            }
        };

        if snapshot_metadata.is_dir() {
            return Self::refusal_decision(
                path,
                "directory_restore_not_supported_in_simulation_slice",
            );
        }

        let snapshot_hash = match Self::hash_file(&snapshot_path) {
            Ok(hash) => hash,
            Err(err) => {
                return RollbackPathDecision {
                    path: path.to_string(),
                    outcome: RollbackPathOutcome::FailedIntegrity,
                    reason: format!("snapshot_hash_failed: {err}"),
                    bytes_affected: 0,
                    hash_before: None,
                    hash_after: None,
                    metadata_diff: None,
                };
            }
        };

        let live_metadata = match fs::metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return RollbackPathDecision {
                    path: path.to_string(),
                    outcome: RollbackPathOutcome::FailedIntegrity,
                    reason: format!("live_metadata_failed: {err}"),
                    bytes_affected: 0,
                    hash_before: Some(snapshot_hash),
                    hash_after: None,
                    metadata_diff: None,
                };
            }
        };

        let Some(live_metadata) = live_metadata else {
            return RollbackPathDecision {
                path: path.to_string(),
                outcome: RollbackPathOutcome::Restored,
                reason: "live_file_missing_snapshot_available".to_string(),
                bytes_affected: snapshot_metadata.len(),
                hash_before: Some(snapshot_hash),
                hash_after: None,
                metadata_diff: Some(vec!["live_missing".to_string()]),
            };
        };

        let live_hash = match Self::hash_file(path) {
            Ok(hash) => hash,
            Err(err) => {
                return RollbackPathDecision {
                    path: path.to_string(),
                    outcome: RollbackPathOutcome::FailedIntegrity,
                    reason: format!("live_hash_failed: {err}"),
                    bytes_affected: 0,
                    hash_before: Some(snapshot_hash),
                    hash_after: None,
                    metadata_diff: None,
                };
            }
        };

        if live_hash == snapshot_hash {
            return RollbackPathDecision {
                path: path.to_string(),
                outcome: RollbackPathOutcome::Skipped,
                reason: "no_change_needed".to_string(),
                bytes_affected: 0,
                hash_before: Some(snapshot_hash),
                hash_after: Some(live_hash),
                metadata_diff: None,
            };
        }

        if let (Ok(live_modified), Ok(snapshot_modified)) =
            (live_metadata.modified(), snapshot_metadata.modified())
        {
            if live_modified > snapshot_modified {
                return RollbackPathDecision {
                    path: path.to_string(),
                    outcome: RollbackPathOutcome::RefusedOutOfScope,
                    reason: "unsafe_overwrite: live file is newer than recovery point".to_string(),
                    bytes_affected: 0,
                    hash_before: Some(snapshot_hash),
                    hash_after: Some(live_hash),
                    metadata_diff: Some(vec!["live_modified_after_recovery_point".to_string()]),
                };
            }
        }

        let mut metadata_diff = Vec::new();
        if live_metadata.len() != snapshot_metadata.len() {
            metadata_diff.push(format!(
                "size:{}->{}",
                live_metadata.len(),
                snapshot_metadata.len()
            ));
        }

        RollbackPathDecision {
            path: path.to_string(),
            outcome: RollbackPathOutcome::Restored,
            reason: "snapshot_differs_and_safe_to_restore".to_string(),
            bytes_affected: snapshot_metadata.len(),
            hash_before: Some(snapshot_hash),
            hash_after: Some(live_hash),
            metadata_diff: if metadata_diff.is_empty() {
                None
            } else {
                Some(metadata_diff)
            },
        }
    }

    fn check_privilege(name: &str) -> (bool, String) {
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if !OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .is_ok()
            {
                return (false, "Failed to open process token".to_string());
            }

            let mut luid = LUID::default();
            let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            if !LookupPrivilegeValueW(None, PCWSTR(name_u16.as_ptr()), &mut luid).is_ok() {
                let _ = CloseHandle(token);
                return (false, format!("Failed to lookup privilege {}", name));
            }

            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }; 1],
            };

            let res = AdjustTokenPrivileges(
                token,
                BOOL(0),
                Some(&tp as *const _),
                0,
                None,
                None,
            );

            let _ = CloseHandle(token);

            if res.is_ok() {
                (true, format!("{}=enabled", name))
            } else {
                (false, format!("AdjustTokenPrivileges failed for {}", name))
            }
        }
    }

    fn check_vss_service_running() -> (bool, String) {
        unsafe {
            let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT);
            let scm = match scm {
                Ok(h) => h,
                Err(e) => return (false, format!("SCM connect failed: {:?}", e)),
            };

            let service_name: Vec<u16> = "VSS\0".encode_utf16().collect();
            let service = OpenServiceW(scm, PCWSTR(service_name.as_ptr()), SERVICE_QUERY_STATUS);
            let service = match service {
                Ok(h) => h,
                Err(e) => return (false, format!("OpenService VSS failed: {:?}", e)),
            };

            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut bytes_needed = 0;
            let res = QueryServiceStatusEx(
                service,
                SC_STATUS_TYPE(0), // SC_STATUS_PROCESS_INFO
                Some(&mut status as *mut _ as *mut u8),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            );

            if res.is_ok() {
                // SERVICE_RUNNING = 4 (0x00000004)
                let state_str = match status.dwCurrentState.0 {
                    1 => "STOPPED",
                    2 => "START_PENDING",
                    3 => "STOP_PENDING",
                    4 => "RUNNING",
                    5 => "CONTINUE_PENDING",
                    6 => "PAUSE_PENDING",
                    7 => "PAUSED",
                    _ => "UNKNOWN",
                };
                let running = status.dwCurrentState.0 == 4;
                (running, format!("state={}", state_str))
            } else {
                (false, "QueryServiceStatusEx failed".to_string())
            }
        }
    }

    fn discover_volumes() -> Vec<VolumeInfo> {
        let mut volumes = Vec::new();
        unsafe {
            let mut volume_name = [0u16; 512];
            let handle = FindFirstVolumeW(&mut volume_name);
            let handle = match handle {
                Ok(h) => h,
                Err(_) => return volumes,
            };

            loop {
                let len = volume_name.iter().position(|&x| x == 0).unwrap_or(volume_name.len());
                let volume_guid = String::from_utf16_lossy(&volume_name[..len]);

                // Map to mount point
                let mut mount_names = [0u16; 512];
                let mut return_len = 0;
                let mut mount_point = String::new();
                if GetVolumePathNamesForVolumeNameW(
                    PCWSTR(volume_name.as_ptr()),
                    Some(&mut mount_names),
                    &mut return_len,
                )
                .is_ok()
                {
                    let m_len = mount_names
                        .iter()
                        .position(|&x| x == 0)
                        .unwrap_or(mount_names.len());
                    if m_len > 0 {
                        mount_point = String::from_utf16_lossy(&mount_names[..m_len]);
                    }
                }

                // FS Type
                let mut fs_name = [0u16; 256];
                let mut filesystem = String::new();
                if GetVolumeInformationW(
                    PCWSTR(volume_name.as_ptr()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(&mut fs_name),
                )
                .is_ok()
                {
                    let fs_len = fs_name.iter().position(|&x| x == 0).unwrap_or(fs_name.len());
                    filesystem = String::from_utf16_lossy(&fs_name[..fs_len]);
                }

                if !mount_point.is_empty() {
                    volumes.push(VolumeInfo {
                        volume_guid,
                        mount_point,
                        filesystem,
                    });
                }

                let mut next_name = [0u16; 512];
                if !FindNextVolumeW(handle, &mut next_name).is_ok() {
                    break;
                }
                volume_name = next_name;
            }

            let _ = FindVolumeClose(handle);
        }
        volumes
    }

    fn query_shadow_copies() -> Result<Vec<CimShadowCopy>, String> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$items = Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object ID,DeviceObject,InstallDate,VolumeName,State; ConvertTo-Json -InputObject @($items) -Depth 3 -Compress",
            ])
            .output()
            .map_err(|e| format!("failed to execute Win32_ShadowCopy CIM query: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Win32_ShadowCopy CIM query failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_shadow_copy_json(&stdout)
    }

    fn enumerate_shadow_copies(volumes: &[VolumeInfo]) -> Result<Vec<ShadowCopyInfo>, String> {
        Self::query_shadow_copies().map(|shadows| {
            shadows
                .into_iter()
                .filter_map(|shadow| Self::map_shadow_copy(shadow, volumes))
                .collect()
        })
    }
}

impl RollbackProvider for VssRollbackProvider {
    fn capabilities(&self) -> RollbackCapabilities {
        RollbackCapabilities {
            provider_name: "vss".to_string(),
            provider_version: "1.0.0".to_string(),
            available: true,
            supported_os: vec!["windows".to_string()],
            supported_filesystems: vec!["ntfs".to_string(), "refs".to_string()],
            privilege_context: "SeBackupPrivilege+SeRestorePrivilege".to_string(),
        }
    }

    fn list_recovery_points(&self, scope: &RollbackScope) -> anyhow::Result<Vec<RecoveryPoint>> {
        let volumes = Self::discover_volumes();
        let shadow_copies = Self::enumerate_shadow_copies(&volumes).map_err(|err| {
            Self::emit_diagnostic(
                "list_recovery_points_failed",
                serde_json::json!({
                    "incident_id": scope.incident_id,
                    "affected_path_count": scope.affected_paths.len(),
                    "volume_count": volumes.len(),
                    "error": err,
                }),
            );
            anyhow::Error::msg(err)
        })?;
        let raw_count = shadow_copies.len();
        let verified_count = shadow_copies.iter().filter(|shadow| shadow.verified).count();
        let points = shadow_copies.into_iter().map(Self::recovery_point_from_shadow);
        let filtered = Self::filter_recovery_points(points, scope);
        Self::emit_diagnostic(
            "list_recovery_points",
            serde_json::json!({
                "incident_id": scope.incident_id,
                "affected_path_count": scope.affected_paths.len(),
                "volume_count": volumes.len(),
                "raw_shadow_copy_count": raw_count,
                "verified_shadow_copy_count": verified_count,
                "returned_recovery_point_count": filtered.len(),
                "recovery_point_ids": filtered.iter().map(|point| point.id.clone()).collect::<Vec<_>>(),
            }),
        );
        Ok(filtered)
    }

    fn simulate_restore(&self, candidates: &RollbackCandidateSet) -> anyhow::Result<RollbackSimulation> {
        let volumes = Self::discover_volumes();
        let shadow_copies = match Self::enumerate_shadow_copies(&volumes) {
            Ok(shadows) => shadows,
            Err(err) => {
                let decisions = candidates
                    .paths
                    .iter()
                    .map(|path| Self::refusal_decision(path, format!("recovery_point_enumeration_failed: {err}")))
                    .collect();
                return Ok(Self::simulation_result(
                    candidates,
                    decisions,
                    vec![format!("vss simulation failed to enumerate recovery points: {err}")],
                ));
            }
        };

        let Some(shadow) = shadow_copies
            .iter()
            .find(|shadow| shadow.id == candidates.recovery_point_id)
        else {
            let decisions = candidates
                .paths
                .iter()
                .map(|path| Self::refusal_decision(path, "recovery_point_not_found"))
                .collect();
            return Ok(Self::simulation_result(
                candidates,
                decisions,
                vec![format!(
                    "vss simulation recovery_point_id={} not found",
                    candidates.recovery_point_id
                )],
            ));
        };

        if !shadow.verified {
            let decisions = candidates
                .paths
                .iter()
                .map(|path| Self::refusal_decision(path, "recovery_point_unverified"))
                .collect();
            return Ok(Self::simulation_result(
                candidates,
                decisions,
                vec![format!(
                    "vss simulation recovery_point_id={} is unverified",
                    candidates.recovery_point_id
                )],
            ));
        }

        let decisions = candidates
            .paths
            .iter()
            .map(|path| Self::assess_candidate_path(shadow, path, candidates.max_depth))
            .collect();
        Ok(Self::simulation_result(
            candidates,
            decisions,
            vec![
                format!("vss simulation recovery_point_id={}", candidates.recovery_point_id),
                format!("vss simulation protected_root={}", shadow.protected_root),
            ],
        ))
    }

    fn restore(
        &self,
        candidates: &RollbackCandidateSet,
        approved_action_id: &str,
    ) -> anyhow::Result<RollbackEvidence> {
        // Kept as no-op/unavailable for this slice
        Ok(RollbackEvidence {
            status: "not_applicable".to_string(),
            decision_trace: vec!["vss provider: restore is unavailable in this slice".to_string()],
            evidence_controls: vec![],
            endpoint_id: String::new(),
            customer_id: None,
            policy_version: String::new(),
            requester_id: String::new(),
            approver_ids: vec![],
            simulation_id: String::new(),
            candidate_set_hash: candidates.candidate_set_hash.clone(),
            approved_action_id: approved_action_id.to_string(),
            provider: "vss".to_string(),
            recovery_point_id: candidates.recovery_point_id.clone(),
            recovery_point_created_at: String::new(),
            recovery_point_expires_at: None,
            recovery_point_verified: false,
            metadata_preserved: None,
            provider_refusal: Some("provider_unavailable: vss provider restore is unavailable in this slice".to_string()),
            restored_paths: vec![],
            failed_paths: vec![],
            skipped_paths: vec![],
            provider_version: "1.0.0".to_string(),
            os_platform: "windows".to_string(),
            privilege_context: "SeBackupPrivilege+SeRestorePrivilege".to_string(),
        })
    }

    fn probe(&self) -> ProbeResult {
        // 1. Service state check
        let (vss_running, service_diag) = Self::check_vss_service_running();

        // 2. Privilege boundary check
        let (has_backup, backup_diag) = Self::check_privilege(SE_BACKUP_NAME);
        let (has_restore, restore_diag) = Self::check_privilege(SE_RESTORE_NAME);
        let sufficient_privilege = has_backup && has_restore;

        let privilege_boundary = Some(format!(
            "requires SeBackupPrivilege ({}), SeRestorePrivilege ({})",
            if has_backup { "detected" } else { "missing" },
            if has_restore { "detected" } else { "missing" }
        ));

        // 3. Real Volume Discovery
        let volumes = Self::discover_volumes();
        let volume_capabilities: Vec<String> = volumes
            .iter()
            .map(|v| format!("vss:{}", v.mount_point.trim_end_matches('\\')))
            .collect();

        // Determine available filesystems based on discovered volumes
        let mut available_filesystems = Vec::new();
        for v in &volumes {
            let fs_lower = v.filesystem.to_lowercase();
            if !fs_lower.is_empty() && !available_filesystems.contains(&fs_lower) {
                available_filesystems.push(fs_lower);
            }
        }
        if available_filesystems.is_empty() {
            available_filesystems.push("ntfs".to_string());
        }

        // 4. Shadow Copy Enumeration via CIM/WMI
        let shadow_copy_res = Self::enumerate_shadow_copies(&volumes);
        let (shadow_copies, shadow_diag) = match shadow_copy_res {
            Ok(shadows) => (shadows, None),
            Err(err) => (Vec::new(), Some(err)),
        };
        let verified_shadow_count = shadow_copies.iter().filter(|shadow| shadow.verified).count();
        let recovery_point_count = verified_shadow_count;
        let shadow_volume_count = shadow_copies
            .iter()
            .filter(|shadow| shadow.verified)
            .map(|shadow| Self::normalize_windows_root(&shadow.protected_root))
            .collect::<BTreeSet<_>>()
            .len();

        // VSS service info text
        let snapshot_service_info = Some(format!(
            "VSS service is {}, detected {} eligible volume(s), {} verified shadow copy recovery point(s) across {} volume(s)",
            if vss_running { "running" } else { "stopped" },
            volumes.len(),
            verified_shadow_count,
            shadow_volume_count
        ));

        // Functional only when startup can interrogate VSS, volumes, and privilege state.
        let functional = vss_running && !volumes.is_empty() && sufficient_privilege;

        let diagnosis = if functional {
            format!(
                "VSS provider functional, active volumes: {:?}",
                volume_capabilities
            )
        } else {
            let mut issues = Vec::new();
            if !vss_running {
                issues.push(format!("VSS service stopped ({})", service_diag));
            }
            if !sufficient_privilege {
                issues.push(format!(
                    "insufficient privilege ({}, {})",
                    backup_diag, restore_diag
                ));
            }
            if volumes.is_empty() {
                issues.push("no eligible volumes discovered".to_string());
            }
            if let Some(err) = shadow_diag {
                issues.push(format!("shadow copy enumeration failed ({})", err));
            }
            format!("VSS provider not functional: {}", issues.join("; "))
        };

        ProbeResult {
            functional,
            diagnosis,
            recovery_point_count,
            available_filesystems,
            service_available: vss_running,
            sufficient_privilege,
            volume_capabilities,
            snapshot_service_info,
            privilege_boundary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vss_capabilities() {
        let provider = VssRollbackProvider::new();
        let caps = provider.capabilities();
        assert_eq!(caps.provider_name, "vss");
        assert_eq!(caps.provider_version, "1.0.0");
        assert!(caps.available);
        assert_eq!(caps.supported_os, vec!["windows".to_string()]);
    }

    #[test]
    fn test_vss_probe_runs_on_windows() {
        let provider = VssRollbackProvider::new();
        let probe = provider.probe();

        // The probe must complete without panicking and return realistic shapes.
        println!("Probe functional: {}", probe.functional);
        println!("Probe diagnosis: {}", probe.diagnosis);
        println!("Probe service_available: {}", probe.service_available);
        println!("Probe sufficient_privilege: {}", probe.sufficient_privilege);
        println!("Probe volume_capabilities: {:?}", probe.volume_capabilities);
        println!("Probe snapshot_service_info: {:?}", probe.snapshot_service_info);
        println!("Probe privilege_boundary: {:?}", probe.privilege_boundary);

        assert!(!probe.available_filesystems.is_empty());
    }

    #[test]
    fn parses_wmi_datetime_as_utc_rfc3339() {
        assert_eq!(
            VssRollbackProvider::parse_wmi_datetime("20260528143015.000000-420"),
            Some("2026-05-28T21:30:15+00:00".to_string())
        );
    }

    #[test]
    fn parses_shadow_copy_json_array_and_single_object() {
        let array = r#"[{"ID":"{rp-1}","DeviceObject":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1","InstallDate":"20260528143015.000000-420","VolumeName":"\\\\?\\Volume{abc}\\","State":12}]"#;
        let items = VssRollbackProvider::parse_shadow_copy_json(array).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_deref(), Some("{rp-1}"));

        let single = r#"{"ID":"{rp-2}","DeviceObject":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2","InstallDate":"20260528150000.000000-420","VolumeName":"C:\\","State":12}"#;
        let items = VssRollbackProvider::parse_shadow_copy_json(single).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_deref(), Some("{rp-2}"));
    }

    #[test]
    fn maps_shadow_copy_to_verified_recovery_point_shape() {
        let volumes = vec![VolumeInfo {
            volume_guid: "\\\\?\\Volume{abc}\\".to_string(),
            mount_point: "C:\\".to_string(),
            filesystem: "NTFS".to_string(),
        }];
        let shadow = CimShadowCopy {
            id: Some("{rp-1}".to_string()),
            device_object: Some("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1".to_string()),
            install_date: Some("20260528143015.000000-420".to_string()),
            volume_name: Some("\\\\?\\Volume{abc}\\".to_string()),
            state: Some(12),
        };

        let mapped =
            VssRollbackProvider::map_shadow_copy_with_verifier(shadow, &volumes, |_| true)
                .unwrap();
        let point = VssRollbackProvider::recovery_point_from_shadow(mapped);

        assert_eq!(point.id, "{rp-1}");
        assert_eq!(point.provider, "vss");
        assert_eq!(point.created_at, "2026-05-28T21:30:15+00:00");
        assert_eq!(point.protected_roots, vec!["C:\\".to_string()]);
        assert!(point.read_only);
        assert!(point.verified);
    }

    #[test]
    fn filters_verified_non_expired_scope_matching_points() {
        let scope = RollbackScope {
            incident_id: "test-inc".to_string(),
            detector_rule_id: "test-rule".to_string(),
            affected_paths: vec!["C:\\Users\\victim\\locked.txt".to_string()],
            observed_at: "now".to_string(),
        };
        let points = vec![
            RecoveryPoint {
                id: "match-new".to_string(),
                provider: "vss".to_string(),
                created_at: "2026-05-28T21:30:15+00:00".to_string(),
                expires_at: None,
                protected_roots: vec!["C:\\".to_string()],
                read_only: true,
                verified: true,
            },
            RecoveryPoint {
                id: "unverified".to_string(),
                provider: "vss".to_string(),
                created_at: "2026-05-28T22:30:15+00:00".to_string(),
                expires_at: None,
                protected_roots: vec!["C:\\".to_string()],
                read_only: true,
                verified: false,
            },
            RecoveryPoint {
                id: "wrong-root".to_string(),
                provider: "vss".to_string(),
                created_at: "2026-05-28T23:30:15+00:00".to_string(),
                expires_at: None,
                protected_roots: vec!["D:\\".to_string()],
                read_only: true,
                verified: true,
            },
            RecoveryPoint {
                created_at: "2026-05-28T20:30:15+00:00".to_string(),
                expires_at: Some("2000-01-01T00:00:00+00:00".to_string()),
                protected_roots: vec!["C:\\".to_string()],
                read_only: true,
                verified: true,
            },
        ];

        let filtered = VssRollbackProvider::filter_recovery_points(points, &scope);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "match-new");
    }

    #[test]
    fn maps_live_path_to_shadow_device_path() {
        let shadow = ShadowCopyInfo {
            id: "rp-1".to_string(),
            device_object: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1".to_string(),
            volume_name: "\\\\?\\Volume{abc}\\".to_string(),
            created_at: "2026-05-28T21:30:15+00:00".to_string(),
            protected_root: "C:\\".to_string(),
            state: Some(12),
            verified: true,
        };

        assert_eq!(
            VssRollbackProvider::shadow_path_for_live_path(
                &shadow,
                "C:\\Users\\victim\\locked.txt"
            ),
            Some(
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Users\\victim\\locked.txt"
                    .to_string()
            )
        );
        assert_eq!(
            VssRollbackProvider::shadow_path_for_live_path(&shadow, "D:\\other.txt"),
            None
        );
    }

    #[test]
    fn simulation_result_reports_only_non_restorable_paths_in_skipped_paths() {
        let scope = RollbackScope {
            incident_id: "test-inc".to_string(),
            detector_rule_id: "test-rule".to_string(),
            affected_paths: vec![],
            observed_at: "now".to_string(),
        };
        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-1".to_string(),
            paths: vec!["C:\\restore.txt".to_string(), "C:\\same.txt".to_string()],
            total_bytes_estimate: 100,
            max_depth: 8,
            candidate_set_hash: "hash".to_string(),
        };
        let sim = VssRollbackProvider::simulation_result(
            &candidates,
            vec![
                RollbackPathDecision {
                    path: "C:\\restore.txt".to_string(),
                    outcome: RollbackPathOutcome::Restored,
                    reason: "snapshot_differs_and_safe_to_restore".to_string(),
                    bytes_affected: 10,
                    hash_before: Some("snapshot".to_string()),
                    hash_after: Some("live".to_string()),
                    metadata_diff: None,
                },
                RollbackPathDecision {
                    path: "C:\\same.txt".to_string(),
                    outcome: RollbackPathOutcome::Skipped,
                    reason: "no_change_needed".to_string(),
                    bytes_affected: 0,
                    hash_before: Some("same".to_string()),
                    hash_after: Some("same".to_string()),
                    metadata_diff: None,
                },
            ],
            vec!["trace".to_string()],
        );

        assert_eq!(sim.candidate_count, 2);
        assert_eq!(sim.restorable_count, 1);
        assert_eq!(sim.skipped_paths.len(), 1);
        assert_eq!(sim.skipped_paths[0].reason, "no_change_needed");
        assert!(!sim.destructive);
    }

    #[test]
    fn test_vss_restore_method_remains_unavailable() {
        let provider = VssRollbackProvider::new();
        let scope = RollbackScope {
            incident_id: "test-inc".to_string(),
            detector_rule_id: "test-rule".to_string(),
            affected_paths: vec![],
            observed_at: "now".to_string(),
        };

        let candidates = RollbackCandidateSet {
            scope,
            recovery_point_id: "rp-1".to_string(),
            paths: vec!["C:\\test".to_string()],
            total_bytes_estimate: 100,
            max_depth: 8,
            candidate_set_hash: "hash".to_string(),
        };

        let evidence = provider.restore(&candidates, "action-1").unwrap();
        assert_eq!(evidence.status, "not_applicable");
    }

    #[test]
    fn test_vss_list_recovery_points_execution() {
        let provider = VssRollbackProvider::new();
        let scope = crate::edr::rollback::types::RollbackScope {
            incident_id: "test".to_string(),
            detector_rule_id: "test".to_string(),
            affected_paths: vec![],
            observed_at: "test".to_string(),
        };
        // Ensure that querying doesn't panic on a Windows box.
        // It might return an Ok with 0 points, or Ok with >0 points, or Err depending on WMI health,
        // but it must not crash the test suite.
        let result = provider.list_recovery_points(&scope);
        println!("list_recovery_points result: {:?}", result.is_ok());
    }
}
