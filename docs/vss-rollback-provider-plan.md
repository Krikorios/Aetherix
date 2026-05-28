# VSS Rollback Provider — Implementation Plan

**Status:** Planning — review before implementation.  
**Target:** First real OS provider for the `RollbackProvider` trait.  
**Rationale:** Windows VSS is the most common ransomware rollback scenario in enterprise deployments. A working VSS provider unblocks the full rollback evidence chain on real Windows endpoints.

---

## 1. Module Structure

A single new file, conditionally compiled:

```
agent/src/edr/rollback/
├── mod.rs        # + cfg-gated re-export
├── vss.rs        # NEW (184 lines planned)
├── provider.rs   # No changes
├── types.rs      # No changes
├── intent.rs     # No changes
├── evidence.rs   # No changes
└── persistence.rs# No changes
```

### mod.rs additions

```rust
// At top of file:
#[cfg(windows)]
pub mod vss;
#[cfg(windows)]
pub use vss::VssRollbackProvider;
```

---

## 2. VssRollbackProvider Struct

```rust
/// Windows VSS-based rollback provider.
///
/// Uses WMI (Win32_ShadowCopy) to enumerate shadow copies and direct
/// device-path access for read-only file copy-out. Does NOT mutate
/// shadow copy state — all reads are from the snapshot device view.
///
/// ## Safety invariants
/// - Never writes to the shadow copy device path.
/// - Never deletes a shadow copy (expiry is OS-managed).
/// - Never falls back to an unverified recovery point.
/// - Requires SeBackupPrivilege + SeRestorePrivilege for full operation.
#[cfg(windows)]
pub struct VssRollbackProvider {
    /// State cached from the last successful probe()
    state: Option<ProviderState>,
}

#[cfg(windows)]
struct ProviderState {
    volumes: Vec<VolumeInfo>,
    recovery_points: Vec<ShadowCopyInfo>,
    has_backup_privilege: bool,
    has_restore_privilege: bool,
    vss_service_running: bool,
    writer_status: String,
}

#[cfg(windows)]
struct VolumeInfo {
    volume_guid: String,       // "\\\\?\\Volume{...}"
    mount_point: String,       // "C:\\"
    filesystem: String,        // "NTFS"
    has_shadow_copies: bool,
}

#[cfg(windows)]
struct ShadowCopyInfo {
    id: String,                // Snapshot set ID (from WMI)
    volume_guid: String,
    device_path: String,       // "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{N}"
    created_at: String,        // ISO-8601
    is_verified: bool,         // Path exists on disk
}
```

All supporting types are `pub(crate)` or private to `vss.rs`. No new public types are needed.

---

## 3. Win32 / COM API Surface

### 3.1 Required API Categories

| Category | APIs | Purpose | Used In |
|----------|------|---------|---------|
| COM | `CoInitializeEx(COINIT_APARTMENTTHREADED)`, `CoUninitialize` | COM apartment for WMI | `probe()`, `list_recovery_points()` |
| WMI | `IWbemLocator`, `IWbemServices`, `IWbemClassObject`, `IEnumWbemClassObject` | Query Win32_ShadowCopy | `probe()`, `list_recovery_points()` |
| Volume enum | `FindFirstVolumeW`, `FindNextVolumeW`, `FindVolumeClose` | List all system volumes | `probe()` |
| Volume info | `GetVolumePathNamesForVolumeNameW`, `GetVolumeInformationW` | Map GUID→mount, detect FS type | `probe()` |
| Privilege | `OpenProcessToken`, `GetTokenInformation`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges` | Check/enable SeBackup + SeRestore | `probe()` |
| File copy | `CopyFileExW` (`COPY_FILE_COPY_SYMLINK`, `COPY_FILE_OPEN_SOURCE_FOR_WRITE`) | Copy from shadow device path | `restore()` |
| Metadata | `SetFileTime`, `SetFileAttributesW` | Preserve timestamps + attributes | `restore()` |
| Security | `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW` (DACL/SACL/owner) | Preserve ACLs | `restore()` |
| ADS | `BackupRead` / `BackupWrite` stream API | Preserve alternate data streams | `restore()` |
| Service | `OpenSCManagerW`, `OpenServiceW("VSS")`, `QueryServiceStatusEx` | Check VSS service state | `probe()` |

### 3.2 Rust Dependency

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_System_Services",
    "Win32_System_Com",
    "Win32_System_Wmi",
    "Win32_Foundation",
    "Win32_System_Threading",
    "Win32_Security_Authorization",
]} 
```

Use the `windows` crate (not `windows-sys`) for:
- Idiomatic Rust COM bindings (`Interface`, `implement`, `ComObject`)
- Safe wrappers around Win32 handles
- The `WMI` convenience layer (`WmiConnection`, `WmiClass`, etc.)
- The `HSTRING` / `BSTR` string handling

This is a **Windows-only build dependency** — it does not affect non-Windows compilation or binary size.

---

## 4. Method Implementations

### 4.1 `probe()` — Startup Health Check

```
1. CoInitializeEx(COINIT_APARTMENTTHREADED)
2. Check VSS service state via OpenSCManager + QueryServiceStatusEx
3. Check + attempt to enable SeBackupPrivilege and SeRestorePrivilege
4. Enumerate volumes via FindFirstVolume / FindNextVolume
   For each volume:
   a. GetVolumePathNamesForVolumeNameW → mount point
   b. GetVolumeInformationW → filesystem type
   c. Record "vss:{mount_point}" in volume_capabilities
5. Query Win32_ShadowCopy via WMI → enumerate existing shadow copies
   For each shadow:
   a. Extract: VolumeDeviceID, InstallDate, ID, DeviceObject
   b. Verify device path exists via CreateFile(READ_ONLY)
   c. Record as recovery point
6. CoUninitialize
7. Populate ProbeResult:
   - functional: VSS running AND at least one volume with shadow copies
     AND both privileges available
   - service_available: VSS service state
   - sufficient_privilege: both privileges enabled
   - volume_capabilities: ["vss:C:", "vss:D:", ...]
   - snapshot_service_info: "VSS v{version}, Writers: {ok}/{total} ready"
   - privilege_boundary: "SeBackupPrivilege={enabled/missing}, SeRestorePrivilege={...}"
   - recovery_point_count: total verified shadow copies
```

**Key detail — privilege check:**

```rust
fn check_privilege(name: &str) -> (bool, String) {
    // 1. OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
    // 2. LookupPrivilegeValueW(NULL, name)
    // 3. GetTokenInformation(TokenPrivileges) → check SE_PRIVILEGE_ENABLED
    // 4. If not enabled, attempt AdjustTokenPrivileges(SE_PRIVILEGE_ENABLED)
    // 5. Return (enabled, detail_string)
}
```

### 4.2 `capabilities()` — Static Metadata

```rust
RollbackCapabilities {
    provider_name: "vss".to_string(),
    provider_version: env!("CARGO_PKG_VERSION").to_string(), // or a constant
    available: self.state.is_some(),  // true if probe() succeeded
    supported_os: vec!["windows".to_string()],
    supported_filesystems: vec!["ntfs".to_string(), "refs".to_string()],
    privilege_context: "SeBackupPrivilege+SeRestorePrivilege".to_string(),
}
```

### 4.3 `list_recovery_points(scope)` — Filter by Volume

```
1. Query `Win32_ShadowCopy` through the Windows-only CIM/WMI path
2. Map each shadow to `RecoveryPoint`:
   - ID -> `id`
   - InstallDate -> UTC RFC3339 `created_at`
   - VolumeName -> discovered mount point in `protected_roots`
   - DeviceObject + State -> `verified`
3. If scope.affected_paths is empty, return all verified non-expired recovery points
2. For each path in scope.affected_paths:
   a. Resolve to a volume mount point (e.g., "C:\", "D:\")
   b. Filter recovery points by matching volume
3. For each matching recovery point:
   a. Verify device path still exists (CreateFile with 0 access)
   b. Check created_at is BEFORE scope.observed_at
   c. Mark verified=false if device path missing
4. Return Vec<RecoveryPoint> sorted by created_at descending
```

**Slice status:** implemented for Windows-gated discovery and filtering. Restore and simulate remain stubbed pending the copy-out and metadata-preservation slice.

RecoveryPoint mapping:
```rust
RecoveryPoint {
    id: shadow.id.clone(),
    provider: "vss".to_string(),
    created_at: shadow.created_at.clone(),
    expires_at: None,  // VSS shadows do not have a hard expiry; Windows
                       // may auto-delete old shadows based on storage limits
    protected_roots: vec![format!("{}:\\", &volume_mount[..1])],
                        // e.g., "C:\", "D:\"
    read_only: true,    // VSS device path is always read-only
    verified: shadow.is_verified,
}
```

### 4.4 `simulate_restore(candidates)` — Preview Without Mutation

```
1. Map candidates.recovery_point_id → ShadowCopyInfo (fail if not found)
2. Build device path prefix:
   shadow_device = shadow_info.device_path  // e.g., \\?\GLOBALROOT\Device\...
3. For each candidate path:
   a. Convert absolute path (e.g., "C:\Users\...") to shadow device path:
      shadow_path = shadow_device + relative_from_volume_root
   b. Check shadow_path exists: CreateFile(READ_ONLY, FILE_FLAG_BACKUP_SEMANTICS)
   c. Check live path exists
   d. Decision logic:

      | Shadow file? | Live file? | Outcome | Reason |
      |--------------|------------|---------|--------|
      | Yes          | No         | Restored | file_deleted_by_ransomware |
      | Yes          | Yes        | check mtime/hash |
      |   — same hash   |            | Skipped | no_change_needed |
      |   — live newer  |            | RefusedOutOfScope | unsafe_overwrite |
      |   — same mtime  |            | Restored | same_mtime_needs_restore |
      | No           | —          | RefusedOutOfScope | not_found_in_point |

   e. For each file that exists in shadow, compute SHA-256 hash_before
      (stream through sha2::Sha256 from the shadow copy)
4. Assemble RollbackSimulation
```

**Important:** The `simulate_restore` must NOT write to the live filesystem. All reads are from the shadow device path. Hash computation streams from the shadow copy.

### 4.5 `restore(candidates, approved_action_id)` — File Copy-Out

```
1. Re-verify recovery point existence (defence-in-depth — it may have been
   deleted between simulation and execution)
2. For each candidate path:
   a. Compute hash_before from shadow copy (SHA-256)
   b. CopyFileExW(shadow_path, live_path, COPY_FILE_COPY_SYMLINK |
      COPY_FILE_OPEN_SOURCE_FOR_WRITE | COPY_FILE_FAIL_IF_EXISTS?)
      - Use COPY_FILE_FAIL_IF_EXISTS? NO — we want to overwrite the
        ransomware-encrypted file with the shadow copy version.
        But: if simulate_restore flagged `unsafe_overwrite`, the path
        was already excluded from the candidate set. If it somehow
        arrives here, refuse with RefusedOutOfScope.
      - Use COPY_FILE_OPEN_SOURCE_FOR_WRITE — allows reading the shadow
        device even though it is technically read-only.
   c. Compute hash_after from restored file
   d. Preserve metadata:
      - Ownership: GetNamedSecurityInfoW(SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION |
        GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)
        from shadow path → SetNamedSecurityInfoW on live path
      - Timestamps: GetFileTime from shadow → SetFileTime on live
      - Attributes: GetFileAttributesW from shadow → SetFileAttributesW on live
      - Alternate data streams: BackupRead→BackupWrite (stream enumeration + copy)
      Record metadata_diff if any preservation step fails
   e. If CopyFileExW fails, record in failed_paths with error reason
3. Assemble RollbackEvidence
```

**Metadata preservation strategy — recommended priority:**

| Priority | Metadata | API | If Unavailable |
|----------|----------|-----|----------------|
| P0 | File content (data stream) | `CopyFileExW` | Path is `failed` |
| P1 | Ownership (owner + group SID) | `GetNamedSecurityInfoW` → `SetNamedSecurityInfoW` | Log metadata_diff, continue |
| P2 | DACL (discretionary ACL) | `GetNamedSecurityInfoW` → `SetNamedSecurityInfoW` | Log metadata_diff, continue |
| P3 | Timestamps (create/write/change) | `GetFileTime` → `SetFileTime` | Log metadata_diff, continue |
| P4 | File attributes | `GetFileAttributesW` → `SetFileAttributesW` | Log metadata_diff, continue |
| P5 | SACL (system ACL) | `GetNamedSecurityInfoW` → `SetNamedSecurityInfoW` | Log metadata_diff, continue |
| P6 | Alternate data streams | `BackupRead` → `BackupWrite` | Log metadata_diff, continue |

Each P1–P6 failure records a string in `metadata_diff` (e.g., `"DACL not preserved: access_denied"`) but does NOT fail the overall path restore. Only P0 failure causes a `failed` path outcome.

**RollbackEvidence shape during and after metadata preservation:**

- `metadata_preserved=false` in the current copy-out slice because ACLs, timestamps, attributes, and alternate data streams are not fully preserved yet.
- `metadata_preserved=true` only after every restored path preserves content plus owner/group, DACL/SACL, timestamps, attributes, and alternate data streams.
- `restored_paths` contains only paths copied from the VSS shadow and verified by post-copy hash comparison. Metadata-only preservation failures stay in `restored_paths` and append `metadata_diff` entries such as `dacl_not_preserved:<error>` or `ads_not_preserved:<stream>:<error>`.
- `failed_paths` contains content-copy and integrity failures only: parent creation failure, `CopyFileExW`/copy failure, post-copy hash failure, or post-copy hash mismatch.
- `skipped_paths` is populated from the restore-time safety re-validation, not from stale approval state. It contains unchanged files, unsafe overwrite refusals, missing snapshot paths, protected-root refusals, depth refusals, and recovery-point refusal paths.
- `provider_refusal` is set only when restore refuses before any copy attempt, such as recovery point enumeration failure, missing recovery point, or unverified recovery point. Mixed per-path failures use `failed_paths` with `provider_refusal=null`.
- `decision_trace` always records that simulation safety was revalidated before copy and includes `approved_action_id`, `recovery_point_id`, `candidate_set_hash`, and per-path aggregate counts.

---

## 5. Probe / Readiness Differences vs. Simulation

| Field | SimulationRollbackProvider | VssRollbackProvider (real) |
|-------|---------------------------|---------------------------|
| `functional` | Same as `available` config | `true` only if VSS service running + eligible volumes + privileges granted |
| `diagnosis` | Static description | Live: "VSS v1.6, Writers: 3/5 ready, 2 volumes with shadows" or "VSS service not running (state: STOPPED)" |
| `recovery_point_count` | Count of pre-configured points | Count of WMI-enumerated, existence-verified shadow copies |
| `available_filesystems` | `["apfs", "ntfs", "ext4"]` (stub) | `["ntfs"]` or `["ntfs", "refs"]` |
| `service_available` | Same as `available` config | `OpenSCManager` → `QueryServiceStatusEx("VSS")` → `SERVICE_RUNNING` |
| `sufficient_privilege` | Same as `available` config | `OpenProcessToken` → `GetTokenInformation` → checks `SE_BACKUP_NAME` + `SE_RESTORE_NAME` with `SE_PRIVILEGE_ENABLED` |
| `volume_capabilities` | `["simulation:/home", ...]` | `["vss:C:", "vss:D:"]` — real volume mount points |
| `snapshot_service_info` | "simulation provider: N recovery point(s)" | "VSS v1.6, Writers: 3/5 ready (2 stalled: SqlWriter, FsWriter)" |
| `privilege_boundary` | `"simulated: user"` | `"requires SeBackupPrivilege (detected), SeRestorePrivilege (detected)"` or `"missing SeBackupPrivilege (agent runs as LOCAL SYSTEM)"` |

---

## 6. Interface Stability Assessment

**Does the existing `RollbackProvider` trait need changes?**  
**No.** The current trait with its 5 methods (`capabilities`, `list_recovery_points`, `simulate_restore`, `restore`, `probe`) maps cleanly to VSS operations:

| Trait Method | VSS Implementation Target |
|-------------|--------------------------|
| `capabilities()` | Static metadata about VSS availability |
| `probe()` | VSS service + privilege + shadow enumeration |
| `list_recovery_points(scope)` | WMI Win32_ShadowCopy query filtered by volume |
| `simulate_restore(candidates)` | Shadow device path → file existence + hash check |
| `restore(candidates, action_id)` | CopyFileExW from shadow device + metadata preservation |

**No new public types are required.** The `RollbackEvidence`, `RollbackSimulation`, `RecoveryPoint`, and `ProbeResult` types already contain all fields a VSS provider needs to report (provider name, version, privilege context, volume capabilities, recovery point metadata, per-path outcomes).

**One minor addition recommended** (not strictly required but helpful for the VSS provider to report writer-level diagnostics):

Add an optional `snapshot_service_info` field **already exists** in `ProbeResult` (line 215 of types.rs). The VSS provider will populate it with detailed writer status. No type change needed.

---

## 7. Error Handling Strategy

### 7.1 COM Initialization Failures

`CoInitializeEx` can fail if COM is already initialized in a different concurrency mode. Handle by:
- Attempt `COINIT_APARTMENTTHREADED` first
- On `RPC_E_CHANGED_MODE`, retry with `COINIT_MULTITHREADED`
- If both fail, probe returns `functional: false, diagnosis: "COM init failed: ..."`

### 7.2 WMI Query Failures

WMI queries (`ExecQuery("SELECT * FROM Win32_ShadowCopy")`) can fail if:
- WMI service is disabled → `functional: false`
- No shadow copies exist → `recovery_point_count: 0`
- Access denied (WMI permissions) → `functional: false, diagnosis: "WMI access denied"`
- Query timeout → retry once, then return empty or with partial results

All failures are caught and mapped to `ProbeResult` or `RollbackEvidence` with appropriate `provider_refusal`.

### 7.3 Privilege Elevation Failures

If the agent does not hold `SeBackupPrivilege`:
- `probe()` reports `sufficient_privilege: false`
- `functional` is set to `false`
- The VSS provider is not available (files can still be read but metadata cannot be preserved)
- The control plane sees `provider_available: false` in `RollbackReadiness`

### 7.4 CopyFileExW Failures

| Error | Handling |
|-------|----------|
| `ERROR_PATH_NOT_FOUND` | File deleted between simulation and restore → `RefusedOutOfScope` (not_found_in_point) |
| `ERROR_ACCESS_DENIED` | Shadow device inaccessible → mark path as `failed` with `provider_refusal` |
| `ERROR_SHARING_VIOLATION` | Locked by another process → retry once after 1s, then `failed` |
| `ERROR_DISK_FULL` | No space for restored file → `failed`, mark evidence as partial success |
| `ERROR_FILE_EXISTS` | Should not happen (we use COPY_FILE_FAIL_IF_EXISTS=false) |

---

## 8. main.rs Integration (Provider Selection)

The provider selection at startup changes from a hardcoded NoopRollbackProvider to a platform-aware factory:

```rust
use aetherix_agent::edr::rollback::{
    NoopRollbackProvider, RollbackProvider,
    #[cfg(windows)] VssRollbackProvider,
};

let rollback_provider: Arc<dyn RollbackProvider + Send + Sync> = {
    #[cfg(windows)]
    {
        let vss = VssRollbackProvider::new();
        let probe = vss.probe();
        if probe.functional {
            println!("aetherix-agent: VSS rollback provider ready — {} volume(s), {} recovery point(s)",
                probe.volume_capabilities.len(), probe.recovery_point_count);
            Arc::new(vss)
        } else {
            println!("aetherix-agent: VSS rollback provider not functional ({}), falling back to noop",
                probe.diagnosis);
            Arc::new(NoopRollbackProvider) as Arc<dyn RollbackProvider + Send + Sync>
        }
    }
    #[cfg(not(windows))]
    {
        Arc::new(NoopRollbackProvider) as Arc<dyn RollbackProvider + Send + Sync>
    }
};
```

---

## 9. Testing Strategy

### 9.1 Unit Tests (Windows-host only)

Run these via `#[cfg(windows)] #[cfg(test)]`:

| Test | What it validates |
|------|-------------------|
| `test_vss_probe_runs_on_windows` | Probe completes and reports realistic VSS shape |
| `parses_wmi_datetime_as_utc_rfc3339` | WMI datetime conversion for shadow `InstallDate` |
| `parses_shadow_copy_json_array_and_single_object` | CIM JSON output handles one or many shadows |
| `maps_shadow_copy_to_verified_recovery_point_shape` | `Win32_ShadowCopy` fields map into `RecoveryPoint` |
| `filters_verified_non_expired_scope_matching_points` | Verified, non-expired, protected-root filtering |
| `synthetic_shadow_like_restore_copies_content_and_verifies_hash` | Synthetic CI guard for copy-out, hash verification, and evidence shape using separate temp directories. This is **not** proof of Win32_ShadowCopy device access. |
| `real_vss_shadow_copy_restore_end_to_end` | Ignored by default. On a Windows admin/VSS host, creates a real VSS shadow, modifies a live file, runs `simulate_restore()` and `restore()`, verifies content plus `hash_before`/`hash_after`, and attempts shadow cleanup. |

### 9.2 Integration Tests (requires Windows with VSS)

Manual or CI-gated:
- Create a VSS shadow copy via `vssadmin create shadow /for=C:`
- Run `simulate_restore` → verify `RollbackSimulation` with real file hash
- Run `restore` → verify `RollbackEvidence` with restored path, hash_before/after, metadata preserved

Concrete agent test command on a Windows machine with admin privileges and VSS enabled:

```powershell
cd agent
$env:AETHERIX_RUN_REAL_VSS_TEST = "1"
# Optional: choose a disposable test root on C:
$env:AETHERIX_REAL_VSS_TEST_ROOT = "C:\AetherixVssRollbackTest"
cargo test real_vss_shadow_copy_restore_end_to_end -- --ignored --nocapture
```

The test is intentionally ignored by default because it is destructive to a
disposable live test file and requires `vssadmin` privileges. It writes only to
the live test file under `AETHERIX_REAL_VSS_TEST_ROOT`; it never writes to or
deletes snapshot device contents. Snapshot deletion is limited to a best-effort
cleanup of the test-created shadow via `vssadmin delete shadows /Shadow={id}`.

Validation status note: macOS/Linux CI can only run the synthetic copy-out test.
Real acceptance requires the ignored Windows test above to pass on a Windows
runner/VM with VSS. Do not treat the synthetic test as evidence that
`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{N}` access works.

### 9.3 Cross-Platform Compilation Assurance

The `#[cfg(windows)]` attribute on `mod vss` ensures the module:
- Does not compile on macOS/Linux (avoids unresolved Win32 imports)
- Does not increase binary size on non-Windows
- All Windows-specific dependencies in `[target.'cfg(windows)'.dependencies]`

---

## 10. Open Questions

1. **Shadow copy identification**: Does `ID` from `Win32_ShadowCopy` uniquely identify a specific shadow copy for restore purposes, or should we use `DeviceObject` path instead?  
   *Resolution: Use `DeviceObject` for device path access, use `ID` for indexing/selection.*

2. **Error semantics for locked files**: Should `CopyFileExW` with `ERROR_SHARING_VIOLATION` auto-retry, or fail immediately and report in `failed_paths`?  
   *Proposal: Retry once (1s delay), then fail.*

3. **Large file handling**: Does `CopyFileExW` with `COPY_FILE_RESTARTABLE` provide meaningful progress for very large files (>1 GB)?  
   *Proposal: Not in v1 — treat as one atomic copy and rely on heartbeat timeout.*

4. **Alternate data stream complexity**: `BackupRead`/`BackupWrite` requires stream enumeration. For v1, ADS preservation can be logged as metadata_diff without fully implementing the stream copy. This is a known gap.

5. **ReFS vs NTFS**: ReFS supports block-level snapshots differently from NTFS. The WMI query (`Win32_ShadowCopy`) only returns VSS-created shadow copies, not ReFS block snapshots.  
   *Resolution: For v1, only enumerate VSS shadow copies. ReFS block snapshots are a future enhancement.*

---

## 11. Implementation Sequence

1. Create `vss.rs` with struct + `new()` + `capabilities()` + `probe()` (complete)
2. Add Windows dependency to `Cargo.toml` (complete)
3. Wire `VssRollbackProvider::new()` in `main.rs` with noop fallback (complete)
4. Implement `list_recovery_points()` via WMI/CIM (complete)
5. Implement `simulate_restore()` (read-only, hash comparison)
6. Implement `restore()` (CopyFileExW + metadata preservation)
7. Unit tests for each method
8. Integration test on a Windows VM with `vssadmin` pre-created shadow copies

Steps 1–4 are landed. Steps 5–6 add the full dispatch path.

---

## 12. Changes Summary

| File | Change Type | Lines |
|------|-------------|-------|
| `Cargo.toml` | Add `[target.'cfg(windows)'.dependencies.windows]` | +15 |
| `agent/src/edr/rollback/mod.rs` | Add `#[cfg(windows)] pub mod vss;` + pub use | +4 |
| `agent/src/edr/rollback/vss.rs` | **New file** — full VSS provider | ~184 |
| `agent/src/main.rs` | Platform-aware provider selection | +20 |
| `docs/native-security-gap-review.md` | Update Remaining Gaps | +2 |
