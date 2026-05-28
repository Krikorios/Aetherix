# VSS Rollback Provider Tasks

## Landed

- Slice 1: Windows-gated VSS probe/readiness with service, privilege, and volume discovery.
- Slice 2: Real `list_recovery_points()` through `Win32_ShadowCopy` CIM/WMI enumeration, verified-device filtering, non-expiry filtering, protected-root matching, and readiness recovery-point counts.
- Slice 3: Non-mutating `simulate_restore()` decision support from the VSS shadow device path, including snapshot-path existence checks, hash comparison, safe-overwrite refusal, and structured enumeration diagnostics.

## Next

- Harden approved `restore()` with Windows-native `CopyFileExW` plus full metadata preservation evidence.
- Add Windows integration tests with pre-created VSS shadows and sample encrypted/deleted files.
- Coordinate a richer simulation schema if the backend/console needs explicit restorable-path details instead of only `restorable_count` plus skipped/refused path decisions.

## In Progress

- Slice 4: Initial approved restore copy-out using the same verified VSS shadow path mapping and per-path safety decisions as simulation. This first restore slice uses `std::fs::copy` and post-copy SHA-256 verification; ACL/ADS/timestamp preservation remains for the Windows-native `CopyFileExW` hardening pass.
- Restore hardening now emits structured `restore` and `restore_refused` diagnostics, records simulation-safety revalidation in `decision_trace`, and returns explicit skipped-path refusals for missing/unverified recovery points or enumeration failures.

## Metadata Preservation Slice

- Preserve file content with Windows-native `CopyFileExW` before metadata handling.
- Preserve owner/group and DACL/SACL with `GetNamedSecurityInfoW` and `SetNamedSecurityInfoW`.
- Preserve creation/write/access times with `GetFileTime` and `SetFileTime`.
- Preserve file attributes with `GetFileAttributesW` and `SetFileAttributesW`.
- Preserve alternate data streams with `BackupRead` and `BackupWrite`.
- Keep metadata-only failures in `restored_paths[].metadata_diff`; reserve `failed_paths` for content-copy and integrity failures.

## Gating

- VSS code remains under `#[cfg(windows)]`.
- Non-Windows builds continue to use `NoopRollbackProvider`.
- Restore refuses missing/unverified recovery points and skips paths that simulation would not mark restorable.
