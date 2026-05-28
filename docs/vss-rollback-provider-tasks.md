# VSS Rollback Provider Tasks

## Landed

- Slice 1: Windows-gated VSS probe/readiness with service, privilege, and volume discovery.
- Slice 2: Real `list_recovery_points()` through `Win32_ShadowCopy` CIM/WMI enumeration, verified-device filtering, non-expiry filtering, protected-root matching, and readiness recovery-point counts.
- Slice 3: Non-mutating `simulate_restore()` decision support from the VSS shadow device path, including snapshot-path existence checks, hash comparison, safe-overwrite refusal, and structured enumeration diagnostics.

## Next

- Implement approved `restore()` using `CopyFileExW` plus metadata preservation evidence.
- Add Windows integration tests with pre-created VSS shadows and sample encrypted/deleted files.
- Coordinate a richer simulation schema if the backend/console needs explicit restorable-path details instead of only `restorable_count` plus skipped/refused path decisions.

## Gating

- VSS code remains under `#[cfg(windows)]`.
- Non-Windows builds continue to use `NoopRollbackProvider`.
- Restore paths remain unavailable until copy-out safety checks land.
