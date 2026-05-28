# VSS Rollback Provider Tasks

## Landed

- Slice 1: Windows-gated VSS probe/readiness with service, privilege, and volume discovery.
- Slice 2: Real `list_recovery_points()` through `Win32_ShadowCopy` CIM/WMI enumeration, verified-device filtering, non-expiry filtering, protected-root matching, and readiness recovery-point counts.

## Next

- Implement read-only `simulate_restore()` from the VSS shadow device path.
- Implement approved `restore()` using `CopyFileExW` plus metadata preservation evidence.
- Add Windows integration tests with pre-created VSS shadows and sample encrypted/deleted files.

## Gating

- VSS code remains under `#[cfg(windows)]`.
- Non-Windows builds continue to use `NoopRollbackProvider`.
- Restore paths remain unavailable until simulation and copy-out safety checks land.
