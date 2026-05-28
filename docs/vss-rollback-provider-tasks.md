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

## Gating

- VSS code remains under `#[cfg(windows)]`.
- Non-Windows builds continue to use `NoopRollbackProvider`.
- Restore refuses missing/unverified recovery points and skips paths that simulation would not mark restorable.
