# VSS Recovery Point Walkthrough

## What Runs Today

1. The Windows agent selects `VssRollbackProvider` only when the VSS probe is functional.
2. `probe()` checks VSS service state, privileges, eligible volumes, and verified shadow-copy count.
3. `list_recovery_points(scope)` queries `Win32_ShadowCopy`, maps shadows into `RecoveryPoint[]`, filters unverified/expired points, and limits results to matching protected roots.
4. `simulate_restore(candidates)` remains non-mutating and reads from the VSS shadow device path only to decide whether each candidate is restorable, unchanged, missing from the snapshot, unsafe to overwrite, or integrity-blocked.
5. `restore(candidates, approved_action_id)` starts the approved copy-out path for files that simulation marks restorable, copies from the VSS shadow device path, and verifies the copied file hash before reporting success.

## Manual Windows Check

1. Create a shadow copy on a test host: `vssadmin create shadow /for=C:`.
2. Run the Windows agent tests or startup probe.
3. Confirm readiness reports `provider_name=vss`, a non-zero `recovery_point_count`, and snapshot info containing verified shadow-copy counts.
4. Trigger `list_recovery_points()` and check stderr for JSON lines with `provider="vss"` and `event="list_recovery_points"` or `event="list_recovery_points_failed"`.

## Simulation Output Shape

`simulate_restore()` returns the existing `RollbackSimulation` shape:

- `simulation_id`: generated UUID for this simulation.
- `candidate_set_hash`: copied from the approved candidate set.
- `candidate_count`: number of requested paths.
- `restorable_count`: number of paths that could be restored non-mutatingly from the selected VSS recovery point.
- `skipped_paths`: per-path decisions for non-restorable paths only, using `RollbackPathDecision`.
- `destructive`: always `false` for this simulation slice.
- `valid_until`: one hour from simulation time.
- `decision_trace`: includes the selected `recovery_point_id`, protected root, and aggregate counts.

`RollbackPathDecision` entries use existing fields only:

- `path`: live path assessed.
- `outcome`: `skipped`, `failed_integrity`, or `refused_out_of_scope` for entries in `skipped_paths`.
- `reason`: one of `no_change_needed`, `not_found_in_point:*`, `unsafe_overwrite:*`, `snapshot_hash_failed:*`, `live_hash_failed:*`, `recovery_point_not_found`, `recovery_point_unverified`, or protected-root/depth refusal text.
- `bytes_affected`: snapshot byte size when known; otherwise `0`.
- `hash_before`: SHA-256 of the snapshot copy when readable.
- `hash_after`: SHA-256 of the live file when readable.
- `metadata_diff`: optional strings such as `live_missing`, `live_modified_after_recovery_point`, or `size:<live>-<snapshot>`.

## Restore Evidence Shape

`restore()` returns the existing `RollbackEvidence` shape:

- `status`: `executed`, `failed`, or `not_applicable`.
- `decision_trace`: includes restored/failed/skipped counts, `approved_action_id`, `recovery_point_id`, and protected root.
- `candidate_set_hash`: copied from the approved candidate set.
- `approved_action_id`: copied from the remote action.
- `provider`: `vss`.
- `recovery_point_id`: selected VSS shadow copy ID.
- `recovery_point_created_at`: VSS `InstallDate` normalized to RFC3339.
- `recovery_point_expires_at`: `null` for VSS.
- `recovery_point_verified`: `true` only for verified shadow copies.
- `metadata_preserved`: currently `false` because ACL/ADS/timestamp preservation is not complete in this slice.
- `provider_refusal`: set for missing/unverified recovery points or enumeration failure.
- `restored_paths`: per-path `RollbackPathDecision` with `outcome=restored`, `reason=restored_from_vss_shadow`, `hash_before` as the snapshot SHA-256, `hash_after` as the post-copy live SHA-256, and `metadata_diff` including `copied_from_vss_shadow`.
- `failed_paths`: per-path integrity or copy failures, including `copy_from_shadow_failed`, `post_restore_hash_failed`, or `post_restore_hash_mismatch`.
- `skipped_paths`: unchanged files, unsafe overwrites, missing snapshot paths, protected-root refusals, and depth refusals.
- `provider_version`: `1.0.0`.
- `os_platform`: `windows`.
- `privilege_context`: `SeBackupPrivilege+SeRestorePrivilege`.

Restore diagnostics are emitted as JSON lines on stderr with `provider="vss"`, `event="restore"`, `approved_action_id`, `recovery_point_id`, and restored/failed/skipped counts.

## Not Yet Enabled

- Full Windows-native metadata preservation through `CopyFileExW`, ACL, alternate data stream, and timestamp handling.
- APFS and Btrfs/LVM providers remain future provider work.
