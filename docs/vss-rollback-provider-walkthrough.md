# VSS Recovery Point Walkthrough

## What Runs Today

1. The Windows agent selects `VssRollbackProvider` only when the VSS probe is functional.
2. `probe()` checks VSS service state, privileges, eligible volumes, and verified shadow-copy count.
3. `list_recovery_points(scope)` queries `Win32_ShadowCopy`, maps shadows into `RecoveryPoint[]`, filters unverified/expired points, and limits results to matching protected roots.

## Manual Windows Check

1. Create a shadow copy on a test host: `vssadmin create shadow /for=C:`.
2. Run the Windows agent tests or startup probe.
3. Confirm readiness reports `provider_name=vss`, a non-zero `recovery_point_count`, and snapshot info containing verified shadow-copy counts.

## Not Yet Enabled

- `simulate_restore()` still returns a non-destructive unavailable result.
- `restore()` still returns `not_applicable` with provider refusal text.
- APFS and Btrfs/LVM providers remain future provider work.
