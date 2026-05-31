# Sprint 2 Brief — Agent A (Endpoint Agent)  [re-baselined 2026-05-31]

You own ONLY `agent/` (Rust). Do not edit `apps/` or `docs/`. Do not run git.
**#1 rule: no overclaiming** — code + a passing test, or it isn't done.

Build: `cargo build --manifest-path agent/Cargo.toml`
Test: `cargo test --manifest-path agent/Cargo.toml` (run first for baseline).
Verified baseline: `--lib` = 134 pass; integration suites pass; **but** there is a
parallelism flake in `edr::rollback::persistence` (passes single-threaded).

## Tasks (priority order)
1. **Harden process kill (confirmed termination).** In `src/edr/response.rs`, the
   Unix `kill_process` (~:664) currently returns success the instant
   `kill(pid, SIGTERM)` returns 0, **without verifying the process died**. Fix it to:
   poll for actual exit (handle Linux zombie `Z`/dead `X` via `/proc/<pid>/stat`),
   escalate SIGTERM→SIGKILL, and return `Executed` **only when the process is
   confirmed gone**. Keep the self-kill guard.
   - Add a real test that spawns a child (`sleep`), kills it through the full
     `execute(EdrAction::Kill, …)` path, and asserts `!process_is_alive(pid)` plus
     `status == Executed`. Add a negative test for a nonexistent pid.
2. **Windows kill → direct `TerminateProcess`.** Replace the sysinfo-only Windows
   path (~:697) with `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` (windows
   crate, `#[cfg(windows)]`), verify-gone, sysinfo fallback. (Compiles under cfg
   only; state clearly it's unverified on Linux CI.)
3. **Fix the persistence test parallelism flake.** Make `edr::rollback::persistence`
   tests not share mutable global state (per-test temp dirs / no poisoned global
   lock) so the **default parallel** `cargo test` is green and stable across runs.
4. **Truth-up the stubs in docs-facing strings/code comments** so they don't read as
   done: network isolation is a `TODO` stub (returns Executed — make the evidence
   say "intent only"), USB is detect-only (not "interception"), IOC list is
   hardcoded test data (no feed). Do not implement these now; just stop them
   reading as complete.

Do NOT touch VSS restore (Windows-only, can't verify on this CI) or claim it complete.

## Final report (verbatim)
Before/after `cargo test` counts (parallel + single-threaded); the new kill tests
and how they prove termination; flake fix approach; exact file:line of each change;
explicit list of what remains stub/unverified.
