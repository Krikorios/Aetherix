# Sprint 1 Brief — Agent A (Endpoint Agent)

You are working on the **Aetherix** endpoint security platform. The repo is a
monorepo: a Rust endpoint agent (`agent/`), a FastAPI/Postgres backend
(`apps/api/`), and a React/Vite console (`apps/console/`).

**You own ONLY the `agent/` directory (Rust).** Do not edit `apps/` or `docs/`.

## Rules
- **#1 rule: no overclaiming.** A capability is real only if there is code that
  performs it AND a test that proves it. If you cannot implement something, say so
  plainly — never fake a status or build evidence for an action that didn't happen.
- Do not run git. Leave your edits in the working tree.
- Keep changes small and reviewable.

## Setup
- Build: `cargo build --manifest-path agent/Cargo.toml`
- Test: `cargo test --manifest-path agent/Cargo.toml`
- Run the existing tests FIRST to confirm a green baseline before changing anything.

## Critical context
The project docs claim *"Process Kill ✅ Cross-platform (Unix permission-checked
SIGTERM + fallback; Windows TerminateProcess)"*, but a code review could NOT find
the actual kill syscall in `agent/src/edr/response.rs`. The response path appears
to build `ResponseEvidence` and set a status (Staged/Success/Failed) WITHOUT
performing the real OS operation. Your job is to make the claim TRUE or make it
honest.

## Tasks (in priority order)
1. **Investigate.** Read `agent/src/edr/response.rs` and the response/action
   execution path in `agent/src/main.rs`. Determine precisely whether the agent
   actually terminates a target process via a syscall, or only builds evidence.
   Report exact `file:line` evidence either way.
2. **Make process kill real (preferred).**
   - Unix: permission-checked `SIGTERM` (via `nix` or libc `kill`), with a fallback,
     and **self-kill protection** (never kill our own PID).
   - Windows: `TerminateProcess` via `windows`/`windows-sys`, gated `#[cfg(windows)]`.
   - Wire the real call into the existing response-execution path so the resulting
     `ResponseEvidence` status reflects the actual outcome (Success only if the
     process is actually gone).
   - Add a test: spawn a harmless child process (e.g. `sleep`), kill it through the
     agent path, assert it terminated. Use `#[cfg(unix)]`/`#[cfg(windows)]` so CI
     (Linux) actually exercises the Unix path.
3. **If kill genuinely cannot ship this sprint, STOP and report why** — do not leave
   a misleading status. (We will correct the docs instead.)
4. **If time remains:** continue the Windows VSS restore copy-out in
   `agent/src/edr/rollback/vss.rs`. Only add paths you can cover with a test. Do NOT
   mark VSS restore as complete.

## Required final report (paste this back to me verbatim)
- The truth about process kill BEFORE your change (`file:line`).
- What you implemented (`file:line` for each change).
- The new test and exactly how it proves termination.
- `cargo test` results before and after (counts).
- VSS progress, if any.
- An explicit, honest list of what is STILL simulated/stubbed in `agent/`.
