# Aetherix Regression + Hardening Report

Date: 2026-05-23
Scope: Backend Policy Engine v2, Semantic DLP + GenAI Guardrails, Rust Agent bridge/enforcement, MV3 browser extension, frontend console, dependency/security checks, documentation.

## Executive Summary

Overall status: **Pass with non-blocking findings**.

Critical customer-facing regression suites are green across backend, Rust agent, extension unit logic, console build, and Playwright critical policy flows. One bridge hardening issue was fixed during this pass: disallowed browser origins are now rejected with `403` instead of relying only on absent CORS headers, and `/dlp-event` now requires a non-empty `event_type`.

No critical or high-severity security issues were found. Remaining risks are mostly test-environment/tooling gaps: real-site browser manual testing was not executed from this workspace, console lint currently fails on pre-existing React hook lint rules, and `pip-audit`, `cargo-audit`, and `cargo clippy` are not installed in the environment.

## Proposed Execution Order and Estimated Time

1. Backend full regression and policy simulation performance: 15-25 minutes.
2. Rust agent and local bridge regression/stress checks: 15-25 minutes.
3. Browser extension automated tests and bridge fallback coverage: 10-20 minutes.
4. Console unit/build/E2E/sidebar regression: 20-35 minutes.
5. Integration flow validation using API/agent/console mocked E2E paths: 15-30 minutes.
6. Security and dependency hardening review: 20-40 minutes.
7. Documentation/report/sign-off: 15-25 minutes.

Actual automated runtime in this pass was shorter because dependencies and browsers were already installed.

## New Test Cases Added

### Rust bridge

Added in `agent/src/bridge.rs`:

- Reject disallowed `Origin` headers on HTTP bridge routes with `403`.
- Reject `/dlp-event` payloads that omit `event_type` and confirm they are not forwarded to the backend.

### Browser extension

Added in `apps/extension/test/unit.test.js`:

- Verify extension bridge falls back to HTTP when native messaging is unavailable.
- Verify extension bridge reports disconnected and rejects policy fetch when both native messaging and HTTP are unavailable.

Planned but not automated in this pass:

- Real browser content-script tests on Claude, ChatGPT, Gemini, and Copilot with paste/upload/copy fixtures.
- Large content interception performance tests in an instrumented Chromium session.
- Extension memory/CPU profiling during repeated paste/upload flows.

## Performance Measurement Method

### Policy simulation

Used the existing full-envelope policy v2 performance test with pytest durations enabled.

Result:

- `test_policy_v2_simulation_full_envelope_under_500ms`: call phase ~90 ms.
- Target: < 500 ms.
- Status: **Pass**.

### Local bridge

Started a temporary mock control plane and launched the Rust agent bridge on `127.0.0.1:18787`, then sampled `/health` and `/policy` over loopback using Python `time.perf_counter()`.

Results over 25 requests per endpoint:

| Endpoint | p50 | p95 | max | Target |
| --- | ---: | ---: | ---: | ---: |
| `/health` | 0.398 ms | 0.536 ms | 26.604 ms | < 100 ms |
| `/policy` | 0.431 ms | 0.470 ms | 0.497 ms | < 100 ms |

A 100-request burst also hit `429 Too Many Requests`, confirming the token bucket activates under burst pressure.

### Browser extension

Automated unit-test timings show classification and bridge-mode logic in low single-digit milliseconds. Full browser CPU/memory/page-load impact was not measured because no shared real browser sessions/sites were available in this run.

## Test Results

| Area | Command | Result |
| --- | --- | --- |
| Backend API | `PYTHONPATH=apps/api pytest -q apps/api/tests` | **Pass**, 126 passed in 32.22 s |
| Policy simulation perf | `pytest ...test_policy_v2_simulation_full_envelope_under_500ms --durations=3 --durations-min=0` | **Pass**, call ~0.09 s |
| Rust bridge focused | `cargo test bridge -- --nocapture` | **Pass**, 8 passed |
| Rust agent full | `cargo test -- --nocapture` | **Pass**, 15 passed |
| Extension unit | `npm test` in `apps/extension` | **Pass**, 12 passed |
| Console unit | `npm test -- --run` in `apps/console` | **Pass**, 3 passed |
| Console build | `npm run build` in `apps/console` | **Pass** |
| Console E2E | `npm run test:e2e` in `apps/console` | **Pass**, 4 passed |
| Console lint | `npm run lint` in `apps/console` | **Fail**, 25 errors / 6 warnings |
| Node dependency audit | `npm audit --audit-level=high` | **Pass for high/critical**, 5 moderate dev advisories |
| Rust Clippy | `cargo clippy --all-targets -- -D warnings` | **Not run**, clippy component not installed |
| Rust dependency audit | `cargo audit` | **Not run**, cargo-audit not installed |
| Backend dependency audit | `python -m pip_audit -r apps/api/requirements.txt` | **Not run**, pip-audit not installed |

## Bugs and Findings

### Fixed: Bridge accepted disallowed browser origins

Severity: Medium.

The bridge previously omitted CORS headers for disallowed origins but still processed the request. Browser CORS would block normal hostile web pages from reading responses, but rejecting the request at the bridge boundary is clearer and safer.

Fix:

- Reject supplied origins that are not extension origins or explicit allow-list matches with `403`.
- Apply the same rejection to CORS preflight.
- Added regression test.

### Fixed: `/dlp-event` defaulted missing `event_type`

Severity: Low/Medium.

The documentation said `event_type` was required, but the bridge defaulted missing values to `paste`. That could make malformed evidence look valid.

Fix:

- Require non-empty `event_type`.
- Return `400 {ok:false, error:"event_type is required"}`.
- Confirm malformed payload is not forwarded.

### Open: Console lint gate is red

Severity: Low for runtime, Medium for CI quality.

`npm run lint` fails mostly on `react-hooks/set-state-in-effect` across existing pages plus a few no-explicit-any/unused-variable issues. Build, unit tests, and Playwright E2E pass. This should be handled as a focused UI lint cleanup pass rather than mixed into bridge/security hardening.

### Open: Moderate dev dependency advisories

Severity: Low/Medium.

`npm audit --audit-level=high` found no high/critical advisories, but reported moderate advisories in nested `vitest`/`vite`/`esbuild` dev dependencies. The suggested fix is a breaking Vitest upgrade, so this should be planned separately.

### Open: Manual real-site extension validation not completed

Severity: Medium residual coverage risk.

Automated tests cover classification, destination mapping, bridge fallback, and offline status. Real GenAI site behavior can still vary due to DOM/CSP/event handling differences, so manual or Playwright-with-extension validation remains required before early customer rollout.

## Security Review Notes

- Bridge binds to `127.0.0.1` and validates loopback peers.
- Agent secret remains agent-side; extension only talks to the local bridge.
- Bridge origin validation is now explicit: invalid supplied origins receive `403`.
- Bridge body cap remains 256 KiB.
- Bridge rate limiting activated during burst testing with `429`.
- Backend agent DLP evidence endpoint requires enrolled agent token validation; backend tests cover valid/invalid tokens.
- Multi-tenant isolation is covered by backend tenancy tests and policy assignment/effective policy tests.
- Destructive promotion gates are covered by backend and Playwright flows.

Threat model assumption to keep documented: origin validation protects browser-originated calls, but any local process on the host can attempt direct loopback calls. The security boundary is therefore host-local trust plus no credential exposure, rate limiting, strict payload validation, and backend-side token validation for forwarded evidence.

## Documentation Updates

Updated `docs/agent-semantic-dlp-enforcement.md` to document:

- Required non-empty `event_type` for `/dlp-event`.
- `400` response for missing event type.
- `403` behavior for disallowed supplied origins.

## Final Sign-off Checklist

- Backend Policy Engine v2 suite: **Green**.
- Semantic DLP + GenAI backend tests: **Green** via full backend suite.
- Evidence emission and compliance export tests: **Green** via full backend suite.
- Rust agent and bridge tests: **Green**.
- Browser extension unit/bridge fallback tests: **Green**.
- Console unit/build/E2E flows: **Green**.
- Policy simulation performance < 500 ms: **Green** (~90 ms call phase).
- Bridge response < 100 ms: **Green** (p95 < 1 ms for `/health` and `/policy`).
- No critical/high dependency advisories found in Node audit: **Green**.
- Console lint: **Red**, non-blocking runtime finding but should be fixed before strict CI sign-off.
- Manual real-site browser validation: **Not complete**, required before customer pilot.
- Rust/backend security audit tooling: **Not complete**, missing local tools.

## Recommendation

Proceed to broader internal testing with the bridge hardening fixes included. Before early customer use, complete the remaining gates: console lint cleanup, real-site extension validation on Claude/ChatGPT/Gemini/Copilot, and install/run `pip-audit`, `cargo-audit`, and Clippy in CI or a fully provisioned dev environment.
